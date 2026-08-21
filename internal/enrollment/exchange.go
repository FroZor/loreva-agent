package enrollment

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/challenge"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

func exchangeEnrollment(
	ctx context.Context,
	conn *websocket.Conn,
	options Options,
	portalChallenge protocol.Challenge,
	pending *state.PendingEnrollment,
	material *agentcrypto.KeyMaterial,
) (*state.Identity, error) {
	proof, err := agentcrypto.EnrollmentPoP(
		material,
		portalChallenge.PortalID,
		pending.RequestID,
		portalChallenge.Nonce,
		portalChallenge.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	request := protocol.EnrollmentRequest{
		Type:            protocol.EnrollmentRequestType,
		ProtocolVersion: protocol.Version,
		Agent: protocol.AgentInfo{
			Version:      options.Version,
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			Hostname:     options.Hostname,
			Capabilities: []string{},
		},
		CSR:   material.CSRPEM,
		PQPoP: proof,
	}
	if err := wsframe.WriteJSON(ctx, conn, request); err != nil {
		return nil, fmt.Errorf("write enrollment request: %w", err)
	}

	accepted, err := readEnrollmentResult(ctx, conn)
	if err != nil {
		return nil, err
	}

	return validateAccepted(options, portalChallenge, pending, material, accepted)
}

func readEnrollmentChallenge(ctx context.Context, conn *websocket.Conn) (protocol.Challenge, error) {
	var portalChallenge protocol.Challenge
	if err := wsframe.ReadJSON(ctx, conn, &portalChallenge); err != nil {
		return protocol.Challenge{}, fmt.Errorf("read enrollment challenge: %w", err)
	}
	if err := challenge.Validate(portalChallenge, protocol.EnrollmentChallenge, ""); err != nil {
		return protocol.Challenge{}, err
	}

	return portalChallenge, nil
}

func readEnrollmentResult(ctx context.Context, conn *websocket.Conn) (protocol.EnrollmentAccepted, error) {
	message, err := wsframe.ReadRawJSON(ctx, conn)
	if err != nil {
		return protocol.EnrollmentAccepted{}, fmt.Errorf("read enrollment result: %w", err)
	}

	messageType, err := protocol.MessageType(message)
	if err != nil {
		return protocol.EnrollmentAccepted{}, errors.New("enrollment result is not valid JSON")
	}

	if messageType == protocol.EnrollmentRejectedType {
		var rejected protocol.Rejected
		if err := protocol.DecodeStrict(message, &rejected); err != nil {
			return protocol.EnrollmentAccepted{}, err
		}

		return protocol.EnrollmentAccepted{}, &rejectedError{Code: rejected.Code, Message: rejected.Message}
	}
	if messageType != protocol.EnrollmentAcceptedType {
		return protocol.EnrollmentAccepted{}, fmt.Errorf("unexpected enrollment result type %q", messageType)
	}

	var accepted protocol.EnrollmentAccepted
	if err := protocol.DecodeStrict(message, &accepted); err != nil {
		return protocol.EnrollmentAccepted{}, err
	}

	return accepted, nil
}
