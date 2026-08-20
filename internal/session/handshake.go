package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/challenge"
	"github.com/FroZor/loreva-agent/internal/connectivity"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const handshakeTimeout = 30 * time.Second

func (r *Runner) runEndpoint(ctx context.Context, endpoint string, onConnected func(string)) error {
	dialer, err := connectivity.NewDialer(connectivity.Config{
		PortalCAPEM:        r.identity.PortalCAPEM,
		ClientCertificate:  &r.clientCertificate,
		AllowDevelopmentWS: r.identity.AllowDevelopmentWS,
	})
	if err != nil {
		return &permanentError{Err: err}
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	conn, response, err := dialer.Dial(handshakeCtx, endpoint, connectivity.DialOptions{
		Subprotocols: []string{protocol.ConnectSubprotocol},
	})
	if err != nil {
		return r.classifyDialError(endpoint, response, err)
	}
	defer conn.CloseNow()

	portalChallenge, err := r.readConnectChallenge(handshakeCtx, conn, endpoint)
	if err != nil {
		return err
	}

	proof, err := agentcrypto.ConnectPoP(
		r.material,
		r.identity.PortalID,
		portalChallenge.Nonce,
		portalChallenge.ExpiresAt,
	)
	if err != nil {
		return err
	}

	if err := wsframe.WriteJSON(handshakeCtx, conn, protocol.ConnectProof{
		Type:         protocol.ConnectProofType,
		PQCredential: r.identity.PQCredential,
		PQPoP:        proof,
	}); err != nil {
		return fmt.Errorf("write connect proof: %w", err)
	}

	if err := r.readConnectResult(handshakeCtx, conn, endpoint); err != nil {
		return err
	}

	cancel()

	if onConnected != nil {
		onConnected(endpoint)
	}

	return &connectedError{Err: r.maintain(ctx, conn, portalChallenge.Nonce, endpoint)}
}

func (r *Runner) classifyDialError(endpoint string, response *http.Response, err error) error {
	if errors.Is(err, connectivity.ErrTLSPolicy) || errors.Is(err, connectivity.ErrSubprotocol) {
		return r.endpointFailure(endpoint, err)
	}
	if response == nil {
		return err
	}
	if connectivity.RetryableHTTPStatus(response.StatusCode) {
		return err
	}

	return r.endpointFailure(endpoint, fmt.Errorf("portal returned HTTP %d: %w", response.StatusCode, err))
}

func (r *Runner) readConnectChallenge(ctx context.Context, conn *websocket.Conn, endpoint string) (protocol.Challenge, error) {
	message, err := wsframe.ReadRawJSON(ctx, conn)
	if err != nil {
		return protocol.Challenge{}, fmt.Errorf("read connect challenge: %w", err)
	}

	var signed protocol.SignedChallenge
	if err := protocol.DecodeStrict(message, &signed); err != nil {
		return protocol.Challenge{}, r.endpointFailure(endpoint, fmt.Errorf("decode connect challenge: %w", err))
	}
	if signed.Type != protocol.ConnectChallenge || signed.SignedChallenge == "" {
		return protocol.Challenge{}, r.endpointFailure(endpoint, errors.New("invalid signed connect challenge envelope"))
	}

	var portalChallenge protocol.Challenge
	if err := agentcrypto.VerifyCompactJWS(&r.identity.PortalPQRoot, signed.SignedChallenge, &portalChallenge); err != nil {
		return protocol.Challenge{}, r.endpointFailure(endpoint, fmt.Errorf("verify signed connect challenge: %w", err))
	}
	if err := challenge.Validate(portalChallenge, protocol.ConnectChallenge, r.identity.PortalID); err != nil {
		if errors.Is(err, challenge.ErrExpired) {
			return protocol.Challenge{}, err
		}

		return protocol.Challenge{}, r.endpointFailure(endpoint, err)
	}

	return portalChallenge, nil
}

func (r *Runner) readConnectResult(ctx context.Context, conn *websocket.Conn, endpoint string) error {
	message, err := wsframe.ReadRawJSON(ctx, conn)
	if err != nil {
		return fmt.Errorf("read connect result: %w", err)
	}

	messageType, err := protocol.MessageType(message)
	if err != nil {
		return r.endpointFailure(endpoint, errors.New("connect result is not valid JSON"))
	}

	if messageType == protocol.ConnectRejectedType {
		var rejected protocol.Rejected
		if err := protocol.DecodeStrict(message, &rejected); err != nil {
			return r.endpointFailure(endpoint, err)
		}

		rejection := &rejectedError{Code: rejected.Code, Message: rejected.Message}
		if terminalRejection(rejected.Code) {
			return r.endpointFailure(endpoint, rejection)
		}

		return rejection
	}

	if messageType != protocol.ConnectAcceptedType {
		return r.endpointFailure(endpoint, fmt.Errorf("unexpected connect result type %q", messageType))
	}

	var accepted protocol.ConnectAccepted
	if err := protocol.DecodeStrict(message, &accepted); err != nil {
		return r.endpointFailure(endpoint, fmt.Errorf("decode connect result: %w", err))
	}

	return nil
}
