package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// ErrPairingRejected means the operator answered no on the node.
var ErrPairingRejected = errors.New("pairing was rejected on the node")

// ErrPairingExpired means the invite expired or was cancelled on the node.
var ErrPairingExpired = errors.New("invite expired before pairing was approved")

// PairOptions configures Pair.
type PairOptions struct {
	DeviceName string
	// ShowSAS displays the code the operator must find on the node before
	// approving. It is called once, before Pair waits for the decision.
	ShowSAS func(sas string)
}

// Pair uses a one-time connection key to register this device with the node
// and returns its permanent credentials.
func Pair(ctx context.Context, invite *pairing.Invite, options PairOptions) (*Credentials, error) {
	if err := pairing.ValidateDeviceName(options.DeviceName); err != nil {
		return nil, err
	}
	if options.ShowSAS == nil {
		return nil, errors.New("a SAS display callback is required")
	}

	identity, err := certpin.Generate()
	if err != nil {
		return nil, err
	}
	devicePin, err := identity.Pin()
	if err != nil {
		return nil, err
	}

	session, err := ConnectInvite(ctx, invite, identity)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	err = session.WriteJSON(ctx, protocol.PairingRequest{
		Type:        protocol.PairingRequestType,
		DeviceName:  options.DeviceName,
		InviteToken: pairing.EncodeToken(invite.Token),
	})
	if err != nil {
		return nil, fmt.Errorf("send pairing request: %w", err)
	}

	var started protocol.PairingStarted
	if err := readReply(ctx, session, protocol.PairingStartedType, &started); err != nil {
		return nil, err
	}

	transcript, err := pairingTranscript(session, invite, started, devicePin, options.DeviceName)
	if err != nil {
		return nil, err
	}

	options.ShowSAS(transcript.SAS())

	deviceID, err := waitForApproval(ctx, session, started.PairingID)
	if err != nil {
		return nil, err
	}

	endpoints := []string{session.endpoint.String()}
	for _, endpoint := range invite.Endpoints {
		if endpoint != session.endpoint {
			endpoints = append(endpoints, endpoint.String())
		}
	}

	return &Credentials{
		Version:     credentialsVersion,
		NodeID:      invite.NodeID,
		NodePin:     invite.NodePin,
		Endpoints:   endpoints,
		DeviceID:    deviceID,
		DeviceName:  options.DeviceName,
		PrivateKey:  identity.PrivateKey,
		Certificate: identity.Certificate,
	}, nil
}

// ConnectInvite opens a session that presents the device's new key, which
// the node accepts only while an invite is active and only for pairing.
func ConnectInvite(ctx context.Context, invite *pairing.Invite, identity certpin.Identity) (*Session, error) {
	certificate, err := identity.TLSCertificate()
	if err != nil {
		return nil, err
	}

	session, err := open(ctx, endpointConfig{
		nodeID:      invite.NodeID,
		nodePin:     invite.NodePin,
		certificate: certificate,
		endpoints:   invite.Endpoints,
	})
	if err != nil {
		return nil, err
	}
	if session.Hello.Peer != protocol.SessionPeerInvite {
		session.Close()
		return nil, errors.New("node did not accept the connection key for pairing")
	}

	return session, nil
}

func pairingTranscript(session *Session, invite *pairing.Invite, started protocol.PairingStarted, devicePin, deviceName string) (*pairing.Transcript, error) {
	if !agentcrypto.ValidUUID(started.PairingID) {
		return nil, errors.New("node returned an invalid pairing ID")
	}

	nonce, err := base64.StdEncoding.Strict().DecodeString(started.NodeNonce)
	if err != nil || len(nonce) != pairing.NonceSize {
		return nil, errors.New("node returned an invalid pairing nonce")
	}
	exporter, err := session.exporter()
	if err != nil {
		return nil, fmt.Errorf("export TLS keying material: %w", err)
	}

	return &pairing.Transcript{
		InviteID:   invite.InviteID,
		NodeID:     invite.NodeID,
		NodePin:    invite.NodePin,
		DevicePin:  devicePin,
		DeviceName: deviceName,
		NodeNonce:  nonce,
		Exporter:   exporter,
	}, nil
}

func waitForApproval(ctx context.Context, session *Session, pairingID string) (string, error) {
	var result protocol.PairingResult
	if err := readReply(ctx, session, protocol.PairingResultType, &result); err != nil {
		return "", err
	}
	if result.PairingID != pairingID {
		return "", errors.New("node sent the result of another pairing")
	}

	switch result.Status {
	case protocol.PairingApproved:
		if result.DeviceID == "" {
			return "", errors.New("node approved pairing without a device ID")
		}

		return result.DeviceID, nil
	case protocol.PairingRejected:
		return "", ErrPairingRejected
	case protocol.PairingExpired:
		return "", ErrPairingExpired
	default:
		return "", fmt.Errorf("unknown pairing status %q", result.Status)
	}
}

// readReply reads the next frame and decodes it as wantType, turning an
// error frame into a *RemoteError.
func readReply(ctx context.Context, session *Session, wantType string, target any) error {
	data, err := session.Read(ctx)
	if err != nil {
		return err
	}

	messageType, err := protocol.MessageType(data)
	if err != nil {
		return errors.New("node sent a frame that is not valid JSON")
	}
	if messageType == protocol.ErrorType {
		var refusal protocol.Error
		if err := protocol.DecodeStrict(data, &refusal); err != nil {
			return fmt.Errorf("decode error frame: %w", err)
		}

		return &RemoteError{Code: refusal.Code, Message: refusal.Message}
	}
	if messageType != wantType {
		return fmt.Errorf("node sent %q, want %q", messageType, wantType)
	}

	return protocol.DecodeStrict(data, target)
}
