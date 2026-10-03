package client

import (
	"context"
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/FroZor/loreva-agent/internal/agentapi"
	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/tunnel"
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

// Pair uses a one-time invite to register this device with the node and
// returns its permanent credentials.
func Pair(ctx context.Context, invite *pairing.Invite, options PairOptions) (*Credentials, error) {
	if err := pairing.ValidateDeviceName(options.DeviceName); err != nil {
		return nil, err
	}
	if options.ShowSAS == nil {
		return nil, errors.New("a SAS display callback is required")
	}

	devicePrivateKey, err := tunnel.GenerateKey()
	if err != nil {
		return nil, err
	}
	devicePublicKey, err := devicePrivateKey.PublicKey()
	if err != nil {
		return nil, err
	}
	decapsulationKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM-768 key: %w", err)
	}

	session, err := ConnectInvite(ctx, invite)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	encapsulationKey := decapsulationKey.EncapsulationKey().Bytes()
	var started agentapi.PairingStarted
	err = session.doJSON(ctx, http.MethodPost, agentapi.PairingPath, agentapi.PairingRequest{
		DeviceName:            options.DeviceName,
		WireGuardPublicKey:    devicePublicKey.String(),
		MLKEMEncapsulationKey: base64.StdEncoding.EncodeToString(encapsulationKey),
	}, &started)
	if err != nil {
		return nil, err
	}

	transcript, err := pairingTranscript(invite, started, devicePublicKey, options.DeviceName, encapsulationKey)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := decapsulationKey.Decapsulate(transcript.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulate ML-KEM-768 ciphertext: %w", err)
	}
	presharedKey, err := transcript.PresharedKey(sharedSecret, invite.PresharedKey)
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
		Version:       credentialsVersion,
		NodeID:        invite.NodeID,
		NodePublicKey: invite.NodePublicKey.String(),
		NodeAddress:   invite.NodeAddress.String(),
		Endpoints:     endpoints,
		DeviceID:      deviceID,
		DeviceName:    options.DeviceName,
		PrivateKey:    devicePrivateKey.String(),
		PresharedKey:  presharedKey.String(),
		Address:       transcript.DeviceAddress.String(),
	}, nil
}

// ConnectInvite opens a session as the temporary invite peer. The node lets
// this peer call only the pairing endpoints.
func ConnectInvite(ctx context.Context, invite *pairing.Invite) (*Session, error) {
	return open(ctx, endpointConfig{
		privateKey:    invite.PrivateKey,
		presharedKey:  invite.PresharedKey,
		address:       invite.Address,
		nodePublicKey: invite.NodePublicKey,
		nodeAddress:   invite.NodeAddress,
		endpoints:     invite.Endpoints,
	})
}

func pairingTranscript(invite *pairing.Invite, started agentapi.PairingStarted, devicePublicKey tunnel.Key,
	deviceName string, encapsulationKey []byte,
) (*pairing.Transcript, error) {
	if !agentcrypto.ValidUUID(started.PairingID) {
		return nil, errors.New("node returned an invalid pairing ID")
	}

	nonce, err := base64.StdEncoding.Strict().DecodeString(started.NodeNonce)
	if err != nil || len(nonce) != pairing.NonceSize {
		return nil, errors.New("node returned an invalid pairing nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(started.MLKEMCiphertext)
	if err != nil || len(ciphertext) != mlkem.CiphertextSize768 {
		return nil, errors.New("node returned an invalid ML-KEM ciphertext")
	}
	deviceAddress, err := netip.ParseAddr(started.DeviceAddress)
	if err != nil || !deviceAddress.Is6() || deviceAddress == invite.NodeAddress || deviceAddress == invite.Address {
		return nil, errors.New("node returned an invalid device address")
	}

	return &pairing.Transcript{
		InviteID:         invite.InviteID,
		NodeID:           invite.NodeID,
		NodePublicKey:    invite.NodePublicKey,
		DevicePublicKey:  devicePublicKey,
		DeviceName:       deviceName,
		DeviceAddress:    deviceAddress,
		EncapsulationKey: encapsulationKey,
		Ciphertext:       ciphertext,
		NodeNonce:        nonce,
	}, nil
}

// waitForApproval long-polls the pairing status until the operator decides.
func waitForApproval(ctx context.Context, session *Session, pairingID string) (string, error) {
	for {
		var status agentapi.PairingStatus
		if err := session.doJSON(ctx, http.MethodGet, agentapi.PairingPath+"/"+pairingID, nil, &status); err != nil {
			return "", err
		}

		switch status.Status {
		case agentapi.PairingPending:
			continue
		case agentapi.PairingApproved:
			if status.DeviceID == "" {
				return "", errors.New("node approved pairing without a device ID")
			}

			return status.DeviceID, nil
		case agentapi.PairingRejected:
			return "", ErrPairingRejected
		case agentapi.PairingExpired:
			return "", ErrPairingExpired
		default:
			return "", fmt.Errorf("unknown pairing status %q", status.Status)
		}
	}
}
