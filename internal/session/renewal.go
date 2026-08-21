package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/identity"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
)

const (
	renewProofTTL     = 30 * time.Second
	renewWriteTimeout = 10 * time.Second
	renewReplyTimeout = 30 * time.Second
)

var errIdentityRenewed = errors.New("agent identity renewed")

type activeRenewal struct {
	pending  *state.PendingRenewal
	material *agentcrypto.KeyMaterial
}

func (r *Runner) renewalDelay(now time.Time) (time.Duration, error) {
	pending, err := r.store.LoadRenewal()
	if err == nil {
		if pending.ECDSAPrivateKey == r.identity.ECDSAPrivateKey && pending.MLDSASeed == r.identity.MLDSASeed {
			if err := r.store.ClearRenewal(); err != nil {
				return 0, fmt.Errorf("clear committed renewal state: %w", err)
			}
		} else {
			return 0, nil
		}
	} else if !errors.Is(err, state.ErrNotFound) {
		return 0, fmt.Errorf("load pending renewal: %w", err)
	}

	if !r.identity.RenewAfter.After(now) {
		return 0, nil
	}

	return time.Until(r.identity.RenewAfter), nil
}

func (r *Runner) loadOrCreateRenewal() (*state.PendingRenewal, *agentcrypto.KeyMaterial, error) {
	rootThumbprint, err := agentcrypto.JWKThumbprint(&r.identity.PortalPQRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("validate stored portal_pq_root: %w", err)
	}

	pending, err := r.store.LoadRenewal()
	if err == nil {
		if pending.PortalURL != r.identity.PortalURL ||
			pending.PortalID != r.identity.PortalID ||
			pending.NodeID != r.identity.NodeID ||
			pending.PortalPQRootSHA256 != rootThumbprint {
			return nil, nil, errors.New("pending renewal belongs to another portal, node, or PQ root")
		}

		material, err := agentcrypto.Restore(pending.ECDSAPrivateKey, pending.CSR, pending.MLDSASeed)
		if err != nil {
			return nil, nil, fmt.Errorf("restore pending renewal: %w", err)
		}

		return pending, material, nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return nil, nil, fmt.Errorf("load pending renewal: %w", err)
	}

	material, err := agentcrypto.Generate(r.identity.NodeID)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := material.PrivateKeyPEM()
	if err != nil {
		return nil, nil, err
	}

	jti, err := agentcrypto.NewUUID()
	if err != nil {
		return nil, nil, err
	}

	pending = &state.PendingRenewal{
		PortalURL:          r.identity.PortalURL,
		PortalID:           r.identity.PortalID,
		NodeID:             r.identity.NodeID,
		PortalPQRootSHA256: rootThumbprint,
		JTI:                jti,
		ECDSAPrivateKey:    privateKey,
		CSR:                material.CSRPEM,
		MLDSASeed:          material.SeedBase64(),
	}
	if err := r.store.SaveRenewal(pending); err != nil {
		return nil, nil, fmt.Errorf("persist pending renewal: %w", err)
	}

	return pending, material, nil
}

func (r *Runner) handleRenewalResponse(
	conn *websocket.Conn,
	endpoint string,
	renewal *activeRenewal,
	message []byte,
) error {
	messageType, err := protocol.MessageType(message)
	if err != nil {
		return r.endpointFailure(endpoint, errors.New("renewal result is not valid JSON"))
	}

	if messageType == protocol.RenewRejectedType {
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
	if messageType != protocol.RenewAcceptedType {
		return r.endpointFailure(endpoint, fmt.Errorf("unexpected renewal result type %q", messageType))
	}

	var accepted protocol.RenewAccepted
	if err := protocol.DecodeStrict(message, &accepted); err != nil {
		return r.endpointFailure(endpoint, err)
	}

	replacement, err := identity.ValidateRenewal(r.identity, renewal.pending, renewal.material, accepted)
	if err != nil {
		return r.endpointFailure(endpoint, fmt.Errorf("validate renewed identity: %w", err))
	}

	if err := r.store.ReplaceIdentity(replacement); err != nil {
		persisted, loadErr := r.store.LoadIdentity()
		if loadErr != nil ||
			persisted.ECDSAPrivateKey != replacement.ECDSAPrivateKey ||
			persisted.MLDSASeed != replacement.MLDSASeed {
			return &permanentError{Err: fmt.Errorf("persist renewed identity: %w", err)}
		}
	}
	if err := r.installIdentity(replacement); err != nil {
		return &permanentError{Err: fmt.Errorf("activate renewed identity: %w", err)}
	}
	if err := r.store.ClearRenewal(); err != nil {
		return &permanentError{Err: fmt.Errorf("renewed identity committed but pending state cleanup failed: %w", err)}
	}

	_ = conn.Close(websocket.StatusNormalClosure, "identity renewed")

	return errIdentityRenewed
}
