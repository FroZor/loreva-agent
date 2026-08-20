// Package session maintains an enrolled node's portal connection lifecycle.
package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/connectivity"
	"github.com/FroZor/loreva-agent/internal/state"
)

type permanentError struct{ Err error }

func (e *permanentError) Error() string { return e.Err.Error() }
func (e *permanentError) Unwrap() error { return e.Err }

type endpointPolicyError struct{ Err error }

func (e *endpointPolicyError) Error() string { return e.Err.Error() }
func (e *endpointPolicyError) Unwrap() error { return e.Err }

type connectedError struct{ Err error }

func (e *connectedError) Error() string { return e.Err.Error() }
func (e *connectedError) Unwrap() error { return e.Err }

type rejectedError struct {
	Code    string
	Message string
}

func (e *rejectedError) Error() string {
	if e.Message == "" {
		return "portal rejected connection: " + e.Code
	}
	return "portal rejected connection: " + e.Code + ": " + e.Message
}

// Runner maintains the enrolled agent's outbound portal session.
type Runner struct {
	store             *state.Store
	identity          *state.Identity
	material          *agentcrypto.KeyMaterial
	clientCertificate tls.Certificate
	masterEndpoint    string
}

// New validates the persisted identity and creates a session runner.
func New(store *state.Store, identity *state.Identity) (*Runner, error) {
	if store == nil {
		return nil, errors.New("agent state store is required")
	}

	runner := &Runner{store: store}
	if err := runner.installIdentity(identity); err != nil {
		return nil, err
	}

	return runner, nil
}

func (r *Runner) installIdentity(identity *state.Identity) error {
	if identity == nil || !agentcrypto.ValidUUID(identity.NodeID) || !agentcrypto.ValidUUID(identity.PortalID) {
		return errors.New("invalid stored agent identity")
	}
	if err := agentcrypto.ValidateJWK(&identity.PortalPQRoot); err != nil {
		return fmt.Errorf("validate stored portal_pq_root: %w", err)
	}

	material, err := agentcrypto.RestoreKeys(identity.ECDSAPrivateKey, identity.MLDSASeed)
	if err != nil {
		return err
	}

	certificatePEM := []byte(strings.Join(identity.CertificateChain, "\n"))
	clientCertificate, err := tls.X509KeyPair(certificatePEM, []byte(identity.ECDSAPrivateKey))
	if err != nil {
		return fmt.Errorf("load mTLS identity: %w", err)
	}

	masterEndpoint, err := connectivity.Endpoint(identity.PortalURL, "/agent/v1/connect")
	if err != nil {
		return fmt.Errorf("validate stored portal URL: %w", err)
	}

	r.identity = identity
	r.material = material
	r.clientCertificate = clientCertificate
	r.masterEndpoint = masterEndpoint

	return nil
}

// Run connects until the context is cancelled or a permanent policy error occurs.
func (r *Runner) Run(ctx context.Context, onConnected func(string)) error {
	attempt := 0
	disabledEndpoints := make(map[string]struct{})

connectionLoop:
	for {
		endpoints := r.endpoints(time.Now())
		var lastErr error

		for _, endpoint := range endpoints {
			if _, disabled := disabledEndpoints[endpoint]; disabled {
				continue
			}

			err := r.runEndpoint(ctx, endpoint, onConnected)

			if connected, ok := errors.AsType[*connectedError](err); ok {
				attempt = 0
				err = connected.Err
			}

			if errors.Is(err, errIdentityRenewed) {
				disabledEndpoints = make(map[string]struct{})
				continue connectionLoop
			}
			if errors.Is(err, errReconnectRequested) {
				disabledEndpoints = make(map[string]struct{})
				attempt = 0
				continue connectionLoop
			}

			if err == nil || errors.Is(err, context.Canceled) {
				return err
			}

			if endpointPolicy, ok := errors.AsType[*endpointPolicyError](err); ok {
				disabledEndpoints[endpoint] = struct{}{}
				lastErr = endpointPolicy
				continue
			}

			if permanent, ok := errors.AsType[*permanentError](err); ok {
				return permanent
			}

			lastErr = err
		}

		if lastErr == nil {
			return &permanentError{Err: errors.New("all connection endpoints are disabled by security policy")}
		}

		attempt++
		delay := retryDelay(attempt)
		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (r *Runner) endpointFailure(endpoint string, err error) error {
	if endpoint == r.masterEndpoint {
		return &permanentError{Err: err}
	}
	return &endpointPolicyError{Err: err}
}

func terminalRejection(code string) bool {
	switch code {
	case "expired_pq_proof", "replayed_pq_proof", "internal_error":
		return false
	default:
		return true
	}
}
