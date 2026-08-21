package enrollment

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/state"
)

func loadOrCreatePending(
	store *state.Store,
	options Options,
	portalEndpoint string,
	portalID string,
	tokenID string,
) (*state.PendingEnrollment, *agentcrypto.KeyMaterial, error) {
	pending, err := store.LoadPending()
	if err == nil {
		material, err := agentcrypto.Restore(pending.ECDSAPrivateKey, pending.CSR, pending.MLDSASeed)
		if err != nil {
			return nil, nil, fmt.Errorf("restore pending enrollment: %w", err)
		}

		samePortal := pending.PortalEndpoint == portalEndpoint &&
			(pending.PortalID == "" || pending.PortalID == portalID)
		if samePortal {
			if pending.PortalEndpoint == portalEndpoint &&
				pending.PortalID == portalID &&
				pending.EnrollmentTokenID == tokenID {
				return pending, material, nil
			}

			updated := *pending
			updated.PortalEndpoint = portalEndpoint
			updated.PortalID = portalID
			updated.EnrollmentTokenID = tokenID
			if err := store.ReplacePending(&updated); err != nil {
				return nil, nil, fmt.Errorf("update pending enrollment binding: %w", err)
			}

			return &updated, material, nil
		}

		return replacePending(store, options, portalEndpoint, portalID, tokenID)
	}
	if !errors.Is(err, state.ErrNotFound) {
		return nil, nil, fmt.Errorf("load pending enrollment: %w", err)
	}

	pending, material, err := newPending(options, portalEndpoint, portalID, tokenID)
	if err != nil {
		return nil, nil, err
	}
	if err := store.SavePending(pending); err != nil {
		return nil, nil, fmt.Errorf("persist pending enrollment: %w", err)
	}

	return pending, material, nil
}

func replacePending(
	store *state.Store,
	options Options,
	portalEndpoint string,
	portalID string,
	tokenID string,
) (*state.PendingEnrollment, *agentcrypto.KeyMaterial, error) {
	pending, material, err := newPending(options, portalEndpoint, portalID, tokenID)
	if err != nil {
		return nil, nil, err
	}
	if err := store.ReplacePending(pending); err != nil {
		return nil, nil, fmt.Errorf("replace pending enrollment: %w", err)
	}

	return pending, material, nil
}

func newPending(
	options Options,
	portalEndpoint string,
	portalID string,
	tokenID string,
) (*state.PendingEnrollment, *agentcrypto.KeyMaterial, error) {

	material, err := agentcrypto.Generate(options.Hostname)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := material.PrivateKeyPEM()
	if err != nil {
		return nil, nil, err
	}

	requestID, err := agentcrypto.NewUUID()
	if err != nil {
		return nil, nil, err
	}

	pending := &state.PendingEnrollment{
		PortalEndpoint:    portalEndpoint,
		PortalID:          portalID,
		EnrollmentTokenID: tokenID,
		RequestID:         requestID,
		ECDSAPrivateKey:   privateKey,
		CSR:               material.CSRPEM,
		MLDSASeed:         material.SeedBase64(),
	}
	return pending, material, nil
}

func normalizeAndValidateOptions(options *Options) error {
	options.PortalURL = strings.TrimSpace(options.PortalURL)
	if options.PortalURL == "" {
		return errors.New("portal URL is required")
	}
	if options.Token == "" || len(options.Token) > 4096 || strings.ContainsAny(options.Token, "\r\n") {
		return errors.New("valid enrollment token is required")
	}
	if options.Version == "" {
		options.Version = "dev"
	}
	if options.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("read hostname: %w", err)
		}

		options.Hostname = hostname
	}
	if len(options.Hostname) > 255 {
		return errors.New("hostname exceeds 255 characters")
	}

	return nil
}

func enrollmentTokenID(token string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || len(parts[0]) != 16 || parts[1] == "" {
		return "", errors.New("enrollment token must use 16-character token_id.secret format")
	}

	return parts[0], nil
}
