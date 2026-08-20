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
	tokenID string,
) (*state.PendingEnrollment, *agentcrypto.KeyMaterial, error) {
	rootThumbprint, err := agentcrypto.JWKThumbprint(options.PortalPQRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("validate portal_pq_root: %w", err)
	}

	pending, err := store.LoadPending()
	if err == nil {
		if pending.PortalEndpoint != portalEndpoint ||
			pending.EnrollmentTokenID != tokenID ||
			pending.PortalPQRootSHA256 != rootThumbprint {
			return nil, nil, errors.New("pending enrollment belongs to another portal, token, or PQ root; explicitly reset pending state to continue")
		}

		material, err := agentcrypto.Restore(pending.ECDSAPrivateKey, pending.CSR, pending.MLDSASeed)
		if err != nil {
			return nil, nil, fmt.Errorf("restore pending enrollment: %w", err)
		}

		return pending, material, nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return nil, nil, fmt.Errorf("load pending enrollment: %w", err)
	}

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

	pending = &state.PendingEnrollment{
		PortalEndpoint:     portalEndpoint,
		EnrollmentTokenID:  tokenID,
		PortalPQRootSHA256: rootThumbprint,
		RequestID:          requestID,
		ECDSAPrivateKey:    privateKey,
		CSR:                material.CSRPEM,
		MLDSASeed:          material.SeedBase64(),
	}
	if err := store.SavePending(pending); err != nil {
		return nil, nil, fmt.Errorf("persist pending enrollment: %w", err)
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
	if err := agentcrypto.ValidateJWK(options.PortalPQRoot); err != nil {
		return fmt.Errorf("valid portal_pq_root is required: %w", err)
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
