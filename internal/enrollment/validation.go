package enrollment

import (
	"errors"
	"fmt"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/identity"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/sources"
	"github.com/FroZor/loreva-agent/internal/state"
)

func validateAccepted(
	options Options,
	portalChallenge protocol.Challenge,
	pending *state.PendingEnrollment,
	material *agentcrypto.KeyMaterial,
	accepted protocol.EnrollmentAccepted,
) (*state.Identity, error) {
	if accepted.Type != protocol.EnrollmentAcceptedType || !agentcrypto.ValidUUID(accepted.NodeID) {
		return nil, errors.New("portal returned an invalid enrollment identity")
	}
	if err := validatePortalPQRoot(accepted.PortalPQRoot, pending.PortalPQRootSHA256); err != nil {
		return nil, err
	}

	if err := identity.ValidateIssued(
		accepted.PortalPQRoot,
		portalChallenge.PortalID,
		accepted.NodeID,
		material,
		accepted.CertificateChain,
		accepted.PQCredential,
		accepted.RenewAfter,
	); err != nil {
		return nil, err
	}
	if err := sources.Validate(accepted.Sources); err != nil {
		return nil, err
	}

	return &state.Identity{
		PortalURL:          options.PortalURL,
		PortalCAPEM:        options.PortalCAPEM,
		AllowDevelopmentWS: options.AllowDevelopmentWS,
		PortalID:           portalChallenge.PortalID,
		NodeID:             accepted.NodeID,
		PortalPQRoot:       *accepted.PortalPQRoot,
		ECDSAPrivateKey:    pending.ECDSAPrivateKey,
		CertificateChain:   append([]string(nil), accepted.CertificateChain...),
		MLDSASeed:          pending.MLDSASeed,
		PQCredential:       accepted.PQCredential,
		RenewAfter:         accepted.RenewAfter,
		Sources:            accepted.Sources,
	}, nil
}

func validatePortalPQRoot(root *agentcrypto.JWK, expectedThumbprint string) error {
	if err := agentcrypto.ValidateJWK(root); err != nil {
		return fmt.Errorf("portal returned an invalid portal_pq_root: %w", err)
	}
	if expectedThumbprint == "" {
		return nil
	}

	thumbprint, err := agentcrypto.JWKThumbprint(root)
	if err != nil {
		return fmt.Errorf("calculate portal_pq_root thumbprint: %w", err)
	}
	if thumbprint != expectedThumbprint {
		return errors.New("portal_pq_root does not match pending enrollment state")
	}

	return nil
}
