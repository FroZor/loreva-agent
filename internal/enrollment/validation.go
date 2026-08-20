package enrollment

import (
	"errors"

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

	if err := identity.ValidateIssued(
		options.PortalPQRoot,
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
		PortalPQRoot:       *options.PortalPQRoot,
		ECDSAPrivateKey:    pending.ECDSAPrivateKey,
		CertificateChain:   append([]string(nil), accepted.CertificateChain...),
		MLDSASeed:          pending.MLDSASeed,
		PQCredential:       accepted.PQCredential,
		RenewAfter:         accepted.RenewAfter,
		Sources:            accepted.Sources,
	}, nil
}
