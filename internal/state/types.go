package state

import (
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// PendingEnrollment stores crash-safe enrollment material before portal acceptance.
type PendingEnrollment struct {
	Version           int    `json:"version"`
	PortalEndpoint    string `json:"portal_endpoint"`
	PortalID          string `json:"portal_id,omitempty"`
	EnrollmentTokenID string `json:"enrollment_token_id"`
	// PortalPQRootSHA256 keeps compatibility with pending enrollment state
	// created before the portal root moved into enrollment.accepted.
	PortalPQRootSHA256 string `json:"portal_pq_root_sha256,omitempty"`
	RequestID          string `json:"request_id"`
	ECDSAPrivateKey    string `json:"ecdsa_private_key"`
	CSR                string `json:"csr"`
	MLDSASeed          string `json:"mldsa_seed"`
}

// PendingRenewal contains a new identity key set that has not yet been
// accepted by the portal. It includes identity bindings so callers can reject
// stale state before reusing its JTI or private keys.
type PendingRenewal struct {
	Version            int    `json:"version"`
	PortalURL          string `json:"portal_url"`
	PortalID           string `json:"portal_id"`
	NodeID             string `json:"node_id"`
	PortalPQRootSHA256 string `json:"portal_pq_root_sha256"`
	JTI                string `json:"jti"`
	ECDSAPrivateKey    string `json:"ecdsa_private_key"`
	CSR                string `json:"csr"`
	MLDSASeed          string `json:"mldsa_seed"`
}

// Identity is the validated portal-issued identity persisted by the agent.
type Identity struct {
	Version            int              `json:"version"`
	PortalURL          string           `json:"portal_url"`
	PortalCAPEM        string           `json:"portal_ca,omitempty"`
	AllowDevelopmentWS bool             `json:"allow_development_ws,omitempty"`
	PortalID           string           `json:"portal_id"`
	NodeID             string           `json:"node_id"`
	PortalPQRoot       agentcrypto.JWK  `json:"portal_pq_root"`
	ECDSAPrivateKey    string           `json:"ecdsa_private_key"`
	CertificateChain   []string         `json:"certificate_chain"`
	MLDSASeed          string           `json:"mldsa_seed"`
	PQCredential       string           `json:"pq_credential"`
	RenewAfter         time.Time        `json:"renew_after"`
	Sources            protocol.Sources `json:"sources"`
}
