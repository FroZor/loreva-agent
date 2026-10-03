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

// Node is the locally created identity that lets devices connect to the agent
// directly over WireGuard, without a portal.
type Node struct {
	Version int    `json:"version"`
	NodeID  string `json:"node_id"`
	// WireGuardPrivateKey is the standard Base64 encoding of the node's
	// Curve25519 private key.
	WireGuardPrivateKey string `json:"wireguard_private_key"`
	ListenPort          int    `json:"listen_port"`
	// TunnelPrefix is the node's random unique local IPv6 /64. The node uses
	// the first address and assigns every peer its own address from it.
	TunnelPrefix string `json:"tunnel_prefix"`
	// Endpoints are operator-supplied host:port values advertised in invites
	// before the automatically detected interface addresses.
	Endpoints []string  `json:"endpoints,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Devices is the registry of devices paired with the local node.
type Devices struct {
	Version int      `json:"version"`
	Items   []Device `json:"items"`
}

// Device is one paired client device and its WireGuard peer configuration.
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// WireGuardPublicKey is the standard Base64 encoding of the device's
	// Curve25519 public key for this node.
	WireGuardPublicKey string `json:"wireguard_public_key"`
	// PresharedKey is the standard Base64 encoding of the WireGuard PSK
	// derived during pairing.
	PresharedKey  string    `json:"preshared_key"`
	TunnelAddress string    `json:"tunnel_address"`
	PairedAt      time.Time `json:"paired_at"`
}
