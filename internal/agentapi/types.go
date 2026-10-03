// Package agentapi defines the JSON documents of the HTTP API that the agent
// serves to paired devices inside the WireGuard tunnel. docs/api/openapi.yaml
// is the human-readable contract for the same types.
package agentapi

import (
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// Port is the TCP port of the API on the node's tunnel address. The API uses
// plain HTTP because WireGuard already authenticates and encrypts every packet.
const Port = 80

// API paths.
const (
	PairingPath        = "/v1/pairing"
	NodePath           = "/v1/node"
	SpecificationsPath = "/v1/node/specifications"
	NetworkPath        = "/v1/node/network"
	DevicesPath        = "/v1/devices"
)

// Pairing statuses.
const (
	PairingPending  = "pending"
	PairingApproved = "approved"
	PairingRejected = "rejected"
	PairingExpired  = "expired"
)

// PairingRequest starts pairing from the temporary invite peer. The device
// commits to its keys and name before it learns the node's nonce.
type PairingRequest struct {
	DeviceName string `json:"device_name"`
	// WireGuardPublicKey is the device's new key for this node, standard Base64.
	WireGuardPublicKey string `json:"wireguard_public_key"`
	// MLKEMEncapsulationKey is a fresh ML-KEM-768 key, standard Base64.
	MLKEMEncapsulationKey string `json:"mlkem_encapsulation_key"`
}

// PairingStarted returns what the device needs to compute the SAS and the PSK.
type PairingStarted struct {
	PairingID string `json:"pairing_id"`
	// NodeNonce is 32 random bytes, standard Base64.
	NodeNonce string `json:"node_nonce"`
	// MLKEMCiphertext is the ML-KEM-768 ciphertext, standard Base64.
	MLKEMCiphertext string `json:"mlkem_ciphertext"`
	// DeviceAddress is the device's permanent IPv6 address inside the tunnel.
	DeviceAddress string `json:"device_address"`
}

// PairingStatus reports the operator's decision on the node.
type PairingStatus struct {
	Status   string `json:"status"`
	DeviceID string `json:"device_id,omitempty"`
}

// Node describes the agent and its direct-connection settings.
type Node struct {
	NodeID             string    `json:"node_id"`
	AgentVersion       string    `json:"agent_version"`
	Hostname           string    `json:"hostname"`
	OS                 string    `json:"os"`
	Architecture       string    `json:"architecture"`
	WireGuardPublicKey string    `json:"wireguard_public_key"`
	TunnelAddress      string    `json:"tunnel_address"`
	ListenPort         int       `json:"listen_port"`
	PortalEnrolled     bool      `json:"portal_enrolled"`
	Time               time.Time `json:"time"`
}

// Specifications is a hardware snapshot. It uses the same schema as the
// node.specifications.report portal message.
type Specifications struct {
	ObservedAt       time.Time                   `json:"observed_at"`
	ObservationScope string                      `json:"observation_scope"`
	Specifications   protocol.NodeSpecifications `json:"specifications"`
}

// Network is a network and firewall snapshot. It uses the same schema as the
// node.network.report portal message.
type Network struct {
	ObservedAt       time.Time            `json:"observed_at"`
	ObservationScope string               `json:"observation_scope"`
	Network          protocol.NodeNetwork `json:"network"`
}

// Device is a paired device as other devices see it. The PSK is never exposed.
type Device struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	WireGuardPublicKey string    `json:"wireguard_public_key"`
	TunnelAddress      string    `json:"tunnel_address"`
	PairedAt           time.Time `json:"paired_at"`
	Current            bool      `json:"current"`
}

// DeviceList lists every paired device.
type DeviceList struct {
	Devices []Device `json:"devices"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries a stable machine-readable code and a short message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
