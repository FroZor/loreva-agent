package protocol

import (
	"encoding/json"
	"time"
)

// Direct session endpoint. A device reaches it only through the node's
// userspace WireGuard listener, so plain WebSocket is enough: WireGuard
// authenticates both sides and encrypts every packet.
const (
	DirectSessionPort        = 80
	DirectSessionPath        = "/v1/session"
	DirectSessionSubprotocol = "loreva.session.v1"
)

// Direct session message types. Node reports, metrics, and workload results
// use the same types as the portal session.
const (
	SessionHelloType          = "session.hello"
	ErrorType                 = "error"
	PairingRequestType        = "pairing.request"
	PairingStartedType        = "pairing.started"
	PairingResultType         = "pairing.result"
	DevicesListType           = "devices.list"
	DevicesListResultType     = "devices.list.result"
	DeviceRemoveType          = "device.remove"
	DeviceRemoveResultType    = "device.remove.result"
	ArtifactUploadRequestType = "artifact.upload.request"
	ArtifactUploadChunkType   = "artifact.upload.chunk"
	ArtifactUploadResultType  = "artifact.upload.result"
)

// Session peers.
const (
	SessionPeerDevice = "device"
	SessionPeerInvite = "invite"
)

// Pairing statuses.
const (
	PairingApproved = "approved"
	PairingRejected = "rejected"
	PairingExpired  = "expired"
)

// Artifact upload states.
const (
	ArtifactStored   = "stored"
	ArtifactRejected = "rejected"
)

// MaxArtifactChunkBytes bounds the decoded data of one upload chunk, so the
// Base64 frame stays below the 64 KiB inbound frame limit.
const MaxArtifactChunkBytes = 32 * 1024

// SessionHello is the first frame of every direct session. Peer tells the
// device whether it may pair (invite) or use the node (device).
type SessionHello struct {
	Type           string    `json:"type"`
	Protocol       string    `json:"protocol"`
	Peer           string    `json:"peer"`
	DeviceID       string    `json:"device_id,omitempty"`
	NodeID         string    `json:"node_id"`
	AgentVersion   string    `json:"agent_version"`
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	Architecture   string    `json:"architecture"`
	PortalEnrolled bool      `json:"portal_enrolled"`
	Time           time.Time `json:"time"`
}

// Error answers a request the agent could not accept. RequestID is empty
// when the request had none.
type Error struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
}

// PairingRequest starts pairing from the temporary invite peer. The device
// commits to its keys and name before it learns the node's nonce.
type PairingRequest struct {
	Type       string `json:"type"`
	DeviceName string `json:"device_name"`
	// WireGuardPublicKey is the device's new key for this node, standard Base64.
	WireGuardPublicKey string `json:"wireguard_public_key"`
	// MLKEMEncapsulationKey is a fresh ML-KEM-768 key, standard Base64.
	MLKEMEncapsulationKey string `json:"mlkem_encapsulation_key"`
}

// PairingStarted returns what the device needs to compute the code and the PSK.
type PairingStarted struct {
	Type      string `json:"type"`
	PairingID string `json:"pairing_id"`
	// NodeNonce is 32 random bytes, standard Base64.
	NodeNonce string `json:"node_nonce"`
	// MLKEMCiphertext is the ML-KEM-768 ciphertext, standard Base64.
	MLKEMCiphertext string `json:"mlkem_ciphertext"`
	// DeviceAddress is the device's permanent IPv6 address inside the tunnel.
	DeviceAddress string `json:"device_address"`
}

// PairingResult reports the operator's decision on the node.
type PairingResult struct {
	Type      string `json:"type"`
	PairingID string `json:"pairing_id"`
	Status    string `json:"status"`
	DeviceID  string `json:"device_id,omitempty"`
}

// DevicesList asks for every paired device.
type DevicesList struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

// DevicesListResult lists every paired device.
type DevicesListResult struct {
	Type      string   `json:"type"`
	RequestID string   `json:"request_id"`
	Devices   []Device `json:"devices"`
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

// DeviceRemove revokes a paired device, possibly the caller itself.
type DeviceRemove struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	DeviceID  string `json:"device_id"`
}

// DeviceRemoveResult confirms a revocation.
type DeviceRemoveResult struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	DeviceID  string `json:"device_id"`
}

// DeviceWorkloadCommand is a workload request from a paired device. The
// device is authenticated by its WireGuard key, so the command is not
// signed; the agent binds it to the node's direct controller scope.
type DeviceWorkloadCommand struct {
	Type          string          `json:"type"`
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	WorkloadID    string          `json:"workload_id"`
	Payload       json.RawMessage `json:"payload"`
}

// ArtifactUploadRequest announces an artifact that the following chunks carry.
type ArtifactUploadRequest struct {
	Type       string `json:"type"`
	RequestID  string `json:"request_id"`
	ArtifactID string `json:"artifact_id"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
}

// ArtifactUploadChunk carries the next part of an announced artifact.
type ArtifactUploadChunk struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Offset    int64  `json:"offset"`
	// Data is at most MaxArtifactChunkBytes, standard Base64.
	Data string `json:"data"`
}

// ArtifactUploadResult ends an upload.
type ArtifactUploadResult struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	State     string `json:"state"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}
