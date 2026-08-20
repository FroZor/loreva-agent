// Package protocol defines the agent-to-portal wire messages.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/FroZor/loreva-agent/internal/strictjson"
)

// Wire protocol identifiers shared by the agent and portal.
const (
	Version                = 1
	SecurityProfile        = "pqc-hybrid-v1"
	EnrollmentSubprotocol  = "loreva.enrollment.v1"
	ConnectSubprotocol     = "loreva.connect.v1"
	EnrollmentChallenge    = "enrollment.challenge"
	EnrollmentRequestType  = "enrollment.request"
	EnrollmentAcceptedType = "enrollment.accepted"
	EnrollmentRejectedType = "enrollment.rejected"
	ConnectChallenge       = "connect.challenge"
	ConnectProofType       = "connect.proof"
	ConnectAcceptedType    = "connect.accepted"
	ConnectRejectedType    = "connect.rejected"
	RenewRequestType       = "renew.request"
	RenewAcceptedType      = "renew.accepted"
	RenewRejectedType      = "renew.rejected"
	SourcesUpdateType      = "sources.update"
	DrainType              = "drain"
)

// Challenge is a short-lived portal nonce used to bind a proof.
type Challenge struct {
	Type        string    `json:"type"`
	ChallengeID string    `json:"challenge_id"`
	Nonce       string    `json:"nonce"`
	PortalID    string    `json:"portal_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// AgentInfo describes the agent build and advertised capabilities.
type AgentInfo struct {
	Version      string   `json:"version"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Hostname     string   `json:"hostname"`
	Capabilities []string `json:"capabilities"`
}

// EnrollmentRequest carries the initial identity proof and CSR.
type EnrollmentRequest struct {
	Type            string    `json:"type"`
	ProtocolVersion int       `json:"protocol_version"`
	Agent           AgentInfo `json:"agent"`
	CSR             string    `json:"csr"`
	PQPoP           string    `json:"pq_pop"`
}

// EnrollmentAccepted contains a newly issued node identity.
type EnrollmentAccepted struct {
	Type             string    `json:"type"`
	NodeID           string    `json:"node_id"`
	CertificateChain []string  `json:"certificate_chain"`
	PQCredential     string    `json:"pq_credential"`
	RenewAfter       time.Time `json:"renew_after"`
	Sources          Sources   `json:"sources"`
}

// Sources is a versioned and expiring gateway pool.
type Sources struct {
	Generation int64        `json:"generation"`
	ExpiresAt  time.Time    `json:"expires_at"`
	Items      []SourceItem `json:"items"`
}

// SourceItem defines one weighted gateway endpoint.
type SourceItem struct {
	URL             string `json:"url"`
	Priority        int    `json:"priority"`
	Weight          int    `json:"weight"`
	SecurityProfile string `json:"security_profile"`
}

// ConnectProof proves possession of the enrolled PQ identity.
type ConnectProof struct {
	Type         string `json:"type"`
	PQCredential string `json:"pq_credential"`
	PQPoP        string `json:"pq_pop"`
}

// SignedChallenge wraps a portal-authenticated challenge JWS.
type SignedChallenge struct {
	Type            string `json:"type"`
	SignedChallenge string `json:"signed_challenge"`
}

// ConnectAccepted confirms that the working session is established.
type ConnectAccepted struct {
	Type string `json:"type"`
}

// RenewRequest carries fresh key material for identity rotation.
type RenewRequest struct {
	Type  string `json:"type"`
	CSR   string `json:"csr"`
	PQPoP string `json:"pq_pop"`
}

// RenewAccepted contains the rotated portal-issued identity.
type RenewAccepted struct {
	Type             string    `json:"type"`
	CertificateChain []string  `json:"certificate_chain"`
	PQCredential     string    `json:"pq_credential"`
	RenewAfter       time.Time `json:"renew_after"`
}

// SourcesUpdate replaces the cached gateway pool by generation.
type SourcesUpdate struct {
	Type    string  `json:"type"`
	Sources Sources `json:"sources"`
}

// Drain asks the agent to reconnect away from the current endpoint.
type Drain struct {
	Type     string     `json:"type"`
	Reason   string     `json:"reason,omitempty"`
	Deadline *time.Time `json:"deadline,omitempty"`
}

// Rejected is the common protocol rejection envelope.
type Rejected struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// DecodeStrict decodes exactly one unambiguous protocol message.
func DecodeStrict(data []byte, target any) error {
	if err := strictjson.Decode(data, target); err != nil {
		return fmt.Errorf("decode protocol message: %w", err)
	}

	return nil
}

// MessageType inspects a frame's type for dispatch only. Callers must strictly
// decode every recognized message before using any other field.
func MessageType(data []byte) (string, error) {
	var envelope struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Type == "" {
		return "", errors.New("protocol message does not contain a valid type")
	}

	return envelope.Type, nil
}
