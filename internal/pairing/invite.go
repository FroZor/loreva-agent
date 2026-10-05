// Package pairing defines the connection key format and the transcript that
// both sides of a pairing agree on. Both the agent and clients use it.
package pairing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const (
	// InvitePrefix starts every encoded invite. It is a URI, so the operating
	// system can open Loreva App from it; the format version is the "v" field.
	InvitePrefix   = "loreva://connect/"
	inviteVersion  = 2
	maxInviteSize  = 4096
	maxEndpoints   = 16
	minEndpointLen = len("[::1]:1")
	// TokenSize is the length of the one-time pairing token.
	TokenSize = 32
)

// Invite is the one-time secret printed on the node. Whoever presents its
// token first can start pairing, so it must travel only over a trusted
// channel; the code comparison catches a token used by someone else.
type Invite struct {
	InviteID string
	NodeID   string
	// NodePin is the pin of the node's TLS key. It authenticates the node.
	NodePin   string
	Endpoints []netip.AddrPort
	// Token is the one-time pairing token.
	Token     []byte
	ExpiresAt time.Time
}

type inviteDocument struct {
	Version   int       `json:"v"`
	InviteID  string    `json:"invite_id"`
	NodeID    string    `json:"node_id"`
	NodePin   string    `json:"node_pin"`
	Endpoints []string  `json:"endpoints"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewToken returns a fresh pairing token.
func NewToken() ([]byte, error) {
	token := make([]byte, TokenSize)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate pairing token: %w", err)
	}

	return token, nil
}

// EncodeToken returns the wire form of a pairing token.
func EncodeToken(token []byte) string {
	return base64.RawURLEncoding.EncodeToString(token)
}

// DecodeToken parses the wire form of a pairing token.
func DecodeToken(value string) ([]byte, error) {
	token, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(token) != TokenSize {
		return nil, errors.New("pairing token must be 32 bytes of unpadded Base64URL")
	}

	return token, nil
}

// TokenEqual compares tokens in constant time.
func TokenEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Encode returns the printable loreva://connect/ form of the invite.
func (invite *Invite) Encode() (string, error) {
	if err := invite.validate(); err != nil {
		return "", err
	}

	endpoints := make([]string, 0, len(invite.Endpoints))
	for _, endpoint := range invite.Endpoints {
		endpoints = append(endpoints, endpoint.String())
	}

	data, err := json.Marshal(inviteDocument{
		Version:   inviteVersion,
		InviteID:  invite.InviteID,
		NodeID:    invite.NodeID,
		NodePin:   invite.NodePin,
		Endpoints: endpoints,
		Token:     EncodeToken(invite.Token),
		ExpiresAt: invite.ExpiresAt.UTC(),
	})
	if err != nil {
		return "", fmt.Errorf("encode invite: %w", err)
	}

	return InvitePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// ParseInvite decodes and validates a loreva://connect/ invite. It does not
// check expiry; the node is the authority on that.
func ParseInvite(encoded string) (*Invite, error) {
	encoded = strings.TrimSpace(encoded)
	if len(encoded) > maxInviteSize {
		return nil, errors.New("invite is too long")
	}

	payload, found := strings.CutPrefix(encoded, InvitePrefix)
	if !found {
		return nil, errors.New("invite must start with " + InvitePrefix)
	}

	data, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil {
		return nil, errors.New("invite is not valid unpadded Base64URL")
	}

	var document inviteDocument
	if err := strictjson.Decode(data, &document); err != nil {
		return nil, fmt.Errorf("decode invite: %w", err)
	}

	invite, err := document.invite()
	if err != nil {
		return nil, err
	}
	if err := invite.validate(); err != nil {
		return nil, err
	}

	return invite, nil
}

func (document inviteDocument) invite() (*Invite, error) {
	if document.Version != inviteVersion {
		return nil, fmt.Errorf("unsupported invite version %d", document.Version)
	}
	if len(document.Endpoints) > maxEndpoints {
		return nil, errors.New("invite has too many endpoints")
	}

	token, err := DecodeToken(document.Token)
	if err != nil {
		return nil, fmt.Errorf("invite token: %w", err)
	}

	invite := &Invite{
		InviteID:  document.InviteID,
		NodeID:    document.NodeID,
		NodePin:   document.NodePin,
		Token:     token,
		ExpiresAt: document.ExpiresAt,
	}

	for _, value := range document.Endpoints {
		endpoint, err := ParseEndpoint(value)
		if err != nil {
			return nil, err
		}

		invite.Endpoints = append(invite.Endpoints, endpoint)
	}

	return invite, nil
}

func (invite *Invite) validate() error {
	if !agentcrypto.ValidUUID(invite.InviteID) || !agentcrypto.ValidUUID(invite.NodeID) {
		return errors.New("invite identifiers must be UUIDs")
	}
	if err := certpin.Validate(invite.NodePin); err != nil {
		return fmt.Errorf("invite node_pin: %w", err)
	}
	if len(invite.Token) != TokenSize {
		return errors.New("invite token must be 32 bytes")
	}
	if len(invite.Endpoints) == 0 || len(invite.Endpoints) > maxEndpoints {
		return fmt.Errorf("invite must list between 1 and %d endpoints", maxEndpoints)
	}
	if invite.ExpiresAt.IsZero() {
		return errors.New("invite expiry is required")
	}

	return nil
}

// ParseEndpoint parses an outer host:port endpoint given as an IP literal.
// Host names are rejected so that an invite cannot point a client at an
// address chosen later by DNS.
func ParseEndpoint(value string) (netip.AddrPort, error) {
	if len(value) < minEndpointLen {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q", value)
	}

	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.Port() == 0 || !endpoint.Addr().IsValid() || endpoint.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q must be IP:port", value)
	}
	if endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q is not a unicast address", value)
	}

	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), nil
}
