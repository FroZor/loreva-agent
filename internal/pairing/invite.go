// Package pairing defines the invite format and the key agreement that turns
// an invite into a long-lived device peer. Both the agent and clients use it.
package pairing

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/strictjson"
	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const (
	// InvitePrefix starts every encoded invite and carries the format version.
	InvitePrefix   = "loreva1:"
	inviteVersion  = 1
	maxInviteSize  = 4096
	maxEndpoints   = 16
	minEndpointLen = len("[::1]:1")
)

// Invite is the one-time secret printed on the node. Whoever presents it
// first can start pairing, so it must travel only over a trusted channel.
type Invite struct {
	InviteID string
	NodeID   string
	// NodePublicKey authenticates the node in the WireGuard handshake.
	NodePublicKey tunnel.Key
	NodeAddress   netip.Addr
	Endpoints     []netip.AddrPort
	// PrivateKey, PresharedKey, and Address belong to the temporary invite peer.
	PrivateKey   tunnel.Key
	PresharedKey tunnel.Key
	Address      netip.Addr
	ExpiresAt    time.Time
}

type inviteDocument struct {
	Version       int       `json:"v"`
	InviteID      string    `json:"invite_id"`
	NodeID        string    `json:"node_id"`
	NodePublicKey string    `json:"node_public_key"`
	NodeAddress   string    `json:"node_address"`
	Endpoints     []string  `json:"endpoints"`
	PrivateKey    string    `json:"invite_private_key"`
	PresharedKey  string    `json:"invite_preshared_key"`
	Address       string    `json:"invite_address"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Encode returns the printable loreva1: form of the invite.
func (invite *Invite) Encode() (string, error) {
	if err := invite.validate(); err != nil {
		return "", err
	}

	endpoints := make([]string, 0, len(invite.Endpoints))
	for _, endpoint := range invite.Endpoints {
		endpoints = append(endpoints, endpoint.String())
	}

	data, err := json.Marshal(inviteDocument{
		Version:       inviteVersion,
		InviteID:      invite.InviteID,
		NodeID:        invite.NodeID,
		NodePublicKey: invite.NodePublicKey.String(),
		NodeAddress:   invite.NodeAddress.String(),
		Endpoints:     endpoints,
		PrivateKey:    invite.PrivateKey.String(),
		PresharedKey:  invite.PresharedKey.String(),
		Address:       invite.Address.String(),
		ExpiresAt:     invite.ExpiresAt.UTC(),
	})
	if err != nil {
		return "", fmt.Errorf("encode invite: %w", err)
	}

	return InvitePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// ParseInvite decodes and validates a loreva1: invite. It does not check
// expiry; the node is the authority on that.
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

	invite := &Invite{
		InviteID:  document.InviteID,
		NodeID:    document.NodeID,
		ExpiresAt: document.ExpiresAt,
	}

	var err error
	if invite.NodePublicKey, err = tunnel.ParseKey(document.NodePublicKey); err != nil {
		return nil, fmt.Errorf("invite node_public_key: %w", err)
	}
	if invite.PrivateKey, err = tunnel.ParseKey(document.PrivateKey); err != nil {
		return nil, fmt.Errorf("invite invite_private_key: %w", err)
	}
	if invite.PresharedKey, err = tunnel.ParseKey(document.PresharedKey); err != nil {
		return nil, fmt.Errorf("invite invite_preshared_key: %w", err)
	}
	if invite.NodeAddress, err = netip.ParseAddr(document.NodeAddress); err != nil {
		return nil, fmt.Errorf("invite node_address: %w", err)
	}
	if invite.Address, err = netip.ParseAddr(document.Address); err != nil {
		return nil, fmt.Errorf("invite invite_address: %w", err)
	}
	if len(document.Endpoints) > maxEndpoints {
		return nil, errors.New("invite has too many endpoints")
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
	if invite.NodePublicKey.IsZero() || invite.PrivateKey.IsZero() || invite.PresharedKey.IsZero() {
		return errors.New("invite keys must not be empty")
	}
	if !invite.NodeAddress.Is6() || !invite.Address.Is6() || invite.NodeAddress == invite.Address {
		return errors.New("invite tunnel addresses must be distinct IPv6 addresses")
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
