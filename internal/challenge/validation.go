// Package challenge validates portal-issued protocol challenges.
package challenge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	nonceSize        = 32
	maximumLifetime  = time.Minute
	maximumClockSkew = 30 * time.Second
)

// ErrExpired identifies an otherwise valid challenge whose lifetime elapsed.
var ErrExpired = errors.New("portal challenge expired")

// Validate verifies a challenge type, identity, nonce, and lifetime. An empty
// portalID accepts the valid portal identity supplied during initial enrollment.
func Validate(value protocol.Challenge, expectedType, portalID string) error {
	if value.Type != expectedType {
		return fmt.Errorf("unexpected challenge type %q", value.Type)
	}
	if !agentcrypto.ValidUUID(value.ChallengeID) || !agentcrypto.ValidUUID(value.PortalID) {
		return errors.New("challenge contains an invalid UUID")
	}
	if portalID != "" && value.PortalID != portalID {
		return errors.New("challenge portal_id does not match enrolled portal")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(value.Nonce)
	if err != nil || len(nonce) != nonceSize {
		return errors.New("challenge nonce must be 32-byte base64url without padding")
	}

	now := time.Now()
	if value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() {
		return errors.New("challenge has invalid timestamps")
	}
	if !value.ExpiresAt.After(now) {
		return ErrExpired
	}
	if !value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.Sub(value.IssuedAt) > maximumLifetime {
		return errors.New("challenge lifetime exceeds protocol limit")
	}
	if value.IssuedAt.After(now.Add(maximumClockSkew)) {
		return errors.New("challenge issued_at is too far in the future")
	}

	return nil
}
