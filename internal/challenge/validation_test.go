package challenge

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestValidate(t *testing.T) {
	now := time.Now()
	valid := protocol.Challenge{
		Type:        protocol.ConnectChallenge,
		ChallengeID: "019c8c9d-d6f5-7c31-b4f1-9fd54ed6f590",
		Nonce:       base64.RawURLEncoding.EncodeToString(make([]byte, nonceSize)),
		PortalID:    "019c8c9e-cc31-7a7a-999d-4f99d0c61c0f",
		IssuedAt:    now,
		ExpiresAt:   now.Add(30 * time.Second),
	}

	if err := Validate(valid, protocol.ConnectChallenge, valid.PortalID); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	expired := valid
	expired.IssuedAt = now.Add(-time.Minute)
	expired.ExpiresAt = now.Add(-time.Second)

	if err := Validate(expired, protocol.ConnectChallenge, valid.PortalID); !errors.Is(err, ErrExpired) {
		t.Fatalf("Validate() error = %v, want ErrExpired", err)
	}
}
