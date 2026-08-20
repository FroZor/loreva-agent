package enrollment

import (
	"errors"
	"io"
	"testing"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/challenge"
	"github.com/FroZor/loreva-agent/internal/connectivity"
	"github.com/FroZor/loreva-agent/internal/state"
)

func TestPendingEnrollmentReusesIdentityAndRequestID(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	options := Options{PortalURL: "wss://portal.example:27460", Hostname: "node"}
	first, firstMaterial, err := loadOrCreatePending(store, options, "wss://portal.example:27460/agent/v1/enroll", "token")
	if err != nil {
		t.Fatal(err)
	}
	second, secondMaterial, err := loadOrCreatePending(store, options, "wss://portal.example:27460/agent/v1/enroll", "token")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != second.RequestID || first.CSR != second.CSR ||
		!firstMaterial.ECDSAKey.Equal(secondMaterial.ECDSAKey) ||
		!agentcrypto.PublicKeysEqual(agentcrypto.PublicJWK(firstMaterial.MLDSAPub), secondMaterial.MLDSAPub) {
		t.Fatal("retry did not reuse jti, CSR and key material")
	}
}

func TestEnrollmentRetryClassification(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "network close", err: io.EOF, want: true},
		{name: "portal internal", err: &rejectedError{Code: "internal_error"}, want: true},
		{name: "expired proof", err: &rejectedError{Code: "expired_pq_proof"}, want: true},
		{name: "expired challenge", err: challenge.ErrExpired, want: true},
		{name: "expired token", err: &rejectedError{Code: "token_expired"}, want: false},
		{name: "resume closed", err: &rejectedError{Code: "resume_unavailable"}, want: false},
		{name: "HTTP 503", err: &httpStatusError{statusCode: 503}, want: true},
		{name: "HTTP 404", err: &httpStatusError{statusCode: 404}, want: false},
		{name: "TLS policy", err: errors.Join(errors.New("dial"), connectivity.ErrTLSPolicy), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := retryableEnrollmentError(test.err); got != test.want {
				t.Fatalf("retryableEnrollmentError() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEnrollmentTokenID(t *testing.T) {
	tokenID, err := enrollmentTokenID("1234567890abcdef.secret")
	if err != nil || tokenID != "1234567890abcdef" {
		t.Fatalf("valid token rejected: tokenID=%q err=%v", tokenID, err)
	}
	for _, token := range []string{"", "short.secret", "1234567890abcdef.", "1234567890abcdef"} {
		if _, err := enrollmentTokenID(token); err == nil {
			t.Fatalf("invalid token accepted: %q", token)
		}
	}
}
