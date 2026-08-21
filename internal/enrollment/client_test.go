package enrollment

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

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
	first, firstMaterial, err := loadOrCreatePending(store, options, "wss://portal.example:27460/agent/v1/enroll", "portal-id", "token")
	if err != nil {
		t.Fatal(err)
	}
	second, secondMaterial, err := loadOrCreatePending(store, options, "wss://portal.example:27460/agent/v1/enroll", "portal-id", "token")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != second.RequestID || first.CSR != second.CSR ||
		!firstMaterial.ECDSAKey.Equal(secondMaterial.ECDSAKey) ||
		!agentcrypto.PublicKeysEqual(agentcrypto.PublicJWK(firstMaterial.MLDSAPub), secondMaterial.MLDSAPub) {
		t.Fatal("retry did not reuse jti, CSR and key material")
	}
}

func TestPendingEnrollmentUpdatesTokenWithoutReplacingIdentity(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	options := Options{PortalURL: "wss://portal.example:27460", Hostname: "node"}
	endpoint := "wss://portal.example:27460/agent/v1/enroll"
	first, firstMaterial, err := loadOrCreatePending(store, options, endpoint, "portal-id", "first-token-id")
	if err != nil {
		t.Fatal(err)
	}

	second, secondMaterial, err := loadOrCreatePending(store, options, endpoint, "portal-id", "new-token-id")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != second.RequestID || first.CSR != second.CSR || first.MLDSASeed != second.MLDSASeed ||
		!firstMaterial.ECDSAKey.Equal(secondMaterial.ECDSAKey) ||
		!agentcrypto.PublicKeysEqual(agentcrypto.PublicJWK(firstMaterial.MLDSAPub), secondMaterial.MLDSAPub) {
		t.Fatal("new token for the same portal replaced pending identity material")
	}
	if second.EnrollmentTokenID != "new-token-id" {
		t.Fatalf("EnrollmentTokenID = %q, want new-token-id", second.EnrollmentTokenID)
	}

	persisted, err := store.LoadPending()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.EnrollmentTokenID != "new-token-id" || persisted.RequestID != first.RequestID {
		t.Fatal("updated token binding was not persisted atomically")
	}
}

func TestPendingEnrollmentReplacesIdentityWhenPortalAddressChanges(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	options := Options{PortalURL: "wss://portal.example:27460", Hostname: "node"}
	first, _, err := loadOrCreatePending(store, options, "wss://portal.example:27460/agent/v1/enroll", "portal-id", "first-token-id")
	if err != nil {
		t.Fatal(err)
	}

	second, _, err := loadOrCreatePending(store, options, "wss://replacement.example:27460/agent/v1/enroll", "portal-id", "new-token-id")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID == second.RequestID || first.CSR == second.CSR || first.MLDSASeed == second.MLDSASeed {
		t.Fatal("new portal address reused pending enrollment material")
	}

	persisted, err := store.LoadPending()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.PortalEndpoint != second.PortalEndpoint ||
		persisted.EnrollmentTokenID != second.EnrollmentTokenID ||
		persisted.RequestID != second.RequestID {
		t.Fatal("replacement portal transaction was not persisted atomically")
	}
}

func TestPendingEnrollmentReplacesIdentityWhenPortalIDChanges(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	options := Options{PortalURL: "wss://portal.example:27460", Hostname: "node"}
	endpoint := "wss://portal.example:27460/agent/v1/enroll"
	first, _, err := loadOrCreatePending(store, options, endpoint, "first-portal-id", "first-token-id")
	if err != nil {
		t.Fatal(err)
	}

	second, _, err := loadOrCreatePending(store, options, endpoint, "second-portal-id", "new-token-id")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID == second.RequestID || first.CSR == second.CSR || first.MLDSASeed == second.MLDSASeed {
		t.Fatal("different portal identity reused pending enrollment material")
	}
}

func TestPendingEnrollmentReplacesIdentityForDifferentPortal(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	options := Options{PortalURL: "wss://portal.example:27460", Hostname: "node"}
	first, _, err := loadOrCreatePending(store, options, "wss://portal.example:27460/agent/v1/enroll", "first-portal-id", "first-token-id")
	if err != nil {
		t.Fatal(err)
	}

	second, _, err := loadOrCreatePending(store, options, "wss://replacement.example:27460/agent/v1/enroll", "second-portal-id", "new-token-id")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID == second.RequestID || first.CSR == second.CSR || first.MLDSASeed == second.MLDSASeed {
		t.Fatal("different portal reused pending enrollment material")
	}
}

func TestUnavailablePortalDoesNotCreatePendingEnrollment(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	_, err = Enroll(ctx, Options{
		PortalURL: "wss://" + address,
		Token:     "1234567890abcdef.secret",
		StateDir:  stateDir,
		Hostname:  "node",
	})
	if err == nil || (!errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "connection refused")) {
		t.Fatalf("Enroll() error = %v, want unavailable portal", err)
	}

	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unavailable portal persisted enrollment state: %v", err)
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
