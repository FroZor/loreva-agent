package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
)

func TestStorePersistsStateOnceWithRestrictedPermissions(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pending := &PendingEnrollment{
		PortalEndpoint:     "wss://portal.example:27460/agent/v1/enroll",
		PortalPQRootSHA256: "sha256-root",
		RequestID:          "request",
	}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadPending()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RequestID != pending.RequestID || loaded.PortalPQRootSHA256 != pending.PortalPQRootSHA256 || loaded.Version != currentVersion {
		t.Fatal("stored pending enrollment changed")
	}
	if err := store.SavePending(pending); err == nil {
		t.Fatal("state overwrite must be refused")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(store.Dir(), pendingName))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state permissions are %o", info.Mode().Perm())
		}
	}
	if err := store.ClearPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleared state error = %v", err)
	}
}

func TestStorePersistsAndClearsPendingRenewal(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pending := &PendingRenewal{
		PortalURL:          "wss://portal.example:27460",
		PortalID:           "portal-id",
		NodeID:             "node-id",
		PortalPQRootSHA256: "sha256-root",
		JTI:                "renewal-jti",
		ECDSAPrivateKey:    "ecdsa-key",
		CSR:                "csr",
		MLDSASeed:          "mldsa-seed",
	}
	if err := store.SaveRenewal(pending); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadRenewal()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != currentVersion || loaded.JTI != pending.JTI || loaded.PortalPQRootSHA256 != pending.PortalPQRootSHA256 {
		t.Fatalf("stored pending renewal changed: %#v", loaded)
	}
	if err := store.SaveRenewal(pending); err == nil {
		t.Fatal("renewal state overwrite must be refused")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(store.Dir(), renewalName))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("renewal state permissions are %o", info.Mode().Perm())
		}
	}
	if err := store.ClearRenewal(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadRenewal(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleared renewal state error = %v", err)
	}
}

func TestStoreAtomicallyReplacesExistingIdentity(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := &Identity{
		PortalID:     "portal",
		NodeID:       "node",
		PortalPQRoot: agentcrypto.JWK{Kty: "AKP", Alg: "ML-DSA-65", Pub: "root"},
		PQCredential: "old",
		RenewAfter:   time.Unix(100, 0).UTC(),
	}
	if err := store.SaveIdentity(initial); err != nil {
		t.Fatal(err)
	}
	replacement := &Identity{
		PortalID:     "portal",
		NodeID:       "node",
		PortalPQRoot: initial.PortalPQRoot,
		PQCredential: "new",
		RenewAfter:   time.Unix(200, 0).UTC(),
	}
	if err := store.ReplaceIdentity(replacement); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PQCredential != "new" || loaded.PortalPQRoot != replacement.PortalPQRoot || !loaded.RenewAfter.Equal(replacement.RenewAfter) {
		t.Fatalf("identity was not replaced: %#v", loaded)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(store.Dir(), identityName))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("identity permissions are %o", info.Mode().Perm())
		}
	}
}

func TestStoreRefusesIdentityReplacementWithoutExistingIdentity(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceIdentity(&Identity{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replacement error = %v, want ErrNotFound", err)
	}
}

func TestStoreRejectsOversizedPendingRenewal(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pending := &PendingRenewal{CSR: strings.Repeat("x", maxStateSize)}
	if err := store.SaveRenewal(pending); err == nil {
		t.Fatal("oversized renewal state must be rejected")
	}
	if _, err := store.LoadRenewal(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oversized state created a file: %v", err)
	}
}

func TestStoreKeepsExistingIdentityWhenReplacementIsOversized(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := &Identity{PortalID: "portal", NodeID: "node", PQCredential: "old"}
	if err := store.SaveIdentity(initial); err != nil {
		t.Fatal(err)
	}
	replacement := &Identity{PortalID: "portal", NodeID: "node", PQCredential: strings.Repeat("x", maxStateSize)}
	if err := store.ReplaceIdentity(replacement); err == nil {
		t.Fatal("oversized replacement must be rejected")
	}
	loaded, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PQCredential != initial.PQCredential {
		t.Fatal("failed replacement changed existing identity")
	}
}
