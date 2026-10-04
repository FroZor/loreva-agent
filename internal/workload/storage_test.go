package workload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestSaveImmutableJSONReplaysIdenticalValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations", "request.started.json")
	value := operationMarker{
		Version:       1,
		RequestID:     "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		CommandDigest: "sha256:" + repeatHex('a'),
	}

	if err := saveImmutableJSON(path, value); err != nil {
		t.Fatalf("save immutable state: %v", err)
	}
	if err := saveImmutableJSON(path, value); err != nil {
		t.Fatalf("replay immutable state: %v", err)
	}
}

func TestSaveImmutableJSONRejectsConflictingValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations", "request.started.json")
	original := operationMarker{Version: 1, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}
	conflict := operationMarker{Version: 1, RequestID: "6e0c1d91-5145-440f-bf97-d84db4f83644"}

	if err := saveImmutableJSON(path, original); err != nil {
		t.Fatalf("save immutable state: %v", err)
	}
	if err := saveImmutableJSON(path, conflict); err == nil {
		t.Fatal("conflicting immutable state was accepted")
	}
}

func TestSaveImmutableJSONLeavesNoTemporaryFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "plans", "plan.json")

	if err := saveImmutableJSON(path, map[string]int{"version": 1}); err != nil {
		t.Fatalf("save immutable state: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("unexpected state directory entries: %#v", entries)
	}
}

func TestLoadProtectedJSONRejectsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	var value any
	err := loadProtectedJSON(path, &value)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected protected JSON error: %v", err)
	}
}

func TestArtifactStoreVerifiesUploads(t *testing.T) {
	store := artifactStore{root: t.TempDir()}
	content := []byte("compose artifact")
	sum := sha256.Sum256(content)
	reference := protocol.ArtifactReference{
		ArtifactID: "df9ffacf-fd65-4643-967b-422b2d4c826c",
		SHA256:     "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes:  int64(len(content)),
	}

	if err := store.store(reference, bytes.NewReader([]byte("tampered artifact"))); err == nil {
		t.Fatal("store accepted content that does not match the digest")
	}
	if err := store.store(reference, bytes.NewReader(content)); err != nil {
		t.Fatalf("store() error = %v", err)
	}
	// A repeated upload of a cached artifact is still verified.
	if err := store.store(reference, bytes.NewReader([]byte("tampered artifact"))); err == nil {
		t.Fatal("store accepted a mismatching upload of a cached artifact")
	}

	path, err := store.acquire(t.Context(), reference)
	if err != nil {
		t.Fatalf("acquire() of an uploaded artifact error = %v", err)
	}
	if stored, err := os.ReadFile(path); err != nil || !bytes.Equal(stored, content) {
		t.Fatalf("cached artifact = %q, %v", stored, err)
	}

	missing := reference
	missing.ArtifactID = "6e0c1d91-5145-440f-bf97-d84db4f83644"
	missing.SHA256 = "sha256:" + strings.Repeat("b", 64)
	if _, err := store.acquire(t.Context(), missing); err == nil {
		t.Fatal("acquire() without a source returned an artifact that was never uploaded")
	}
}
