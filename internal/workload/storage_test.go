package workload

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
