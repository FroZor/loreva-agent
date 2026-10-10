package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FroZor/loreva-agent/internal/state"
)

func TestSetUpInitializesDirectAccessWithoutBootstrap(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := setUp(store, missingConfig, logger); err != nil {
		t.Fatal(err)
	}

	node, err := store.LoadNode()
	if err != nil {
		t.Fatalf("LoadNode() error = %v, want a node created by the first start", err)
	}
	if err := setUp(store, missingConfig, logger); err != nil {
		t.Fatal(err)
	}
	again, err := store.LoadNode()
	if err != nil {
		t.Fatal(err)
	}
	if again.NodeID != node.NodeID {
		t.Fatalf("second start replaced node %s with %s", node.NodeID, again.NodeID)
	}
}

func TestSetUpReportsUnreadableBootstrap(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err = setUp(store, t.TempDir(), logger)
	if err == nil || !strings.Contains(err.Error(), "bootstrap config") {
		t.Fatalf("setUp() error = %v, want bootstrap read error", err)
	}
	if _, err := store.LoadNode(); err == nil {
		t.Fatal("setUp() created a direct node although a bootstrap was mounted")
	}
}

func TestRunStartRejectsCorruptIdentityWithoutEnrollment(t *testing.T) {
	stateDir := t.TempDir()
	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIdentity(&state.Identity{}); err != nil {
		t.Fatal(err)
	}

	identityPath := filepath.Join(stateDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = runStart([]string{"--state-dir", stateDir, "--config", missingConfig}, logger)
	if err == nil || !strings.Contains(err.Error(), "decode state file") {
		t.Fatalf("runStart() error = %v, want corrupt identity error", err)
	}
	if strings.Contains(err.Error(), "open bootstrap config") {
		t.Fatalf("runStart() unexpectedly attempted enrollment: %v", err)
	}
}
