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

func TestRunStartReadsBootstrapOnlyWithoutIdentity(t *testing.T) {
	stateDir := t.TempDir()
	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := runStart([]string{"--state-dir", stateDir, "--config", missingConfig}, logger)
	if err == nil || !strings.Contains(err.Error(), "open bootstrap config") {
		t.Fatalf("runStart() error = %v, want missing bootstrap error", err)
	}

	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIdentity(&state.Identity{}); err != nil {
		t.Fatal(err)
	}

	err = runStart([]string{"--state-dir", stateDir, "--config", missingConfig}, logger)
	if err == nil || strings.Contains(err.Error(), "open bootstrap config") {
		t.Fatalf("runStart() error = %v, want stored identity validation error", err)
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
