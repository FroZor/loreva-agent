package main

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestLoadPortalBootstrapFromStdin(t *testing.T) {
	raw := `{"portal":"wss://portal.example:27460","token":"1234567890abcdef.secret"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	path := t.TempDir() + string(os.PathSeparator) + "bootstrap.txt"

	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}

	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := input.Close(); err != nil {
			t.Errorf("close bootstrap input: %v", err)
		}
	})

	previousStdin := os.Stdin
	os.Stdin = input
	t.Cleanup(func() {
		os.Stdin = previousStdin
	})

	bootstrap, err := loadPortalBootstrap("-")
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.PortalURL != "wss://portal.example:27460" || bootstrap.EnrollmentToken != "1234567890abcdef.secret" {
		t.Fatalf("decoded bootstrap = %#v", bootstrap)
	}
}

func TestLoadPortalBootstrapRejectsProcessArgument(t *testing.T) {
	_, err := loadPortalBootstrap("secret")
	if err == nil || !strings.Contains(err.Error(), "not accepted in process arguments") {
		t.Fatalf("loadPortalBootstrap() error = %v", err)
	}
}
