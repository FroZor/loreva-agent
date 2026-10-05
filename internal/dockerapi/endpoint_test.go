package dockerapi

import "testing"

func TestValidateEndpoint(t *testing.T) {
	t.Setenv("DOCKER_TLS_VERIFY", "")

	if err := ValidateEndpoint("tcp://docker.example:2375"); err == nil {
		t.Fatal("plain TCP endpoint was accepted")
	}
	if err := ValidateEndpoint("unix:///var/run/docker.sock"); err != nil {
		t.Fatalf("local socket rejected: %v", err)
	}
}
