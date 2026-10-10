package direct_test

import (
	"testing"

	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/state"
)

func TestInitCreatesTLSIdentityAndTCPPort(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	node, err := direct.Init(store, direct.InitOptions{Endpoints: []string{"203.0.113.10"}})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if node.ListenPort < 20000 || node.ListenPort > 32000 {
		t.Fatalf("listen port = %d, want 20000-32000", node.ListenPort)
	}
	if _, err := (certpin.Identity{PrivateKey: node.TLSPrivateKey, Certificate: node.TLSCertificate}).Pin(); err != nil {
		t.Fatalf("node TLS identity is unusable: %v", err)
	}
	if _, err := direct.Init(store, direct.InitOptions{}); err == nil {
		t.Fatal("second Init() succeeded")
	}
}
