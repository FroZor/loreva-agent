package direct_test

import (
	"errors"
	"os"
	"path/filepath"
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

func TestLoadNodeUpgradesWireGuardState(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"version":1,"node_id":"65a1876f-a715-45fc-9ac0-e4bc31067059",` +
		`"wireguard_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","listen_port":24567,` +
		`"tunnel_prefix":"fd00:1:2:3::/64","endpoints":["203.0.113.10:24567"],"created_at":"2026-10-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "node.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devices.json"), []byte(`{"version":1,"items":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := state.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadNode(); !errors.Is(err, state.ErrLegacyDirect) {
		t.Fatalf("LoadNode() error = %v, want ErrLegacyDirect", err)
	}
	if _, err := store.LoadDevices(); !errors.Is(err, state.ErrLegacyDirect) {
		t.Fatalf("LoadDevices() error = %v, want ErrLegacyDirect", err)
	}

	node, upgraded, err := direct.LoadNode(store)
	if err != nil || !upgraded {
		t.Fatalf("direct.LoadNode() = %v, %v", upgraded, err)
	}
	if node.NodeID != "65a1876f-a715-45fc-9ac0-e4bc31067059" || len(node.Endpoints) != 1 || node.TLSCertificate == "" {
		t.Fatalf("upgraded node = %+v", node)
	}

	again, upgraded, err := direct.LoadNode(store)
	if err != nil || upgraded || again.TLSCertificate != node.TLSCertificate {
		t.Fatalf("second direct.LoadNode() = %+v, %v, %v", again, upgraded, err)
	}
}
