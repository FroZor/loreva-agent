package tunnel

import (
	"net/netip"
	"strings"
	"testing"
)

func TestKeys(t *testing.T) {
	private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseKey(public.String())
	if err != nil || parsed != public {
		t.Fatalf("ParseKey(String()) = %v, %v", parsed, err)
	}
	for _, invalid := range []string{"", "AAAA", strings.Repeat("A", 43) + "=" + "=", public.String() + "AAAA"} {
		if _, err := ParseKey(invalid); err == nil {
			t.Errorf("ParseKey(%q) succeeded", invalid)
		}
	}
	if !(Key{}).IsZero() || public.IsZero() {
		t.Fatal("IsZero() is wrong")
	}
}

func TestAddresses(t *testing.T) {
	prefix, err := NewPrefix()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrefix(prefix.String()); err != nil {
		t.Fatalf("ParsePrefix(NewPrefix()) error = %v", err)
	}

	node := NodeAddress(prefix)
	address, err := RandomAddress(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !prefix.Contains(node) || !prefix.Contains(address) || address == node {
		t.Fatalf("node %s, random %s, prefix %s", node, address, prefix)
	}

	for _, invalid := range []string{"10.0.0.0/8", "fd00::/48", "fd00::1/64", "2001:db8::/64", "nonsense"} {
		if _, err := ParsePrefix(invalid); err == nil {
			t.Errorf("ParsePrefix(%q) succeeded", invalid)
		}
	}
}

func TestPeerRequiresPresharedKey(t *testing.T) {
	public, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	var builder strings.Builder
	err = writePeer(&builder, Peer{PublicKey: public, Address: netip.MustParseAddr("fd00::2")})
	if err == nil {
		t.Fatal("writePeer() accepted a peer without a preshared key")
	}

	err = writePeer(&builder, Peer{PublicKey: public, PresharedKey: public, Address: netip.MustParseAddr("10.0.0.2")})
	if err == nil {
		t.Fatal("writePeer() accepted an IPv4 peer address")
	}
}
