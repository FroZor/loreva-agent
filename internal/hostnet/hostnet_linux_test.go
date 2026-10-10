//go:build linux

package hostnet

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

const fibTrie = `Main:
  +-- 0.0.0.0/0 3 0 4
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 172.17.0.0/16 2 0 2
        |-- 172.17.0.1
           /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 4
     |-- 127.0.0.1
        /32 host LOCAL
     |-- 172.17.0.1
        /32 host LOCAL
     |-- 203.0.113.7
        /32 host LOCAL
`

const routeTable = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	017100CB	0003	0	0	0	00000000	0	0	0
eth0	007100CB	00000000	0001	0	0	0	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

func TestIPv4AddressesFromLocalTableAndConnectedRoutes(t *testing.T) {
	addresses := parseLocalIPv4Addresses([]byte(fibTrie))
	got := matchIPv4Addresses(addresses, parseConnectedRoutes([]byte(routeTable)))

	want := map[string][]netip.Prefix{
		"lo":      {netip.MustParsePrefix("127.0.0.1/8")},
		"docker0": {netip.MustParsePrefix("172.17.0.1/16")},
		"eth0":    {netip.MustParsePrefix("203.0.113.7/24")},
	}
	for name, prefixes := range want {
		if !slices.Equal(got[name], prefixes) {
			t.Errorf("%s addresses = %v, want %v", name, got[name], prefixes)
		}
	}
	if len(got) != len(want) {
		t.Errorf("addresses = %v, want %v", got, want)
	}
}

func TestIPv6AddressesFromIfInet6(t *testing.T) {
	data := "20010db8000000000000000000000001 02 40 00 80     eth0\n" +
		"fe800000000000000000000000000001 02 40 20 80     eth0\n" +
		"broken line\n"

	got := parseIPv6Addresses([]byte(data))["eth0"]
	want := []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64"), netip.MustParsePrefix("fe80::1/64")}
	if !slices.Equal(got, want) {
		t.Fatalf("eth0 addresses = %v, want %v", got, want)
	}
}

func TestLinuxFlags(t *testing.T) {
	flags := linuxFlags(0x1003)
	if flags != net.FlagUp|net.FlagBroadcast|net.FlagMulticast {
		t.Fatalf("flags = %v", flags)
	}
}
