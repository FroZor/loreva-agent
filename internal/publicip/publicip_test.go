package publicip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestPublic(t *testing.T) {
	for value, want := range map[string]bool{
		"8.8.8.8":         true,
		"2a01:4f8::1":     true,
		"10.0.0.1":        false,
		"172.16.5.4":      false,
		"192.168.1.1":     false,
		"100.64.0.1":      false,
		"127.0.0.1":       false,
		"169.254.1.1":     false,
		"203.0.113.9":     false,
		"fd00::1":         false,
		"fe80::1":         false,
		"2001:db8::1":     false,
		"::ffff:10.0.0.1": false,
	} {
		if got := Public(netip.MustParseAddr(value)); got != want {
			t.Errorf("Public(%s) = %v, want %v", value, got, want)
		}
	}
}

func TestElectNeedsTwoOperators(t *testing.T) {
	first, second := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")
	set := func(operators ...string) map[string]struct{} {
		result := make(map[string]struct{})
		for _, operator := range operators {
			result[operator] = struct{}{}
		}
		return result
	}

	cases := []struct {
		name    string
		votes   map[netip.Addr]map[string]struct{}
		address netip.Addr
		issue   string
	}{
		{"none", nil, netip.Addr{}, "not_available"},
		{"one operator", map[netip.Addr]map[string]struct{}{first: set("a")}, netip.Addr{}, "unconfirmed"},
		{"disagreement", map[netip.Addr]map[string]struct{}{first: set("a"), second: set("b")}, netip.Addr{}, "inconsistent"},
		{"agreement", map[netip.Addr]map[string]struct{}{first: set("a", "b"), second: set("c")}, first, ""},
		{"tie", map[netip.Addr]map[string]struct{}{first: set("a", "b"), second: set("c", "d")}, netip.Addr{}, "inconsistent"},
	}
	for _, test := range cases {
		address, issue := elect(test.votes)
		if address != test.address || issue != test.issue {
			t.Errorf("%s: elect = %v %q, want %v %q", test.name, address, issue, test.address, test.issue)
		}
	}
}

func TestAddressesSkipsLookupForFamiliesOnInterfaces(t *testing.T) {
	asked := map[string]int{}
	resolver := &Resolver{
		external: func(_ context.Context, family string) (netip.Addr, string) {
			asked[family]++
			return netip.MustParseAddr("2a01:4f8::7"), ""
		},
		now:    time.Now,
		cached: map[string]lookup{},
	}
	local := []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("8.8.4.4")}

	addresses, issues := resolver.Addresses(context.Background(), local)
	if len(issues) != 0 || asked["ipv4"] != 0 || asked["ipv6"] != 1 {
		t.Fatalf("asked = %v, issues = %v", asked, issues)
	}
	want := []Address{
		{Addr: netip.MustParseAddr("8.8.4.4"), Source: SourceInterface},
		{Addr: netip.MustParseAddr("2a01:4f8::7"), Source: SourceExternal, BehindNAT: true},
	}
	if len(addresses) != len(want) || addresses[0] != want[0] || addresses[1] != want[1] {
		t.Fatalf("addresses = %+v, want %+v", addresses, want)
	}

	resolver.Addresses(context.Background(), local)
	if asked["ipv6"] != 1 {
		t.Fatalf("cached lookup was repeated: %v", asked)
	}
}

func TestConfiguredAddressesReplaceLookups(t *testing.T) {
	resolver := &Resolver{
		settings: Settings{Configured: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		external: func(context.Context, string) (netip.Addr, string) {
			t.Fatal("configured addresses must not be looked up")
			return netip.Addr{}, ""
		},
		now:    time.Now,
		cached: map[string]lookup{},
	}

	addresses, _ := resolver.Addresses(context.Background(), nil)
	if len(addresses) != 1 || addresses[0].Source != SourceConfigured || !addresses[0].BehindNAT {
		t.Fatalf("addresses = %+v", addresses)
	}
}

func TestReadAddressBoundsAndRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ok":
			_, _ = writer.Write([]byte("8.8.8.8\n"))
		case "/long":
			_, _ = writer.Write(make([]byte, 100))
		case "/redirect":
			http.Redirect(writer, request, "/ok", http.StatusFound)
		}
	}))
	defer server.Close()

	client := newClient("tcp4")
	if address, err := ask(context.Background(), client, server.URL+"/ok"); err != nil || address != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("ok = %v, %v", address, err)
	}
	for _, path := range []string{"/long", "/redirect"} {
		if _, err := ask(context.Background(), client, server.URL+path); err == nil {
			t.Errorf("%s was accepted", path)
		}
	}
}
