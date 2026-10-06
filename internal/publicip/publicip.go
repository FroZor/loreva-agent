// Package publicip finds the addresses under which a node is reachable from
// the internet. Addresses on the node's own interfaces come first; a cloud
// provider's metadata service answers next; otherwise the node asks several
// public "what is my IP" services run by different operators and accepts an
// address only when at least two of them agree.
package publicip

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/hostfs"
)

// Sources of a public address.
const (
	SourceInterface     = "interface"
	SourceConfigured    = "configured"
	SourceCloudMetadata = "cloud_metadata"
	SourceExternal      = "external"
)

const (
	// cacheLifetime bounds how often the node asks outside services; the
	// network report is collected once per session and on refresh.
	cacheLifetime = 30 * time.Minute
	lookupTimeout = 5 * time.Second
	// minAgreement is how many independent operators must report the same
	// address before it is believed.
	minAgreement = 2
)

// Address is one public address and how it was found. BehindNAT is set when
// the address is not assigned to any interface of the node.
type Address struct {
	Addr      netip.Addr
	Source    string
	BehindNAT bool
}

// Issue explains why a family could not be resolved.
type Issue struct {
	Component string
	Code      string
}

// Settings are read from the environment of the agent.
type Settings struct {
	// Configured addresses replace every lookup (LOREVA_PUBLIC_IP).
	Configured []netip.Addr
	// LookupDisabled turns off metadata and outside lookups
	// (LOREVA_PUBLIC_IP_LOOKUP=off).
	LookupDisabled bool
}

// SettingsFromEnvironment reads LOREVA_PUBLIC_IP, a comma-separated list of
// addresses, and LOREVA_PUBLIC_IP_LOOKUP.
func SettingsFromEnvironment() Settings {
	var settings Settings
	for value := range strings.SplitSeq(os.Getenv("LOREVA_PUBLIC_IP"), ",") {
		if address, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil && Public(address.Unmap()) {
			settings.Configured = append(settings.Configured, address.Unmap())
		}
	}
	settings.LookupDisabled = strings.EqualFold(strings.TrimSpace(os.Getenv("LOREVA_PUBLIC_IP_LOOKUP")), "off")

	return settings
}

// Resolver finds and caches public addresses.
type Resolver struct {
	settings Settings
	metadata func(ctx context.Context, family string) (netip.Addr, bool)
	external func(ctx context.Context, family string) (netip.Addr, string)
	now      func() time.Time

	mu     sync.Mutex
	cached map[string]lookup
}

type lookup struct {
	address   netip.Addr
	source    string
	issue     string
	checkedAt time.Time
}

// NewResolver returns a resolver for this node. The cloud provider, if any,
// is identified by the SMBIOS system vendor and product name.
func NewResolver(settings Settings) *Resolver {
	vendor, _ := os.ReadFile(hostfs.Sys("class/dmi/id/sys_vendor"))
	product, _ := os.ReadFile(hostfs.Sys("class/dmi/id/product_name"))

	return &Resolver{
		settings: settings,
		metadata: cloudMetadata(strings.TrimSpace(string(vendor)), strings.TrimSpace(string(product))),
		external: externalConsensus(defaultServices),
		now:      time.Now,
		cached:   make(map[string]lookup, 2),
	}
}

// Addresses returns the public addresses of the node. local are the
// addresses of its interfaces.
func (r *Resolver) Addresses(ctx context.Context, local []netip.Addr) ([]Address, []Issue) {
	var addresses []Address
	for _, address := range local {
		if Public(address) && !containsAddress(addresses, address) {
			addresses = append(addresses, Address{Addr: address, Source: SourceInterface})
		}
	}
	if len(r.settings.Configured) > 0 {
		for _, address := range r.settings.Configured {
			if !containsAddress(addresses, address) {
				addresses = append(addresses, Address{Addr: address, Source: SourceConfigured, BehindNAT: !slices.Contains(local, address)})
			}
		}
		return addresses, nil
	}
	if r.settings.LookupDisabled {
		return addresses, nil
	}

	// A family with a public address on an interface needs no lookup, so
	// most servers never ask anyone outside.
	var missing []string
	for _, family := range []string{"ipv4", "ipv6"} {
		if !slices.ContainsFunc(addresses, func(item Address) bool { return item.Addr.Is4() == (family == "ipv4") }) {
			missing = append(missing, family)
		}
	}

	var issues []Issue
	for family, result := range r.lookups(ctx, missing) {
		if result.issue != "" {
			issues = append(issues, Issue{Component: "public_addresses." + family, Code: result.issue})
			continue
		}
		if !containsAddress(addresses, result.address) {
			addresses = append(addresses, Address{Addr: result.address, Source: result.source, BehindNAT: !slices.Contains(local, result.address)})
		}
	}
	slices.SortFunc(addresses, func(left, right Address) int { return left.Addr.Compare(right.Addr) })
	slices.SortFunc(issues, func(left, right Issue) int { return strings.Compare(left.Component, right.Component) })

	return addresses, issues
}

// lookups resolves each family at most once per cache lifetime.
func (r *Resolver) lookups(ctx context.Context, families []string) map[string]lookup {
	r.mu.Lock()
	defer r.mu.Unlock()

	results := make(map[string]lookup, len(families))
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, family := range families {
		if cached, exists := r.cached[family]; exists && r.now().Sub(cached.checkedAt) < cacheLifetime {
			results[family] = cached
			continue
		}
		wait.Go(func() {
			result := r.lookupFamily(ctx, family)
			result.checkedAt = r.now()
			mu.Lock()
			results[family] = result
			mu.Unlock()
		})
	}
	wait.Wait()

	for family, result := range results {
		r.cached[family] = result
	}

	return results
}

func (r *Resolver) lookupFamily(ctx context.Context, family string) lookup {
	ctx, cancel := context.WithTimeout(ctx, 2*lookupTimeout)
	defer cancel()

	if r.metadata != nil {
		if address, ok := r.metadata(ctx, family); ok {
			return lookup{address: address, source: SourceCloudMetadata}
		}
	}
	address, issue := r.external(ctx, family)
	if issue != "" {
		return lookup{issue: issue}
	}

	return lookup{address: address, source: SourceExternal}
}

func containsAddress(addresses []Address, address netip.Addr) bool {
	return slices.ContainsFunc(addresses, func(item Address) bool { return item.Addr == address })
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT, RFC 6598
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation, RFC 5737
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking, RFC 2544
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64, RFC 8215
	netip.MustParsePrefix("2001:db8::/32"),   // documentation, RFC 3849
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2002::/16"),       // 6to4
}

// Public reports a globally routable unicast address. Go's IsGlobalUnicast
// also accepts private and unique-local ranges, so those are excluded here,
// along with shared and documentation ranges.
func Public(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(address) {
			return false
		}
	}

	return true
}
