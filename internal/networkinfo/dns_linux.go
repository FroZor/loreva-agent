//go:build linux

package networkinfo

import (
	"net/netip"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxResolvConf  = 64 * 1024
	maxNameservers = 16
	maxSearch      = 16
)

// collectDNS reads the host's resolv.conf. When it points at the local
// stub of systemd-resolved, the servers the stub forwards to are read from
// the file systemd-resolved maintains for that purpose.
func collectDNS() (*protocol.DNSConfiguration, []protocol.CollectionIssue) {
	data, err := readNetworkFile(hostfs.Etc("resolv.conf"), maxResolvConf)
	if err != nil {
		return nil, []protocol.CollectionIssue{networkIssue("dns", err)}
	}

	dns := parseResolvConf(string(data))
	if len(dns.Nameservers) == 1 && dns.Nameservers[0] == "127.0.0.53" {
		dns.Resolver = "systemd-resolved"
		if upstream, err := readNetworkFile(hostfs.Root("/run/systemd/resolve/resolv.conf"), maxResolvConf); err == nil {
			dns.Upstream = parseResolvConf(string(upstream)).Nameservers
		}
	}

	return dns, nil
}

func parseResolvConf(content string) *protocol.DNSConfiguration {
	dns := &protocol.DNSConfiguration{Nameservers: []string{}, SearchDomains: []string{}}
	for line := range strings.SplitSeq(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if address, err := netip.ParseAddr(fields[1]); err == nil && len(dns.Nameservers) < maxNameservers {
				dns.Nameservers = append(dns.Nameservers, address.String())
			}
		case "search", "domain":
			// The last search or domain line wins, as in resolv.conf(5).
			dns.SearchDomains = dns.SearchDomains[:0]
			for _, domain := range fields[1:] {
				if len(dns.SearchDomains) < maxSearch {
					dns.SearchDomains = append(dns.SearchDomains, sanitizeNetworkValue(domain, 253))
				}
			}
		}
	}

	return dns
}
