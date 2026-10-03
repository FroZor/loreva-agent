package direct

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

const maxInviteEndpoints = 16

// inviteEndpoints lists the outer addresses a device may try, in order:
// endpoints given for this invite, endpoints saved by init, and then the
// unicast addresses of the host's interfaces.
func inviteEndpoints(requested, configured []string, port int) ([]netip.AddrPort, error) {
	var endpoints []netip.AddrPort

	for _, value := range slices.Concat(requested, configured) {
		endpoint, err := parseAdvertisedEndpoint(value, port)
		if err != nil {
			return nil, err
		}

		endpoints = appendEndpoint(endpoints, endpoint)
	}

	for _, address := range interfaceAddresses() {
		endpoints = appendEndpoint(endpoints, netip.AddrPortFrom(address, uint16(port)))
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no usable address found; pass --endpoint with the node's public IP")
	}
	if len(endpoints) > maxInviteEndpoints {
		endpoints = endpoints[:maxInviteEndpoints]
	}

	return endpoints, nil
}

func appendEndpoint(endpoints []netip.AddrPort, endpoint netip.AddrPort) []netip.AddrPort {
	if slices.Contains(endpoints, endpoint) {
		return endpoints
	}

	return append(endpoints, endpoint)
}

// interfaceAddresses returns global unicast interface addresses, IPv4 first.
// Errors are ignored because detection is only a convenience.
func interfaceAddresses() []netip.Addr {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	var result []netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}

		ip := prefix.Addr().Unmap()
		if ip.Zone() == "" && ip.IsGlobalUnicast() {
			result = append(result, ip)
		}
	}

	slices.SortStableFunc(result, func(a, b netip.Addr) int {
		if a.Is4() == b.Is4() {
			return 0
		}
		if a.Is4() {
			return -1
		}

		return 1
	})

	return result
}
