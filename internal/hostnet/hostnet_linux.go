//go:build linux

package hostnet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	mathbits "math/bits"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
)

const maxProcNetFile = 4 * 1024 * 1024

// NetPath returns a /proc/net file of the host's network namespace: the one
// of PID 1, which is the host's init when the agent runs on the host or
// shares its process namespace. /proc/net would describe the agent's own
// namespace, which in a container holds only the container's network.
func NetPath(name string) string {
	path := hostfs.Proc("1", "net", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return hostfs.Proc("net", name)
}

// Interfaces lists the host's interfaces. Outside a container, or in one
// that shares the host's network, it is the standard library's view.
func Interfaces() ([]Interface, error) {
	if !hostfs.Containerized() || sameNamespace() {
		return standardInterfaces()
	}

	return hostInterfaces()
}

// sameNamespace compares the interface names of the agent's namespace with
// the host's; reading the namespace links themselves needs CAP_SYS_PTRACE.
func sameNamespace() bool {
	own, err := deviceNames("/proc/self/net/dev")
	if err != nil {
		return true
	}
	host, err := deviceNames(NetPath("dev"))
	if err != nil {
		return true
	}

	return slices.Equal(own, host)
}

func deviceNames(path string) ([]string, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for line := range strings.SplitSeq(string(data), "\n") {
		name, _, found := strings.Cut(line, ":")
		if found {
			names = append(names, strings.TrimSpace(name))
		}
	}
	slices.Sort(names)

	return names, nil
}

// hostInterfaces reads interfaces from the host's sysfs, IPv6 addresses
// from if_inet6, and IPv4 addresses from the local routing table, whose
// prefixes come from the connected routes of the main table.
func hostInterfaces() ([]Interface, error) {
	entries, err := os.ReadDir(hostfs.Sys("class", "net"))
	if err != nil {
		return nil, err
	}

	byName := make(map[string]int, len(entries))
	interfaces := make([]Interface, 0, len(entries))
	for _, entry := range entries {
		directory := hostfs.Sys("class", "net", entry.Name())
		index, err := readInt(directory + "/ifindex")
		if err != nil {
			continue
		}
		mtu, _ := readInt(directory + "/mtu")
		flags, _ := readHex(directory + "/flags")
		address, _ := readTrimmed(directory + "/address")
		hardware, _ := net.ParseMAC(address)
		if len(hardware) == 0 || bytes.Equal(hardware, make(net.HardwareAddr, len(hardware))) {
			hardware = nil
		}

		byName[entry.Name()] = len(interfaces)
		interfaces = append(interfaces, Interface{
			Index:        index,
			Name:         entry.Name(),
			HardwareAddr: hardware,
			MTU:          mtu,
			Flags:        linuxFlags(flags),
		})
	}

	for name, prefix := range ipv6Addresses() {
		if position, exists := byName[name]; exists {
			interfaces[position].Addresses = append(interfaces[position].Addresses, prefix...)
		}
	}
	for name, prefix := range ipv4Addresses() {
		if position, exists := byName[name]; exists {
			interfaces[position].Addresses = append(interfaces[position].Addresses, prefix...)
		}
	}
	slices.SortFunc(interfaces, func(left, right Interface) int { return left.Index - right.Index })

	return interfaces, nil
}

// linuxFlags converts IFF_* bits from sysfs into net.Flags.
func linuxFlags(value uint64) net.Flags {
	var flags net.Flags
	for bit, flag := range map[uint64]net.Flags{
		0x1:    net.FlagUp,
		0x2:    net.FlagBroadcast,
		0x8:    net.FlagLoopback,
		0x10:   net.FlagPointToPoint,
		0x40:   net.FlagRunning,
		0x1000: net.FlagMulticast,
	} {
		if value&bit != 0 {
			flags |= flag
		}
	}

	return flags
}

// ipv6Addresses parses if_inet6: address, index, prefix length, scope,
// flags, and the interface name.
func ipv6Addresses() map[string][]netip.Prefix {
	data, _ := readBounded(NetPath("if_inet6"))

	return parseIPv6Addresses(data)
}

func parseIPv6Addresses(data []byte) map[string][]netip.Prefix {
	result := make(map[string][]netip.Prefix)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != 16 {
			continue
		}
		bits, err := strconv.ParseUint(fields[2], 16, 8)
		if err != nil || bits > 128 {
			continue
		}
		result[fields[5]] = append(result[fields[5]], netip.PrefixFrom(netip.AddrFrom16([16]byte(raw)), int(bits)))
	}

	return result
}

type connectedRoute struct {
	name   string
	prefix netip.Prefix
}

// ipv4Addresses pairs the host addresses of the local table in fib_trie
// with the most specific connected route that contains them.
func ipv4Addresses() map[string][]netip.Prefix {
	routes, _ := readBounded(NetPath("route"))
	trie, _ := readBounded(NetPath("fib_trie"))

	return matchIPv4Addresses(parseLocalIPv4Addresses(trie), parseConnectedRoutes(routes))
}

func matchIPv4Addresses(addresses []netip.Addr, routes []connectedRoute) map[string][]netip.Prefix {
	result := make(map[string][]netip.Prefix)
	for _, address := range addresses {
		best := -1
		for index, route := range routes {
			if route.prefix.Contains(address) && (best < 0 || route.prefix.Bits() > routes[best].prefix.Bits()) {
				best = index
			}
		}
		switch {
		case best >= 0:
			result[routes[best].name] = append(result[routes[best].name], netip.PrefixFrom(address, routes[best].prefix.Bits()))
		case address.IsLoopback():
			result["lo"] = append(result["lo"], netip.PrefixFrom(address, 8))
		}
	}

	return result
}

// connectedRoutes reads main-table routes without a gateway from
// /proc/net/route, whose addresses and masks are little-endian hex.
func parseConnectedRoutes(data []byte) []connectedRoute {
	var routes []connectedRoute
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "Iface" {
			continue
		}
		destination, okDestination := littleEndianIPv4(fields[1])
		gateway, okGateway := littleEndianIPv4(fields[2])
		mask, okMask := littleEndianIPv4(fields[7])
		if !okDestination || !okGateway || !okMask || !gateway.IsUnspecified() {
			continue
		}
		bits := 0
		for _, octet := range mask.As4() {
			bits += mathbits.OnesCount8(octet)
		}
		if bits == 0 {
			continue
		}
		routes = append(routes, connectedRoute{name: fields[0], prefix: netip.PrefixFrom(destination, bits)})
	}

	return routes
}

// localIPv4Addresses returns the "/32 host LOCAL" entries of fib_trie's
// local table, which are the addresses assigned to interfaces.
func parseLocalIPv4Addresses(data []byte) []netip.Addr {
	var addresses []netip.Addr
	seen := make(map[netip.Addr]struct{})
	var last netip.Addr
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if value, found := strings.CutPrefix(line, "|-- "); found {
			last, _ = netip.ParseAddr(value)
			continue
		}
		if line == "/32 host LOCAL" && last.Is4() {
			if _, duplicate := seen[last]; !duplicate {
				seen[last] = struct{}{}
				addresses = append(addresses, last)
			}
		}
	}

	return addresses
}

func littleEndianIPv4(value string) (netip.Addr, bool) {
	number, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	var octets [4]byte
	binary.LittleEndian.PutUint32(octets[:], uint32(number))

	return netip.AddrFrom4(octets), true
}

func readInt(path string) (int, error) {
	value, err := readTrimmed(path)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(value)
}

func readHex(path string) (uint64, error) {
	value, err := readTrimmed(path)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 64)
}

func readTrimmed(path string) (string, error) {
	data, err := readBounded(path)

	return strings.TrimSpace(string(data)), err
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(io.LimitReader(file, maxProcNetFile))
}
