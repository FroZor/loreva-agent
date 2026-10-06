// Package networkinfo collects runtime network and firewall configuration.
package networkinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"

	"github.com/FroZor/loreva-agent/internal/hostnet"
	"github.com/FroZor/loreva-agent/internal/observation"
	"github.com/FroZor/loreva-agent/internal/procfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxInterfaceAddresses  = 64
	maxInterfaces          = 256
	maxListeningPorts      = 4096
	maxNetworkSnapshotJSON = 480 * 1024
)

// Snapshot contains network information and the namespace in which it was observed.
type Snapshot struct {
	ObservationScope string
	Network          protocol.NodeNetwork
}

// Collect returns a bounded best-effort network and firewall snapshot.
func Collect(ctx context.Context) (Snapshot, error) {
	interfaces, interfaceIssues := collectInterfaces()
	listeners, listenerIssues := collectListeningPorts(ctx)
	platform := collectPlatformNetwork(ctx)

	issues := append(interfaceIssues, listenerIssues...)
	issues = append(issues, platform.issues...)

	network := protocol.NodeNetwork{
		Interfaces:       interfaces,
		Routes:           platform.routes,
		ListeningPorts:   listeners,
		Firewall:         platform.firewall,
		CollectionIssues: deduplicateIssues(issues),
	}
	if err := fitNetworkToBudget(&network); err != nil {
		return Snapshot{}, err
	}

	return Snapshot{
		ObservationScope: observation.Detect(ctx).Scope,
		Network:          network,
	}, nil
}

func fitNetworkToBudget(network *protocol.NodeNetwork) error {
	baseIssues := append([]protocol.CollectionIssue(nil), network.CollectionIssues...)
	truncated := make(map[string]struct{})

	for {
		network.CollectionIssues = append([]protocol.CollectionIssue(nil), baseIssues...)
		for component := range truncated {
			network.CollectionIssues = append(network.CollectionIssues, protocol.CollectionIssue{
				Component: component,
				Code:      "truncated",
			})
		}
		network.CollectionIssues = deduplicateIssues(network.CollectionIssues)

		data, err := json.Marshal(network)
		if err != nil {
			return fmt.Errorf("size network snapshot: %w", err)
		}
		if len(data) <= maxNetworkSnapshotJSON {
			break
		}

		switch {
		case len(network.Firewall.Rules) > 0:
			network.Firewall.Rules = network.Firewall.Rules[:len(network.Firewall.Rules)/2]
			network.Firewall.Truncated = true
			truncated["firewall.rules"] = struct{}{}
		case len(network.ListeningPorts) > 0:
			network.ListeningPorts = network.ListeningPorts[:len(network.ListeningPorts)/2]
			truncated["listening_ports"] = struct{}{}
		case len(network.Routes) > 0:
			network.Routes = network.Routes[:len(network.Routes)/2]
			truncated["routes"] = struct{}{}
		case truncateInterfaceAddresses(network.Interfaces):
			truncated["interfaces.addresses"] = struct{}{}
		case len(network.Interfaces) > 0:
			network.Interfaces = network.Interfaces[:len(network.Interfaces)/2]
			truncated["interfaces"] = struct{}{}
		default:
			return fmt.Errorf("network snapshot exceeds %d bytes without optional entries", maxNetworkSnapshotJSON)
		}
	}

	return nil
}

func truncateInterfaceAddresses(interfaces []protocol.NetworkInterfaceConfiguration) bool {
	index := -1
	addressCount := 0
	for candidate := range interfaces {
		if len(interfaces[candidate].Addresses) > addressCount {
			index = candidate
			addressCount = len(interfaces[candidate].Addresses)
		}
	}
	if index < 0 {
		return false
	}

	interfaces[index].Addresses = interfaces[index].Addresses[:addressCount/2]

	return true
}

func collectInterfaces() ([]protocol.NetworkInterfaceConfiguration, []protocol.CollectionIssue) {
	interfaces, err := hostnet.Interfaces()
	if err != nil {
		return nil, []protocol.CollectionIssue{networkIssue("interfaces", err)}
	}

	sort.Slice(interfaces, func(left, right int) bool {
		return interfaces[left].Index < interfaces[right].Index
	})

	issues := make([]protocol.CollectionIssue, 0)
	if len(interfaces) > maxInterfaces {
		interfaces = interfaces[:maxInterfaces]
		issues = append(issues, protocol.CollectionIssue{Component: "interfaces", Code: "truncated"})
	}

	result := make([]protocol.NetworkInterfaceConfiguration, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		addresses := networkInterface.Addresses
		if len(addresses) > maxInterfaceAddresses {
			addresses = addresses[:maxInterfaceAddresses]
			issues = append(issues, protocol.CollectionIssue{Component: "interfaces.addresses", Code: "truncated"})
		}

		normalizedAddresses := make([]protocol.NetworkAddress, 0, len(addresses))
		for _, address := range addresses {
			family := "ipv6"
			if address.Addr().Is4() {
				family = "ipv4"
			}

			normalizedAddresses = append(normalizedAddresses, protocol.NetworkAddress{
				Family:       family,
				Address:      address.Addr().String(),
				PrefixLength: address.Bits(),
			})
		}

		result = append(result, protocol.NetworkInterfaceConfiguration{
			ID:              networkInterface.ID(),
			Name:            sanitizeNetworkValue(networkInterface.Name, 255),
			HardwareAddress: networkInterface.HardwareAddr.String(),
			MTU:             networkInterface.MTU,
			Flags:           interfaceFlags(networkInterface.Flags),
			Addresses:       normalizedAddresses,
		})
	}

	return result, issues
}

func collectListeningPorts(ctx context.Context) ([]protocol.ListeningPort, []protocol.CollectionIssue) {
	connections, err := connectionStats(ctx, maxListeningPorts+1)
	if err != nil {
		return nil, []protocol.CollectionIssue{networkIssue("listening_ports", err)}
	}

	listeners := make([]protocol.ListeningPort, 0)
	seen := make(map[string]struct{})
	truncated := false
	unowned := false

	for _, connection := range connections {
		protocolName, listening := listeningProtocol(connection)
		if !listening || connection.Laddr.Port == 0 {
			continue
		}
		if len(listeners) == maxListeningPorts {
			truncated = true
			break
		}

		address := net.ParseIP(connection.Laddr.IP)
		if address == nil {
			continue
		}

		key := protocolName + "|" + address.String() + "|" + strconv.FormatUint(uint64(connection.Laddr.Port), 10) +
			"|" + strconv.FormatInt(int64(connection.Pid), 10)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		listener := protocol.ListeningPort{
			Protocol:  protocolName,
			Address:   address.String(),
			Port:      uint16(connection.Laddr.Port),
			ProcessID: connection.Pid,
		}
		if connection.Pid > 0 {
			listener.ProcessName = sanitizeNetworkValue(procfs.Name(connection.Pid), 64)
		} else {
			unowned = true
		}
		listeners = append(listeners, listener)
	}

	sort.Slice(listeners, func(left, right int) bool {
		if listeners[left].Port != listeners[right].Port {
			return listeners[left].Port < listeners[right].Port
		}
		if listeners[left].Protocol != listeners[right].Protocol {
			return listeners[left].Protocol < listeners[right].Protocol
		}
		return listeners[left].Address < listeners[right].Address
	})

	var issues []protocol.CollectionIssue
	if truncated {
		issues = append(issues, protocol.CollectionIssue{Component: "listening_ports", Code: "truncated"})
	}
	if unowned {
		// Owners are found through other processes' file tables, which
		// need root or CAP_SYS_PTRACE.
		issues = append(issues, protocol.CollectionIssue{Component: "listening_ports.process", Code: "partial"})
	}

	return listeners, issues
}

func listeningProtocol(connection gopsutilnet.ConnectionStat) (string, bool) {
	switch connection.Type {
	case syscall.SOCK_STREAM:
		return "tcp", strings.EqualFold(connection.Status, "LISTEN")
	case syscall.SOCK_DGRAM:
		return "udp", connection.Raddr.IP == "" && connection.Raddr.Port == 0
	default:
		return "", false
	}
}

func interfaceFlags(flags net.Flags) []string {
	result := make([]string, 0, 5)
	if flags&net.FlagUp != 0 {
		result = append(result, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		result = append(result, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		result = append(result, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		result = append(result, "point_to_point")
	}
	if flags&net.FlagMulticast != 0 {
		result = append(result, "multicast")
	}

	return result
}

func networkIssue(component string, err error) protocol.CollectionIssue {
	code := "collection_failed"
	if errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
	} else if errors.Is(err, os.ErrPermission) {
		code = "permission_denied"
	} else if errors.Is(err, os.ErrNotExist) {
		code = "not_available"
	}

	return protocol.CollectionIssue{Component: component, Code: code}
}

func deduplicateIssues(issues []protocol.CollectionIssue) []protocol.CollectionIssue {
	seen := make(map[protocol.CollectionIssue]struct{}, len(issues))
	result := make([]protocol.CollectionIssue, 0, len(issues))
	for _, issue := range issues {
		if issue.Component == "" || issue.Code == "" {
			continue
		}
		if _, exists := seen[issue]; exists {
			continue
		}

		seen[issue] = struct{}{}
		result = append(result, issue)
	}

	sort.Slice(result, func(left, right int) bool {
		if result[left].Component == result[right].Component {
			return result[left].Code < result[right].Code
		}
		return result[left].Component < result[right].Component
	})

	return result
}

func sanitizeNetworkValue(value string, limit int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	if len(value) > limit {
		for limit > 0 && !utf8.RuneStart(value[limit]) {
			limit--
		}
		value = value[:limit]
	}

	return value
}
