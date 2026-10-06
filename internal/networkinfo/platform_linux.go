//go:build linux

package networkinfo

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/hostnet"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxFirewallOutput = 4 * 1024 * 1024
	maxFirewallRules  = 4096
	maxRouteFileSize  = 1024 * 1024
	maxRoutes         = 4096
)

func collectPlatformNetwork(ctx context.Context) platformNetwork {
	routes, routeIssues := collectLinuxRoutes()
	firewall, firewallIssues := collectLinuxFirewall(ctx)
	if ufw, err := ufwConfiguration(); ufw != nil || !errors.Is(err, fs.ErrNotExist) {
		firewall.UFW = ufw
		if err != nil {
			firewallIssues = append(firewallIssues, networkIssue("firewall.ufw", err))
		}
	}
	if firewalld, err := firewalldConfiguration(); firewalld != nil || !errors.Is(err, fs.ErrNotExist) {
		firewall.Firewalld = firewalld
		if err != nil {
			firewallIssues = append(firewallIssues, networkIssue("firewall.firewalld", err))
		}
	}
	dns, dnsIssues := collectDNS()

	issues := append(routeIssues, firewallIssues...)
	return platformNetwork{
		routes:   routes,
		firewall: firewall,
		dns:      dns,
		issues:   append(issues, dnsIssues...),
	}
}

func collectLinuxRoutes() ([]protocol.NetworkRoute, []protocol.CollectionIssue) {
	interfaces, err := hostnet.Interfaces()
	if err != nil {
		return nil, []protocol.CollectionIssue{networkIssue("routes", err)}
	}

	interfaceIDs := make(map[string]string, len(interfaces))
	for _, networkInterface := range interfaces {
		interfaceIDs[networkInterface.Name] = networkInterface.ID()
	}

	routes := make([]protocol.NetworkRoute, 0)
	issues := make([]protocol.CollectionIssue, 0, 2)

	ipv4Routes, err := parseIPv4Routes(hostnet.NetPath("route"), interfaceIDs)
	if err != nil {
		issues = append(issues, networkIssue("routes.ipv4", err))
	} else {
		routes = append(routes, ipv4Routes...)
	}

	ipv6Routes, err := parseIPv6Routes(hostnet.NetPath("ipv6_route"), interfaceIDs)
	if err != nil {
		issues = append(issues, networkIssue("routes.ipv6", err))
	} else {
		routes = append(routes, ipv6Routes...)
	}

	if len(routes) > maxRoutes {
		routes = routes[:maxRoutes]
		issues = append(issues, protocol.CollectionIssue{Component: "routes", Code: "truncated"})
	}

	return routes, issues
}

func parseIPv4Routes(path string, interfaceIDs map[string]string) ([]protocol.NetworkRoute, error) {
	data, err := readNetworkFile(path, maxRouteFileSize)
	if err != nil {
		return nil, err
	}

	routes := make([]protocol.NetworkRoute, 0)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}

		destination, err := parseIPv4LittleEndian(fields[1])
		if err != nil {
			continue
		}
		gateway, err := parseIPv4LittleEndian(fields[2])
		if err != nil {
			continue
		}
		mask, err := parseIPv4LittleEndian(fields[7])
		if err != nil {
			continue
		}
		prefixLength, bits := net.IPMask(mask).Size()
		if bits != 32 {
			continue
		}

		metric, _ := strconv.ParseUint(fields[6], 10, 64)
		route := protocol.NetworkRoute{
			Family:      "ipv4",
			Destination: (&net.IPNet{IP: destination.Mask(net.CIDRMask(prefixLength, 32)), Mask: net.CIDRMask(prefixLength, 32)}).String(),
			InterfaceID: interfaceIDs[fields[0]],
			Metric:      metric,
		}
		if !gateway.Equal(net.IPv4zero) {
			route.Gateway = gateway.String()
		}

		routes = append(routes, route)
	}

	return routes, nil
}

func parseIPv6Routes(path string, interfaceIDs map[string]string) ([]protocol.NetworkRoute, error) {
	data, err := readNetworkFile(path, maxRouteFileSize)
	if err != nil {
		return nil, err
	}

	routes := make([]protocol.NetworkRoute, 0)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		destinationBytes, err := hex.DecodeString(fields[0])
		if err != nil || len(destinationBytes) != net.IPv6len {
			continue
		}
		prefixLength, err := strconv.ParseUint(fields[1], 16, 8)
		if err != nil || prefixLength > 128 {
			continue
		}
		gatewayBytes, err := hex.DecodeString(fields[4])
		if err != nil || len(gatewayBytes) != net.IPv6len {
			continue
		}

		metric, _ := strconv.ParseUint(fields[5], 16, 64)
		mask := net.CIDRMask(int(prefixLength), 128)
		destination := net.IP(destinationBytes)
		gateway := net.IP(gatewayBytes)
		route := protocol.NetworkRoute{
			Family:      "ipv6",
			Destination: (&net.IPNet{IP: destination.Mask(mask), Mask: mask}).String(),
			InterfaceID: interfaceIDs[fields[9]],
			Metric:      metric,
		}
		if !gateway.Equal(net.IPv6zero) {
			route.Gateway = gateway.String()
		}

		routes = append(routes, route)
	}

	return routes, nil
}

func collectLinuxFirewall(ctx context.Context) (protocol.FirewallInformation, []protocol.CollectionIssue) {
	providers := detectLinuxFirewallProviders()
	if !hostnet.SameNamespace() {
		// nft and iptables would list the rules of the agent's own
		// container network, not the host's.
		status := "inactive"
		if len(providers) > 0 {
			status = "partial"
		}
		return protocol.FirewallInformation{
			Status:    status,
			Providers: providers,
			Rules:     []protocol.FirewallRule{},
		}, []protocol.CollectionIssue{{Component: "firewall.rules", Code: "other_namespace"}}
	}
	issues := make([]protocol.CollectionIssue, 0)
	rules := make([]protocol.FirewallRule, 0)
	truncated := false
	collected := false

	if nftPath := trustedExecutable(
		"/usr/sbin/nft",
		"/sbin/nft",
		"/usr/bin/nft",
	); nftPath != "" {
		nftRules, nftTruncated, err := collectNFTRules(ctx, nftPath)
		if err == nil {
			providers = upsertProvider(providers, protocol.FirewallProvider{
				Name: "nftables", Role: "filter", Status: "active",
			})
			rules = append(rules, nftRules...)
			truncated = nftTruncated
			collected = true
		} else {
			issues = append(issues, networkIssue("firewall.nftables.rules", err))
		}
	}

	iptablesRules, iptablesProviders, iptablesTruncated, iptablesIssues := collectIPTablesRules(ctx)
	providers = mergeProviders(providers, iptablesProviders)
	issues = append(issues, iptablesIssues...)
	if len(iptablesProviders) > 0 {
		remaining := maxFirewallRules - len(rules)
		if remaining > 0 {
			if len(iptablesRules) > remaining {
				iptablesRules = iptablesRules[:remaining]
				truncated = true
			}
			rules = append(rules, iptablesRules...)
		} else if len(iptablesRules) > 0 {
			truncated = true
		}
		truncated = truncated || iptablesTruncated
		collected = true
	}

	if collected {
		status := "active"
		if len(issues) > 0 {
			status = "partial"
		}

		return protocol.FirewallInformation{
			Status:    status,
			Providers: providers,
			Rules:     rules,
			Truncated: truncated,
		}, deduplicateIssues(issues)
	}

	if len(providers) == 0 {
		return protocol.FirewallInformation{
			Status:    "inactive",
			Providers: []protocol.FirewallProvider{},
			Rules:     []protocol.FirewallRule{},
		}, issues
	}

	issues = append(issues, protocol.CollectionIssue{Component: "firewall.rules", Code: "not_available"})
	return protocol.FirewallInformation{
		Status:    "partial",
		Providers: providers,
		Rules:     []protocol.FirewallRule{},
	}, issues
}

func detectLinuxFirewallProviders() []protocol.FirewallProvider {
	providers := make([]protocol.FirewallProvider, 0, 4)
	modules, _ := readNetworkFile(hostfs.Proc("modules"), maxRouteFileSize)
	moduleText := string(modules)
	if strings.Contains(moduleText, "nf_tables ") {
		providers = append(providers, protocol.FirewallProvider{Name: "nftables", Role: "filter", Status: "detected"})
	}
	if strings.Contains(moduleText, "ip_tables ") || strings.Contains(moduleText, "ip6_tables ") {
		providers = append(providers, protocol.FirewallProvider{Name: "iptables", Role: "filter", Status: "detected"})
	}

	if fileExists(hostfs.Root("/run/firewalld/firewalld.pid")) || fileExists(hostfs.Root("/var/run/firewalld/firewalld.pid")) {
		providers = append(providers, protocol.FirewallProvider{
			Name: "firewalld", Role: "manager", Status: "active", Backend: detectedFilterBackend(providers),
		})
	}
	if configuration, err := readNetworkFile(hostfs.Root("/etc/ufw/ufw.conf"), 64*1024); err == nil {
		status := "inactive"
		if strings.Contains(strings.ToUpper(string(configuration)), "ENABLED=YES") {
			status = "active"
		}
		providers = append(providers, protocol.FirewallProvider{
			Name: "ufw", Role: "manager", Status: status, Backend: detectedFilterBackend(providers),
		})
	}

	return providers
}

func collectNFTRules(ctx context.Context, executable string) ([]protocol.FirewallRule, bool, error) {
	output, err := runBoundedCommand(ctx, executable, []string{"-j", "list", "ruleset"}, maxFirewallOutput)
	if err != nil {
		return nil, false, err
	}

	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, false, fmt.Errorf("decode nftables rules: %w", err)
	}

	rules := make([]protocol.FirewallRule, 0)
	truncated := false
	for _, object := range document.NFTables {
		rawRule, exists := object["rule"]
		if !exists {
			continue
		}
		if len(rules) == maxFirewallRules {
			truncated = true
			break
		}

		rule, include := normalizeNFTRule(rawRule)
		if include {
			rules = append(rules, rule)
		}
	}

	return rules, truncated, nil
}

func normalizeNFTRule(data json.RawMessage) (protocol.FirewallRule, bool) {
	var source struct {
		Family string                       `json:"family"`
		Table  string                       `json:"table"`
		Chain  string                       `json:"chain"`
		Handle int64                        `json:"handle"`
		Expr   []map[string]json.RawMessage `json:"expr"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		return protocol.FirewallRule{}, false
	}

	rule := protocol.FirewallRule{
		ID:               fmt.Sprintf("nft:%s:%s:%s:%d", source.Family, source.Table, source.Chain, source.Handle),
		Provider:         "nftables",
		Family:           normalizeFamily(source.Family),
		Table:            sanitizeNetworkValue(source.Table, 128),
		Chain:            sanitizeNetworkValue(source.Chain, 128),
		Direction:        chainDirection(source.Chain),
		Protocol:         "any",
		Enabled:          true,
		Partial:          true,
		SourceCIDRs:      []string{},
		DestinationCIDRs: []string{},
		SourcePorts:      []protocol.PortRange{},
		DestinationPorts: []protocol.PortRange{},
		Interfaces:       []string{},
	}

	for _, expression := range source.Expr {
		for _, action := range []string{"accept", "drop", "reject"} {
			if _, exists := expression[action]; exists {
				rule.Action = normalizeAction(action)
			}
		}

		rawMatch, exists := expression["match"]
		if !exists {
			continue
		}

		var match struct {
			Left struct {
				Payload *struct {
					Protocol string `json:"protocol"`
					Field    string `json:"field"`
				} `json:"payload"`
			} `json:"left"`
			Right json.RawMessage `json:"right"`
			Op    string          `json:"op"`
		}
		if json.Unmarshal(rawMatch, &match) != nil || match.Left.Payload == nil {
			continue
		}
		if match.Op != "==" {
			continue
		}

		field := match.Left.Payload.Field
		if field != "sport" && field != "dport" {
			continue
		}
		rule.Protocol = normalizeProtocol(match.Left.Payload.Protocol)
		ports := parseNFTPorts(match.Right)
		if field == "sport" {
			rule.SourcePorts = ports
		} else {
			rule.DestinationPorts = ports
		}
	}

	if rule.Action == "" {
		return protocol.FirewallRule{}, false
	}

	return rule, true
}

func parseNFTPorts(data json.RawMessage) []protocol.PortRange {
	var single uint16
	if json.Unmarshal(data, &single) == nil && single > 0 {
		return []protocol.PortRange{{From: single, To: single}}
	}

	var value struct {
		Range []uint16 `json:"range"`
	}
	if json.Unmarshal(data, &value) == nil && len(value.Range) == 2 && value.Range[0] > 0 && value.Range[0] <= value.Range[1] {
		return []protocol.PortRange{{From: value.Range[0], To: value.Range[1]}}
	}

	var values []uint16
	if json.Unmarshal(data, &values) == nil {
		ports := make([]protocol.PortRange, 0, len(values))
		for _, port := range values {
			if port > 0 {
				ports = append(ports, protocol.PortRange{From: port, To: port})
			}
		}
		return ports
	}

	return nil
}

func collectIPTablesRules(ctx context.Context) (
	[]protocol.FirewallRule,
	[]protocol.FirewallProvider,
	bool,
	[]protocol.CollectionIssue,
) {
	rules := make([]protocol.FirewallRule, 0)
	providers := make([]protocol.FirewallProvider, 0, 1)
	issues := make([]protocol.CollectionIssue, 0, 2)
	truncated := false

	for _, command := range []struct {
		family string
		paths  []string
	}{
		{family: "ipv4", paths: []string{"/usr/sbin/iptables-save", "/sbin/iptables-save", "/usr/bin/iptables-save"}},
		{family: "ipv6", paths: []string{"/usr/sbin/ip6tables-save", "/sbin/ip6tables-save", "/usr/bin/ip6tables-save"}},
	} {
		executable := trustedExecutable(command.paths...)
		if executable == "" {
			continue
		}

		output, err := runBoundedCommand(ctx, executable, nil, maxFirewallOutput)
		if err != nil {
			issues = append(issues, networkIssue("firewall.iptables.rules", err))
			continue
		}

		providers = upsertProvider(providers, protocol.FirewallProvider{
			Name: "iptables", Role: "filter", Status: "active",
		})
		parsed, wasTruncated := parseIPTablesSave(output, command.family, maxFirewallRules-len(rules))
		rules = append(rules, parsed...)
		truncated = truncated || wasTruncated
		if len(rules) == maxFirewallRules {
			break
		}
	}

	return rules, providers, truncated, issues
}

func parseIPTablesSave(data []byte, family string, remaining int) ([]protocol.FirewallRule, bool) {
	rules := make([]protocol.FirewallRule, 0)
	table := ""
	for lineIndex, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		if len(rules) == remaining {
			return rules, true
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		rule := protocol.FirewallRule{
			ID:               fmt.Sprintf("iptables:%s:%s:%d", family, table, lineIndex),
			Provider:         "iptables",
			Family:           family,
			Table:            sanitizeNetworkValue(table, 128),
			Chain:            sanitizeNetworkValue(fields[1], 128),
			Direction:        chainDirection(fields[1]),
			Protocol:         "any",
			SourceCIDRs:      []string{},
			DestinationCIDRs: []string{},
			SourcePorts:      []protocol.PortRange{},
			DestinationPorts: []protocol.PortRange{},
			Interfaces:       []string{},
			Enabled:          true,
			Partial:          true,
		}
		negated := false
		for _, field := range fields {
			if field == "!" {
				negated = true
				break
			}
		}

		for index := 2; index < len(fields); index++ {
			if index+1 >= len(fields) {
				break
			}
			value := strings.Trim(fields[index+1], "\"")
			switch fields[index] {
			case "-p", "--protocol":
				if !negated {
					rule.Protocol = normalizeProtocol(value)
				}
				index++
			case "-s", "--source":
				if !negated {
					rule.SourceCIDRs = []string{value}
				}
				index++
			case "-d", "--destination":
				if !negated {
					rule.DestinationCIDRs = []string{value}
				}
				index++
			case "--sport", "--sports":
				if !negated {
					rule.SourcePorts = parsePortList(value)
				}
				index++
			case "--dport", "--dports":
				if !negated {
					rule.DestinationPorts = parsePortList(value)
				}
				index++
			case "-i", "--in-interface", "-o", "--out-interface":
				if !negated {
					rule.Interfaces = append(rule.Interfaces, sanitizeNetworkValue(value, 255))
				}
				index++
			case "-j", "--jump":
				rule.Action = normalizeAction(value)
				index++
			}
		}

		if rule.Action != "" {
			rules = append(rules, rule)
		}
	}

	return rules, false
}

func parsePortList(value string) []protocol.PortRange {
	result := make([]protocol.PortRange, 0)
	for _, item := range strings.Split(value, ",") {
		bounds := strings.FieldsFunc(item, func(character rune) bool {
			return character == ':' || character == '-'
		})
		if len(bounds) == 0 || len(bounds) > 2 {
			continue
		}

		from, err := strconv.ParseUint(bounds[0], 10, 16)
		if err != nil || from == 0 {
			continue
		}
		to := from
		if len(bounds) == 2 {
			to, err = strconv.ParseUint(bounds[1], 10, 16)
			if err != nil || to < from {
				continue
			}
		}

		result = append(result, protocol.PortRange{From: uint16(from), To: uint16(to)})
	}

	return result
}

func runBoundedCommand(ctx context.Context, path string, arguments []string, limit int) ([]byte, error) {
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

	var output boundedBuffer
	output.limit = limit
	command.Stdout = &output
	command.Stderr = io.Discard

	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	if output.exceeded {
		return nil, errors.New("firewall command output exceeds limit")
	}

	return output.Bytes(), nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return len(data), nil
	}

	if len(data) > remaining {
		b.exceeded = true
		_, _ = b.Buffer.Write(data[:remaining])
		return len(data), nil
	}

	return b.Buffer.Write(data)
}

func trustedExecutable(paths ...string) string {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			continue
		}

		return path
	}

	return ""
}

func readNetworkFile(path string, limit int64) (data []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()

	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("network file exceeds %d bytes", limit)
	}

	return data, nil
}

func parseIPv4LittleEndian(value string) (net.IP, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != net.IPv4len {
		return nil, errors.New("invalid IPv4 route value")
	}

	number := binary.LittleEndian.Uint32(decoded)
	result := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(result, number)

	return result, nil
}

func normalizeFamily(value string) string {
	switch strings.ToLower(value) {
	case "ip":
		return "ipv4"
	case "ip6":
		return "ipv6"
	default:
		return "any"
	}
}

func normalizeAction(value string) string {
	switch strings.ToLower(value) {
	case "accept", "allow":
		return "allow"
	case "drop", "block":
		return "deny"
	case "reject":
		return "reject"
	default:
		return ""
	}
}

func normalizeProtocol(value string) string {
	switch strings.ToLower(value) {
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "132", "sctp":
		return "sctp"
	default:
		return "any"
	}
}

func chainDirection(chain string) string {
	switch strings.ToLower(chain) {
	case "input":
		return "inbound"
	case "output":
		return "outbound"
	case "forward":
		return "forward"
	default:
		return "any"
	}
}

func detectedFilterBackend(providers []protocol.FirewallProvider) string {
	for _, provider := range providers {
		if provider.Name == "nftables" {
			return "nftables"
		}
	}
	for _, provider := range providers {
		if provider.Name == "iptables" {
			return "iptables"
		}
	}

	return ""
}

func mergeProviders(current, additions []protocol.FirewallProvider) []protocol.FirewallProvider {
	for _, provider := range additions {
		current = upsertProvider(current, provider)
	}

	return current
}

func upsertProvider(providers []protocol.FirewallProvider, replacement protocol.FirewallProvider) []protocol.FirewallProvider {
	for index := range providers {
		if providers[index].Name == replacement.Name {
			providers[index] = replacement
			return providers
		}
	}

	return append(providers, replacement)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
