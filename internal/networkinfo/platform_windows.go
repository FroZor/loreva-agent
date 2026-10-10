//go:build windows

package networkinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/windows"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxWindowsNetworkOutput = 4 * 1024 * 1024
	maxWindowsNetworkRules  = 4096
)

const windowsNetworkScript = `$ErrorActionPreference = 'Stop'
$utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

$routesAvailable = $true
$routesTruncated = $false
$firewallAvailable = $true
$truncated = $false

try {
    $sourceRoutes = @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore | Select-Object -First 4097)
    if ($sourceRoutes.Count -gt 4096) {
        $sourceRoutes = @($sourceRoutes | Select-Object -First 4096)
        $routesTruncated = $true
    }
    $routes = @($sourceRoutes | ForEach-Object {
        [pscustomobject]@{
            destination = [string]$_.DestinationPrefix
            gateway = [string]$_.NextHop
            interface_index = [int]$_.InterfaceIndex
            metric = [uint64]$_.RouteMetric
        }
    })
} catch {
    $routesAvailable = $false
    $routes = @()
}

try {
    $profiles = @(NetSecurity\Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.Name
            enabled = [bool]$_.Enabled
        }
    })

    $sourceRules = @(NetSecurity\Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True | Select-Object -First 4097)
    if ($sourceRules.Count -gt 4096) {
        $sourceRules = @($sourceRules | Select-Object -First 4096)
		$truncated = $true
	}

	$portsByID = @{}
	NetSecurity\Get-NetFirewallPortFilter -PolicyStore ActiveStore | ForEach-Object {
		$portsByID[[string]$_.InstanceID] = $_
	}
	$addressesByID = @{}
	NetSecurity\Get-NetFirewallAddressFilter -PolicyStore ActiveStore | ForEach-Object {
		$addressesByID[[string]$_.InstanceID] = $_
	}

	$rules = @($sourceRules | ForEach-Object {
		$rule = $_
		$ports = $portsByID[[string]$rule.InstanceID]
		$addresses = $addressesByID[[string]$rule.InstanceID]

        [pscustomobject]@{
            id = [string]$rule.InstanceID
            direction = [string]$rule.Direction
            action = [string]$rule.Action
            protocol = [string]$ports.Protocol
            local_ports = [string]$ports.LocalPort
            remote_ports = [string]$ports.RemotePort
            local_addresses = [string]$addresses.LocalAddress
            remote_addresses = [string]$addresses.RemoteAddress
            interface_alias = [string]$rule.InterfaceAlias
        }
    })
} catch {
    $firewallAvailable = $false
    $profiles = @()
    $rules = @()
}

[pscustomobject]@{
    routes_available = $routesAvailable
    routes_truncated = $routesTruncated
    firewall_available = $firewallAvailable
    truncated = $truncated
    routes = $routes
    profiles = $profiles
    rules = $rules
} | ConvertTo-Json -Depth 5 -Compress`

type windowsNetworkDocument struct {
	RoutesAvailable   bool                  `json:"routes_available"`
	RoutesTruncated   bool                  `json:"routes_truncated"`
	FirewallAvailable bool                  `json:"firewall_available"`
	Truncated         bool                  `json:"truncated"`
	Routes            []windowsRoute        `json:"routes"`
	Profiles          []windowsProfile      `json:"profiles"`
	Rules             []windowsFirewallRule `json:"rules"`
}

type windowsRoute struct {
	Destination    string `json:"destination"`
	Gateway        string `json:"gateway"`
	InterfaceIndex int    `json:"interface_index"`
	Metric         uint64 `json:"metric"`
}

type windowsProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type windowsFirewallRule struct {
	ID               string `json:"id"`
	Direction        string `json:"direction"`
	Action           string `json:"action"`
	Protocol         string `json:"protocol"`
	LocalPorts       string `json:"local_ports"`
	RemotePorts      string `json:"remote_ports"`
	LocalAddresses   string `json:"local_addresses"`
	RemoteAddresses  string `json:"remote_addresses"`
	InterfaceAliases string `json:"interface_alias"`
}

func collectPlatformNetwork(ctx context.Context) platformNetwork {
	document, err := collectWindowsNetwork(ctx)
	if err != nil {
		issue := networkIssue("network.windows", err)

		return platformNetwork{
			firewall: protocol.FirewallInformation{
				Status:    "unavailable",
				Providers: []protocol.FirewallProvider{{Name: "windows_defender_firewall", Role: "filter", Status: "unknown"}},
				Rules:     []protocol.FirewallRule{},
			},
			issues: []protocol.CollectionIssue{issue},
		}
	}

	result := platformNetwork{
		routes: normalizeWindowsRoutes(document.Routes),
		firewall: protocol.FirewallInformation{
			Status:    windowsFirewallStatus(document),
			Providers: windowsFirewallProviders(document.Profiles, document.FirewallAvailable),
			Rules:     normalizeWindowsFirewallRules(document.Rules),
			Truncated: document.Truncated,
		},
	}
	if !document.RoutesAvailable {
		result.routes = nil
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "routes", Code: "not_available"})
	} else if document.RoutesTruncated {
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "routes", Code: "truncated"})
	}
	if !document.FirewallAvailable {
		result.firewall.Rules = nil
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "firewall.rules", Code: "not_available"})
	}
	if document.Truncated {
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "firewall.rules", Code: "truncated"})
	}

	return result
}

func collectWindowsNetwork(ctx context.Context) (windowsNetworkDocument, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return windowsNetworkDocument{}, fmt.Errorf("locate Windows system directory: %w", err)
	}

	executable := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	command := exec.CommandContext(
		ctx,
		executable,
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command", windowsNetworkScript,
	)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, NoInheritHandles: true}

	var stdout limitedWindowsBuffer
	var stderr limitedWindowsBuffer
	stdout.limit = maxWindowsNetworkOutput
	stderr.limit = 64 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return windowsNetworkDocument{}, contextErr
		}
		if stdout.exceeded || stderr.exceeded {
			return windowsNetworkDocument{}, errors.New("Windows network collector output exceeded its limit")
		}

		return windowsNetworkDocument{}, fmt.Errorf("run Windows network collector: %w", err)
	}
	if stdout.exceeded {
		return windowsNetworkDocument{}, errors.New("Windows network collector output exceeded its limit")
	}
	if !utf8.Valid(stdout.Bytes()) {
		return windowsNetworkDocument{}, errors.New("Windows network collector output is not valid UTF-8")
	}

	var document windowsNetworkDocument
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return windowsNetworkDocument{}, fmt.Errorf("decode Windows network information: %w", err)
	}
	if err := ensureWindowsJSONEOF(decoder); err != nil {
		return windowsNetworkDocument{}, err
	}

	return document, nil
}

func normalizeWindowsRoutes(routes []windowsRoute) []protocol.NetworkRoute {
	result := make([]protocol.NetworkRoute, 0, len(routes))
	for _, route := range routes {
		_, destination, err := net.ParseCIDR(route.Destination)
		if err != nil || route.InterfaceIndex <= 0 {
			continue
		}

		normalized := protocol.NetworkRoute{
			Family:      ipFamily(destination.IP),
			Destination: destination.String(),
			InterfaceID: "network:" + strconv.Itoa(route.InterfaceIndex),
			Metric:      route.Metric,
		}
		if gateway := net.ParseIP(route.Gateway); gateway != nil && !gateway.IsUnspecified() {
			normalized.Gateway = gateway.String()
		}

		result = append(result, normalized)
	}

	return result
}

func windowsFirewallStatus(document windowsNetworkDocument) string {
	if !document.FirewallAvailable {
		return "partial"
	}
	for _, profile := range document.Profiles {
		if profile.Enabled {
			return "active"
		}
	}

	return "inactive"
}

func windowsFirewallProviders(profiles []windowsProfile, available bool) []protocol.FirewallProvider {
	status := "unknown"
	if available {
		status = "inactive"
		for _, profile := range profiles {
			if profile.Enabled {
				status = "active"
				break
			}
		}
	}

	return []protocol.FirewallProvider{{Name: "windows_defender_firewall", Role: "filter", Status: status}}
}

func normalizeWindowsFirewallRules(rules []windowsFirewallRule) []protocol.FirewallRule {
	result := make([]protocol.FirewallRule, 0, len(rules))
	for _, source := range rules {
		protocolName := normalizeWindowsProtocol(source.Protocol)
		localPorts := parseWindowsPorts(source.LocalPorts)
		remotePorts := parseWindowsPorts(source.RemotePorts)
		localAddresses := parseWindowsAddresses(source.LocalAddresses)
		remoteAddresses := parseWindowsAddresses(source.RemoteAddresses)
		direction := normalizeWindowsDirection(source.Direction)

		sourceAddresses := remoteAddresses
		destinationAddresses := localAddresses
		sourcePorts := remotePorts
		destinationPorts := localPorts
		if direction == "outbound" {
			sourceAddresses = localAddresses
			destinationAddresses = remoteAddresses
			sourcePorts = localPorts
			destinationPorts = remotePorts
		}

		rule := protocol.FirewallRule{
			ID:               sanitizeNetworkValue(source.ID, 256),
			Provider:         "windows_defender_firewall",
			Family:           "any",
			Direction:        direction,
			Action:           normalizeWindowsAction(source.Action),
			Protocol:         protocolName,
			SourceCIDRs:      sourceAddresses,
			DestinationCIDRs: destinationAddresses,
			SourcePorts:      sourcePorts,
			DestinationPorts: destinationPorts,
			Interfaces:       splitWindowsValues(source.InterfaceAliases),
			Enabled:          true,
			Partial:          true,
		}
		if rule.ID == "" || rule.Direction == "" || rule.Action == "" {
			continue
		}

		result = append(result, rule)
		if len(result) == maxWindowsNetworkRules {
			break
		}
	}

	return result
}

func normalizeWindowsProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "1", "icmpv4":
		return "icmp"
	case "58", "icmpv6":
		return "icmpv6"
	default:
		return "any"
	}
}

func normalizeWindowsDirection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "inbound":
		return "inbound"
	case "2", "outbound":
		return "outbound"
	default:
		return ""
	}
}

func normalizeWindowsAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "2", "allow":
		return "allow"
	case "4", "block":
		return "deny"
	default:
		return ""
	}
}

func parseWindowsPorts(value string) []protocol.PortRange {
	ports := make([]protocol.PortRange, 0)
	for _, item := range splitWindowsValues(value) {
		bounds := strings.SplitN(item, "-", 2)
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

		ports = append(ports, protocol.PortRange{From: uint16(from), To: uint16(to)})
	}

	return ports
}

func parseWindowsAddresses(value string) []string {
	addresses := make([]string, 0)
	for _, item := range splitWindowsValues(value) {
		if strings.EqualFold(item, "Any") {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			addresses = append(addresses, ip.String())
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			addresses = append(addresses, network.String())
		}
	}

	return addresses
}

func splitWindowsValues(value string) []string {
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ';'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		field = sanitizeNetworkValue(field, 255)
		if field != "" && !strings.EqualFold(field, "Any") {
			result = append(result, field)
		}
	}

	return result
}

func ipFamily(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}

	return "ipv6"
}

func ensureWindowsJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("Windows network collector returned multiple JSON values")
	}

	return fmt.Errorf("finish decoding Windows network information: %w", err)
}

type limitedWindowsBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedWindowsBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return originalLength, nil
	}
	if len(data) > remaining {
		buffer.exceeded = true
		data = data[:remaining]
	}

	_, _ = buffer.Buffer.Write(data)

	return originalLength, nil
}
