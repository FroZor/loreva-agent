package networkinfo

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestCollectReturnsNetworkState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	snapshot, err := Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ObservationScope != protocol.ObservationScopeHost &&
		snapshot.ObservationScope != protocol.ObservationScopeRuntime {
		t.Fatalf("observation scope = %q", snapshot.ObservationScope)
	}
	if len(snapshot.Network.Interfaces) == 0 {
		t.Fatal("network interfaces were not collected")
	}
	if snapshot.Network.Firewall.Status == "" {
		t.Fatal("firewall status was not reported")
	}
}

func TestFitNetworkToBudgetTruncatesLargeRuleSet(t *testing.T) {
	rules := make([]protocol.FirewallRule, 5000)
	for index := range rules {
		rules[index] = protocol.FirewallRule{
			ID:               strings.Repeat("r", 128),
			Provider:         "nftables",
			Family:           "ipv4",
			Direction:        "inbound",
			Action:           "allow",
			Protocol:         "tcp",
			SourceCIDRs:      []string{"0.0.0.0/0"},
			DestinationPorts: []protocol.PortRange{{From: 443, To: 443}},
			Enabled:          true,
		}
	}

	network := protocol.NodeNetwork{
		Interfaces:     []protocol.NetworkInterfaceConfiguration{},
		Routes:         []protocol.NetworkRoute{},
		ListeningPorts: []protocol.ListeningPort{},
		Firewall: protocol.FirewallInformation{
			Status: "active", Providers: []protocol.FirewallProvider{}, Rules: rules,
		},
	}
	if err := fitNetworkToBudget(&network); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(network)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxNetworkSnapshotJSON {
		t.Fatalf("network snapshot is %d bytes", len(data))
	}
	if !network.Firewall.Truncated || len(network.Firewall.Rules) >= len(rules) {
		t.Fatal("large firewall rule set was not marked as truncated")
	}
}

func TestFitNetworkToBudgetTruncatesInterfaceAddresses(t *testing.T) {
	addresses := make([]protocol.NetworkAddress, 20000)
	for index := range addresses {
		addresses[index] = protocol.NetworkAddress{
			Family:       "ipv6",
			Address:      strings.Repeat("a", 48),
			PrefixLength: 64,
		}
	}

	network := protocol.NodeNetwork{
		Interfaces: []protocol.NetworkInterfaceConfiguration{{
			ID:        "network:1",
			Name:      "large-interface",
			Flags:     []string{},
			Addresses: addresses,
		}},
		Routes:         []protocol.NetworkRoute{},
		ListeningPorts: []protocol.ListeningPort{},
		Firewall: protocol.FirewallInformation{
			Status: "inactive", Providers: []protocol.FirewallProvider{}, Rules: []protocol.FirewallRule{},
		},
	}
	if err := fitNetworkToBudget(&network); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(network)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxNetworkSnapshotJSON || len(network.Interfaces[0].Addresses) >= len(addresses) {
		t.Fatalf("interface addresses were not bounded: size=%d addresses=%d", len(data), len(network.Interfaces[0].Addresses))
	}
}

func TestSanitizeNetworkValuePreservesUTF8(t *testing.T) {
	if value := sanitizeNetworkValue("éé", 3); value != "é" {
		t.Fatalf("sanitized value = %q", value)
	}
}

func TestNetworkIssueClassifiesTimeout(t *testing.T) {
	if issue := networkIssue("firewall.rules", context.DeadlineExceeded); issue.Code != "timeout" {
		t.Fatalf("issue code = %q", issue.Code)
	}
}

func TestCollectFindsOwnTCPListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close test listener: %v", err)
		}
	})

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	snapshot, err := Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, listeningPort := range snapshot.Network.ListeningPorts {
		if listeningPort.Protocol == "tcp" && listeningPort.Port == port {
			return
		}
	}

	t.Fatalf("TCP listener on port %d was not reported; issues=%#v", port, snapshot.Network.CollectionIssues)
}
