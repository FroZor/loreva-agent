//go:build windows

package networkinfo

import (
	"reflect"
	"testing"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestParseWindowsPorts(t *testing.T) {
	want := []protocol.PortRange{{From: 80, To: 80}, {From: 443, To: 445}}
	if got := parseWindowsPorts("80,443-445,RPC"); !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %#v, want %#v", got, want)
	}
}

func TestNormalizeWindowsFirewallRules(t *testing.T) {
	rules := normalizeWindowsFirewallRules([]windowsFirewallRule{{
		ID:               "rule-1",
		Direction:        "Inbound",
		Action:           "Allow",
		Protocol:         "TCP",
		LocalPorts:       "27460",
		RemotePorts:      "Any",
		LocalAddresses:   "Any",
		RemoteAddresses:  "10.0.0.0/8",
		InterfaceAliases: "Ethernet",
	}})
	if len(rules) != 1 {
		t.Fatalf("rules = %#v", rules)
	}
	if rules[0].Action != "allow" || rules[0].DestinationPorts[0].From != 27460 {
		t.Fatalf("unexpected normalized Windows rule: %#v", rules[0])
	}
}

func TestNormalizeWindowsOutboundFirewallRuleSwapsLocalAndRemote(t *testing.T) {
	rules := normalizeWindowsFirewallRules([]windowsFirewallRule{{
		ID:              "rule-2",
		Direction:       "Outbound",
		Action:          "Block",
		Protocol:        "TCP",
		LocalPorts:      "50000",
		RemotePorts:     "443",
		LocalAddresses:  "10.0.0.2",
		RemoteAddresses: "203.0.113.10",
	}})
	if len(rules) != 1 {
		t.Fatalf("rules = %#v", rules)
	}
	if rules[0].SourcePorts[0].From != 50000 || rules[0].DestinationPorts[0].From != 443 {
		t.Fatalf("outbound ports were not normalized by packet direction: %#v", rules[0])
	}
	if !reflect.DeepEqual(rules[0].SourceCIDRs, []string{"10.0.0.2"}) ||
		!reflect.DeepEqual(rules[0].DestinationCIDRs, []string{"203.0.113.10"}) {
		t.Fatalf("outbound addresses were not normalized by packet direction: %#v", rules[0])
	}
}

func TestNormalizeWindowsFirewallRuleWithoutPortsIsRetainedAsPartial(t *testing.T) {
	rules := normalizeWindowsFirewallRules([]windowsFirewallRule{{
		ID:        "rule-3",
		Direction: "Inbound",
		Action:    "Block",
		Protocol:  "Any",
	}})
	if len(rules) != 1 || !rules[0].Partial {
		t.Fatalf("general firewall rule = %#v", rules)
	}
}
