//go:build linux

package networkinfo

import (
	"net"
	"reflect"
	"syscall"
	"testing"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestParseIPv4LittleEndian(t *testing.T) {
	ip, err := parseIPv4LittleEndian("0102A8C0")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("192.168.2.1")) {
		t.Fatalf("parsed IP = %s", ip)
	}
}

func TestParseProcSocketLine(t *testing.T) {
	connection, include := parseProcSocketLine(
		"0: 0100007F:6B44 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0",
		procSocketTable{family: syscall.AF_INET, socketType: syscall.SOCK_STREAM, tcp: true},
	)
	if !include {
		t.Fatal("TCP listener was omitted")
	}
	if connection.Laddr.IP != "127.0.0.1" || connection.Laddr.Port != 27460 || connection.Status != "LISTEN" {
		t.Fatalf("connection = %#v", connection)
	}
}

func TestNormalizeNFTRule(t *testing.T) {
	rule, include := normalizeNFTRule([]byte(`{
        "family":"ip","table":"filter","chain":"input","handle":12,
        "expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
            {"accept":null}
        ]
    }`))
	if !include {
		t.Fatal("port-bearing nftables rule was omitted")
	}
	if rule.Action != "allow" || rule.Direction != "inbound" || rule.Protocol != "tcp" {
		t.Fatalf("unexpected normalized nftables rule: %#v", rule)
	}
	if !reflect.DeepEqual(rule.DestinationPorts, []protocol.PortRange{{From: 443, To: 443}}) {
		t.Fatalf("destination ports = %#v", rule.DestinationPorts)
	}
}

func TestNormalizeNFTRuleDoesNotInvertNegativeMatch(t *testing.T) {
	rule, include := normalizeNFTRule([]byte(`{
        "family":"ip","table":"filter","chain":"input","handle":13,
        "expr":[
            {"match":{"op":"!=","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
            {"accept":null}
        ]
    }`))
	if !include || !rule.Partial {
		t.Fatalf("negative nftables rule = %#v, included=%v", rule, include)
	}
	if len(rule.DestinationPorts) != 0 {
		t.Fatalf("negative port condition was reported as positive: %#v", rule.DestinationPorts)
	}
}

func TestParseIPTablesSave(t *testing.T) {
	rules, truncated := parseIPTablesSave([]byte(`*filter
-A INPUT -p tcp -s 10.0.0.0/8 --dport 27460 -j ACCEPT
-A OUTPUT -p udp --sport 53 -j ACCEPT
COMMIT
`), "ipv4", 10)
	if truncated || len(rules) != 2 {
		t.Fatalf("rules=%#v truncated=%v", rules, truncated)
	}
	if rules[0].DestinationPorts[0].From != 27460 || rules[1].SourcePorts[0].From != 53 {
		t.Fatalf("unexpected iptables port rules: %#v", rules)
	}
}

func TestParseIPTablesSaveDoesNotInvertNegatedCondition(t *testing.T) {
	rules, truncated := parseIPTablesSave([]byte(`*filter
-A INPUT -p tcp ! --dport 22 -j ACCEPT
COMMIT
`), "ipv4", 10)
	if truncated || len(rules) != 1 {
		t.Fatalf("rules=%#v truncated=%v", rules, truncated)
	}
	if !rules[0].Partial || len(rules[0].DestinationPorts) != 0 {
		t.Fatalf("negated condition was reported as positive: %#v", rules[0])
	}
}
