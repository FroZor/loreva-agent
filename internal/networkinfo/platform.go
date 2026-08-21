package networkinfo

import "github.com/FroZor/loreva-agent/internal/protocol"

type platformNetwork struct {
	routes   []protocol.NetworkRoute
	firewall protocol.FirewallInformation
	issues   []protocol.CollectionIssue
}
