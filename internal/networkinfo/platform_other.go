//go:build !linux && !windows

package networkinfo

import (
	"context"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func collectPlatformNetwork(context.Context) platformNetwork {
	return platformNetwork{
		firewall: protocol.FirewallInformation{
			Status: "unavailable",
		},
		issues: []protocol.CollectionIssue{
			{Component: "routes", Code: "not_available"},
			{Component: "firewall", Code: "not_available"},
		},
	}
}
