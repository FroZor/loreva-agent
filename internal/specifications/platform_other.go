//go:build !linux && !windows

package specifications

import (
	"context"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func collectPlatform(context.Context) platformSpecifications {
	return platformSpecifications{
		logicalProcessorNUMA: make(map[string]string),
		networkInterfaces:    make(map[string]networkInterfaceMetadata),
		issues: []protocol.CollectionIssue{
			{Component: "cpu.numa_nodes", Code: issueNotAvailable},
			{Component: "memory.modules", Code: issueNotAvailable},
			{Component: "gpus", Code: issueNotAvailable},
			{Component: "storage_devices", Code: issueNotAvailable},
		},
	}
}
