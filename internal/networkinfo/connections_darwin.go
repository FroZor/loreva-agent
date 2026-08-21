//go:build darwin

package networkinfo

import (
	"context"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

func connectionStats(ctx context.Context, limit int) ([]gopsutilnet.ConnectionStat, error) {
	connections, err := gopsutilnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, err
	}

	listeners := make([]gopsutilnet.ConnectionStat, 0, min(len(connections), limit))
	for _, connection := range connections {
		if _, listening := listeningProtocol(connection); !listening {
			continue
		}

		listeners = append(listeners, connection)
		if len(listeners) == limit {
			break
		}
	}

	return listeners, nil
}
