//go:build !windows && !linux && !darwin

package networkinfo

import (
	"context"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

func connectionStats(ctx context.Context, limit int) ([]gopsutilnet.ConnectionStat, error) {
	return gopsutilnet.ConnectionsMaxWithoutUidsWithContext(ctx, "inet", limit)
}
