//go:build !linux

package observation

import "github.com/FroZor/loreva-agent/internal/protocol"

func fallbackScope() string {
	return protocol.ObservationScopeHost
}
