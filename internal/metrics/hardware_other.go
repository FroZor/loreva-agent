//go:build !linux

package metrics

import "github.com/FroZor/loreva-agent/internal/protocol"

func collectRAID() []protocol.RAIDMetrics {
	return []protocol.RAIDMetrics{}
}

func collectSensors() []protocol.SensorMetrics {
	return []protocol.SensorMetrics{}
}
