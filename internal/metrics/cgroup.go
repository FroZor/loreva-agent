package metrics

import (
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// cgroupReading is one reading of a container's cgroup v2 files and of its
// network namespace.
type cgroupReading struct {
	readAt           time.Time
	cpuUsageNanos    uint64
	throttledSeconds float64
	throttledPeriods uint64
	memoryCurrent    uint64
	// memoryMax is 0 when the cgroup has no limit.
	memoryMax    uint64
	inactiveFile uint64
	fileBytes    uint64
	oomKills     uint64
	readBytes    uint64
	writeBytes   uint64
	readOps      uint64
	writeOps     uint64
	rxBytes      uint64
	txBytes      uint64
	rxPackets    uint64
	txPackets    uint64
	pids         uint64
	pidsLimit    uint64
}

// raw converts the reading to the counters rates are calculated from. CPU
// usage is measured against wall time, so 100 is one busy logical CPU.
func (reading cgroupReading) raw(onlineCPUs uint32) rawContainer {
	return rawContainer{
		readAt:          reading.readAt,
		cpuTotal:        reading.cpuUsageNanos,
		onlineCPUs:      onlineCPUs,
		cpuUnitNanos:    1,
		readBytes:       reading.readBytes,
		writeBytes:      reading.writeBytes,
		readOperations:  reading.readOps,
		writeOperations: reading.writeOps,
		rxBytes:         reading.rxBytes,
		txBytes:         reading.txBytes,
		rxPackets:       reading.rxPackets,
		txPackets:       reading.txPackets,
	}
}

// memory reports usage as docker stats does: current usage without the
// inactive page cache. Without a limit the node's memory is the limit.
func (reading cgroupReading) memory(hostMemory uint64) protocol.ContainerMemoryMetrics {
	used := reading.memoryCurrent
	if reading.inactiveFile < used {
		used -= reading.inactiveFile
	}

	limit := reading.memoryMax
	if limit == 0 || (hostMemory > 0 && limit > hostMemory) {
		limit = hostMemory
	}

	usedPercent := 0.0
	if limit > 0 {
		usedPercent = percent(float64(used) / float64(limit) * 100)
	}

	return protocol.ContainerMemoryMetrics{
		UsedBytes:      used,
		LimitBytes:     limit,
		UsedPercent:    usedPercent,
		CacheBytes:     reading.fileBytes,
		OOMEventsTotal: reading.oomKills,
	}
}
