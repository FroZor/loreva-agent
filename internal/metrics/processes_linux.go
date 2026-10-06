//go:build linux

package metrics

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/procfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// collectProcesses scans the whole process table every interval, so counts
// and the busiest processes are exact however many processes run. Details
// that need more reads are taken only for the reported items and cached for
// the life of each process.
func collectProcesses(
	_ context.Context,
	previous map[processKey]rawProcess,
	interval time.Duration,
	current *rawCounters,
	users *userCache,
	issues *[]protocol.CollectionIssue,
) protocol.ProcessMetrics {
	result := protocol.ProcessMetrics{Items: []protocol.ProcessMetric{}}

	processes, err := procfs.Scan()
	if err != nil {
		*issues = append(*issues, issue("processes", classifyError(err)))
		return result
	}

	seconds := interval.Seconds()
	nextRaw := make(map[processKey]rawProcess, len(processes))
	metrics := make([]protocol.ProcessMetric, 0, len(processes))
	keys := make(map[int32]processKey, len(processes))
	for _, process := range processes {
		result.Total++
		result.Threads += int(process.Threads)
		countProcessState(&result, process.State)

		key := processKey{pid: process.PID, startedMS: process.StartedAt.UnixMilli()}
		raw := previous[key]
		metric := protocol.ProcessMetric{
			PID:                process.PID,
			ParentPID:          process.ParentPID,
			StartedAt:          process.StartedAt,
			Name:               sanitize(process.Name, 256),
			State:              process.State,
			MemoryRSSBytes:     process.RSSBytes,
			MemoryVirtualBytes: process.VMSBytes,
			Threads:            max(process.Threads, 0),
		}
		if _, existed := previous[key]; existed && seconds > 0 {
			metric.CPUPercent = cpuPercent(counterDelta(raw.cpuSeconds, process.CPUSeconds) / seconds * 100)
		}
		raw.cpuSeconds = process.CPUSeconds
		nextRaw[key] = raw
		keys[process.PID] = key
		metrics = append(metrics, metric)
	}

	slices.SortFunc(metrics, func(left, right protocol.ProcessMetric) int {
		switch {
		case left.CPUPercent != right.CPUPercent:
			return compareDescending(left.CPUPercent, right.CPUPercent)
		case left.MemoryRSSBytes != right.MemoryRSSBytes:
			return compareDescending(left.MemoryRSSBytes, right.MemoryRSSBytes)
		default:
			return int(left.PID - right.PID)
		}
	})
	if len(metrics) > maxProcessItems {
		metrics = metrics[:maxProcessItems]
		result.Truncated = true
		*issues = append(*issues, issue("processes", "truncated"))
	}

	names := users.get()
	for index := range metrics {
		metric := &metrics[index]
		key := keys[metric.PID]
		raw := nextRaw[key]
		if raw.identity == nil {
			identity := procfs.ReadIdentity(metric.PID, names)
			raw.identity = &identity
		}
		metric.User = sanitize(raw.identity.User, 64)
		metric.UID = raw.identity.UID
		metric.ContainerID = raw.identity.ContainerID

		usage := procfs.ReadUsage(metric.PID)
		metric.FileDescriptors = usage.FileDescriptors
		if usage.ReadBytes != nil && usage.WriteBytes != nil {
			if raw.hasIO && seconds > 0 {
				metric.ReadBytesPerSecond = rate(raw.readBytes, *usage.ReadBytes, seconds)
				metric.WriteBytesPerSecond = rate(raw.writeBytes, *usage.WriteBytes, seconds)
			}
			raw.readBytes, raw.writeBytes, raw.hasIO = *usage.ReadBytes, *usage.WriteBytes, true
		}
		nextRaw[key] = raw
	}
	result.Items = metrics
	current.processes = nextRaw

	return result
}

func compareDescending[T float64 | uint64](left, right T) int {
	if left > right {
		return -1
	}
	return 1
}

func countProcessState(result *protocol.ProcessMetrics, state string) {
	switch state {
	case procfs.StateRunning:
		result.Running++
	case procfs.StateBlocked:
		result.Blocked++
	case procfs.StateZombie:
		result.Zombie++
	default:
		result.Sleeping++
	}
}

// userCache keeps the host's UID to name map, re-read once a minute so new
// accounts appear without a restart.
type userCache struct {
	mu     sync.Mutex
	names  map[uint32]string
	readAt time.Time
}

func (c *userCache) get() map[uint32]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.names == nil || time.Since(c.readAt) > time.Minute {
		c.names = procfs.Users()
		c.readAt = time.Now()
	}

	return c.names
}
