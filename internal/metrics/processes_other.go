//go:build !linux

package metrics

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

type processObservation struct {
	metric  protocol.ProcessMetric
	raw     rawProcess
	status  string
	partial bool
}

func collectProcesses(
	ctx context.Context,
	previous map[processKey]rawProcess,
	interval time.Duration,
	current *rawCounters,
	_ *userCache,
	issues *[]protocol.CollectionIssue,
) protocol.ProcessMetrics {
	result := protocol.ProcessMetrics{Items: []protocol.ProcessMetric{}}
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		*issues = append(*issues, issue("processes", classifyError(err)))
		return result
	}

	result.Total = len(processes)

	observations := make([]processObservation, 0, len(processes))
	nextRaw := make(map[processKey]rawProcess, len(processes))
	partial := false

	for _, candidate := range processes {
		observation, key, ok := observeProcess(ctx, candidate, previous, interval)
		if !ok {
			partial = true
			continue
		}

		observations = append(observations, observation)
		nextRaw[key] = observation.raw
		result.Threads += int(observation.metric.Threads)
		countProcessStatus(&result, observation.status)
		partial = partial || observation.partial
	}

	current.processes = nextRaw
	sort.Slice(observations, func(left, right int) bool {
		leftMetric := observations[left].metric
		rightMetric := observations[right].metric
		if leftMetric.CPUPercent != rightMetric.CPUPercent {
			return leftMetric.CPUPercent > rightMetric.CPUPercent
		}
		if leftMetric.MemoryRSSBytes != rightMetric.MemoryRSSBytes {
			return leftMetric.MemoryRSSBytes > rightMetric.MemoryRSSBytes
		}
		return leftMetric.PID < rightMetric.PID
	})

	if len(observations) > maxProcessItems {
		observations = observations[:maxProcessItems]
		result.Truncated = true
	}
	for _, observation := range observations {
		result.Items = append(result.Items, observation.metric)
	}

	if partial {
		*issues = append(*issues, issue("processes", "partial"))
	}
	if result.Truncated {
		*issues = append(*issues, issue("processes", "truncated"))
	}

	return result
}

func observeProcess(
	ctx context.Context,
	candidate *process.Process,
	previous map[processKey]rawProcess,
	interval time.Duration,
) (processObservation, processKey, bool) {
	startedMS, err := candidate.CreateTimeWithContext(ctx)
	if err != nil || startedMS <= 0 {
		return processObservation{}, processKey{}, false
	}

	name, err := candidate.NameWithContext(ctx)
	if err != nil {
		return processObservation{}, processKey{}, false
	}
	times, err := candidate.TimesWithContext(ctx)
	if err != nil {
		return processObservation{}, processKey{}, false
	}
	memory, err := candidate.MemoryInfoWithContext(ctx)
	if err != nil {
		return processObservation{}, processKey{}, false
	}

	ioCounters, ioErr := candidate.IOCountersWithContext(ctx)
	status, statusErr := candidate.StatusWithContext(ctx)
	threads, threadsErr := candidate.NumThreadsWithContext(ctx)
	fileDescriptors, fileDescriptorsErr := candidate.NumFDsWithContext(ctx)

	currentRaw := rawProcess{cpuSeconds: processCPUSeconds(times)}
	if ioCounters != nil {
		currentRaw.readBytes = ioCounters.ReadBytes
		if currentRaw.readBytes == 0 {
			currentRaw.readBytes = ioCounters.DiskReadBytes
		}
		currentRaw.writeBytes = ioCounters.WriteBytes
		if currentRaw.writeBytes == 0 {
			currentRaw.writeBytes = ioCounters.DiskWriteBytes
		}
	}

	key := processKey{pid: candidate.Pid, startedMS: startedMS}
	previousRaw, exists := previous[key]
	seconds := interval.Seconds()
	metric := protocol.ProcessMetric{
		PID:                candidate.Pid,
		StartedAt:          time.UnixMilli(startedMS).UTC(),
		Name:               sanitize(name, 256),
		MemoryRSSBytes:     memory.RSS,
		MemoryVirtualBytes: memory.VMS,
		Threads:            max(threads, 0),
	}
	if exists && seconds > 0 {
		metric.CPUPercent = cpuPercent(counterDelta(previousRaw.cpuSeconds, currentRaw.cpuSeconds) / seconds * 100)
		metric.ReadBytesPerSecond = rate(previousRaw.readBytes, currentRaw.readBytes, seconds)
		metric.WriteBytesPerSecond = rate(previousRaw.writeBytes, currentRaw.writeBytes, seconds)
	}
	if fileDescriptorsErr == nil && fileDescriptors >= 0 {
		metric.FileDescriptors = &fileDescriptors
	}

	processStatus := ""
	if len(status) > 0 {
		processStatus = strings.ToLower(status[0])
	}

	return processObservation{
		metric:  metric,
		raw:     currentRaw,
		status:  processStatus,
		partial: ioErr != nil || statusErr != nil || threadsErr != nil || fileDescriptorsErr != nil,
	}, key, true
}

func countProcessStatus(result *protocol.ProcessMetrics, status string) {
	switch status {
	case "r", "running":
		result.Running++
	case "d", "blocked", "disk-sleep":
		result.Blocked++
	case "z", "zombie":
		result.Zombie++
	default:
		result.Sleeping++
	}
}

func processCPUSeconds(times *cpu.TimesStat) float64 {
	if times == nil {
		return 0
	}

	return times.User + times.Nice + times.System + times.Irq + times.Softirq + times.Steal
}
