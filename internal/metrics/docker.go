package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxContainers       = 256
	containerWorkers    = 8
	maxContainerStats   = 2 * 1024 * 1024
	dockerProbeInterval = 30 * time.Second
)

type containerObservation struct {
	metric protocol.ContainerMetrics
	raw    rawContainer
}

type containerCollection struct {
	summary     container.Summary
	observation containerObservation
	err         error
}

func (collector *Collector) collectContainers(
	ctx context.Context,
	issues *[]protocol.CollectionIssue,
) []protocol.ContainerMetrics {
	if collector.dockerClient == nil {
		*issues = append(*issues, issue("containers.docker", "client_unavailable"))
		return []protocol.ContainerMetrics{}
	}
	if time.Now().Before(collector.nextDockerProbe) {
		return []protocol.ContainerMetrics{}
	}

	result, err := collector.dockerClient.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		collector.nextDockerProbe = time.Now().Add(dockerProbeInterval)
		*issues = append(*issues, issue("containers.docker", classifyError(err)))
		return []protocol.ContainerMetrics{}
	}
	collector.nextDockerProbe = time.Time{}

	containers := result.Items
	truncated := false
	if len(containers) > maxContainers {
		containers = containers[:maxContainers]
		truncated = true
	}

	observations := make([]containerObservation, 0, len(containers))
	nextRaw := make(map[string]rawContainer, len(containers))
	partial := false

	for collection := range collector.collectContainerObservations(ctx, containers) {
		if collection.err != nil {
			partial = true
			continue
		}

		observations = append(observations, collection.observation)
		nextRaw[collection.summary.ID] = collection.observation.raw
	}

	collector.containers = nextRaw
	sort.Slice(observations, func(left, right int) bool {
		return observations[left].metric.ContainerID < observations[right].metric.ContainerID
	})

	metrics := make([]protocol.ContainerMetrics, 0, len(observations))
	for _, observation := range observations {
		metrics = append(metrics, observation.metric)
	}

	if partial {
		*issues = append(*issues, issue("containers.docker", "partial"))
	}
	if truncated {
		*issues = append(*issues, issue("containers.docker", "truncated"))
	}

	return metrics
}

func (collector *Collector) collectContainerObservations(
	ctx context.Context,
	containers []container.Summary,
) <-chan containerCollection {
	results := make(chan containerCollection, len(containers))
	if len(containers) == 0 {
		close(results)
		return results
	}

	jobs := make(chan container.Summary)
	workers := min(containerWorkers, len(containers))
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)

	for range workers {
		go func() {
			defer waitGroup.Done()

			for summary := range jobs {
				observation, err := collector.observeContainer(ctx, summary)
				results <- containerCollection{
					summary:     summary,
					observation: observation,
					err:         err,
				}
			}
		}()
	}

	go func() {
		defer close(jobs)

		for _, summary := range containers {
			select {
			case jobs <- summary:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	return results
}

func (collector *Collector) observeContainer(
	ctx context.Context,
	summary container.Summary,
) (containerObservation, error) {
	statsResult, err := collector.dockerClient.ContainerStats(ctx, summary.ID, client.ContainerStatsOptions{
		Stream:                false,
		IncludePreviousSample: false,
	})
	if err != nil {
		return containerObservation{}, err
	}

	stats, decodeErr := decodeContainerStats(statsResult.Body)
	closeErr := statsResult.Body.Close()
	if decodeErr != nil {
		return containerObservation{}, decodeErr
	}
	if closeErr != nil {
		return containerObservation{}, fmt.Errorf("close Docker container stats: %w", closeErr)
	}

	current := rawDockerCounters(stats)
	previous, hasPrevious := collector.containers[summary.ID]
	metric := protocol.ContainerMetrics{
		ContainerID: sanitize(summary.ID, 128),
		Runtime:     "docker",
		Name:        containerName(summary),
		State:       sanitize(string(summary.State), 64),
		CPU: protocol.ContainerCPUMetrics{
			ThrottledSecondsTotal: float64(stats.CPUStats.ThrottlingData.ThrottledTime) / float64(time.Second),
			ThrottledPeriodsTotal: stats.CPUStats.ThrottlingData.ThrottledPeriods,
		},
		Memory: containerMemory(stats.MemoryStats),
		PIDs: protocol.ContainerPIDMetrics{
			Current: stats.PidsStats.Current,
			Limit:   stats.PidsStats.Limit,
		},
	}
	if stats.PidsStats.Current == 0 && stats.NumProcs > 0 {
		metric.PIDs.Current = uint64(stats.NumProcs)
	}

	if hasPrevious {
		metric.CPU.UsagePercent = containerCPUPercent(previous, current)
		metric.Storage = protocol.ContainerStorageMetrics{
			ReadBytesPerSecond:       containerRate(previous.readBytes, current.readBytes, previous.readAt, current.readAt),
			WriteBytesPerSecond:      containerRate(previous.writeBytes, current.writeBytes, previous.readAt, current.readAt),
			ReadOperationsPerSecond:  containerRate(previous.readOperations, current.readOperations, previous.readAt, current.readAt),
			WriteOperationsPerSecond: containerRate(previous.writeOperations, current.writeOperations, previous.readAt, current.readAt),
		}
		metric.Network = protocol.ContainerNetworkMetrics{
			RXBytesPerSecond:   containerRate(previous.rxBytes, current.rxBytes, previous.readAt, current.readAt),
			TXBytesPerSecond:   containerRate(previous.txBytes, current.txBytes, previous.readAt, current.readAt),
			RXPacketsPerSecond: containerRate(previous.rxPackets, current.rxPackets, previous.readAt, current.readAt),
			TXPacketsPerSecond: containerRate(previous.txPackets, current.txPackets, previous.readAt, current.readAt),
		}
	}

	return containerObservation{metric: metric, raw: current}, nil
}

func decodeContainerStats(reader io.Reader) (container.StatsResponse, error) {
	limited := &io.LimitedReader{R: reader, N: maxContainerStats + 1}
	decoder := json.NewDecoder(limited)

	var stats container.StatsResponse
	if err := decoder.Decode(&stats); err != nil {
		return container.StatsResponse{}, fmt.Errorf("decode Docker container stats: %w", err)
	}
	if limited.N <= 0 {
		return container.StatsResponse{}, fmt.Errorf("Docker container stats exceed %d bytes", maxContainerStats)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return container.StatsResponse{}, errors.New("Docker container stats contain multiple JSON values")
		}
		return container.StatsResponse{}, fmt.Errorf("finish Docker container stats: %w", err)
	}

	return stats, nil
}

func rawDockerCounters(stats container.StatsResponse) rawContainer {
	readAt := stats.Read
	if readAt.IsZero() {
		readAt = time.Now().UTC()
	}

	result := rawContainer{
		readAt:       readAt,
		cpuTotal:     stats.CPUStats.CPUUsage.TotalUsage,
		systemCPU:    stats.CPUStats.SystemUsage,
		onlineCPUs:   stats.CPUStats.OnlineCPUs,
		cpuUnitNanos: 1,
	}
	if result.onlineCPUs == 0 {
		result.onlineCPUs = uint32(len(stats.CPUStats.CPUUsage.PercpuUsage))
	}
	if result.onlineCPUs == 0 {
		result.onlineCPUs = 1
	}
	if strings.EqualFold(stats.OSType, "windows") {
		result.cpuUnitNanos = 100
	}

	for _, entry := range stats.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			result.readBytes += entry.Value
		case "write":
			result.writeBytes += entry.Value
		}
	}
	for _, entry := range stats.BlkioStats.IoServicedRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			result.readOperations += entry.Value
		case "write":
			result.writeOperations += entry.Value
		}
	}
	if result.readBytes == 0 {
		result.readBytes = stats.StorageStats.ReadSizeBytes
	}
	if result.writeBytes == 0 {
		result.writeBytes = stats.StorageStats.WriteSizeBytes
	}
	if result.readOperations == 0 {
		result.readOperations = stats.StorageStats.ReadCountNormalized
	}
	if result.writeOperations == 0 {
		result.writeOperations = stats.StorageStats.WriteCountNormalized
	}

	for _, network := range stats.Networks {
		result.rxBytes += network.RxBytes
		result.txBytes += network.TxBytes
		result.rxPackets += network.RxPackets
		result.txPackets += network.TxPackets
	}

	return result
}

func containerMemory(stats container.MemoryStats) protocol.ContainerMemoryMetrics {
	used := stats.Usage
	if stats.PrivateWorkingSet > 0 {
		used = stats.PrivateWorkingSet
	} else {
		inactive := stats.Stats["inactive_file"]
		if inactive == 0 {
			inactive = stats.Stats["total_inactive_file"]
		}
		if inactive < used {
			used -= inactive
		}
	}

	cache := stats.Stats["cache"]
	if cache == 0 {
		cache = stats.Stats["file"]
	}
	usedPercent := 0.0
	if stats.Limit > 0 {
		usedPercent = percent(float64(used) / float64(stats.Limit) * 100)
	}

	return protocol.ContainerMemoryMetrics{
		UsedBytes:      used,
		LimitBytes:     stats.Limit,
		UsedPercent:    usedPercent,
		CacheBytes:     cache,
		OOMEventsTotal: stats.Stats["oom_kill"],
	}
}

func containerCPUPercent(previous, current rawContainer) float64 {
	containerDelta := counterDeltaUint(previous.cpuTotal, current.cpuTotal)
	systemDelta := counterDeltaUint(previous.systemCPU, current.systemCPU)
	if systemDelta > 0 {
		return cpuPercent(
			float64(containerDelta) / float64(systemDelta) * float64(current.onlineCPUs) * 100,
		)
	}

	interval := current.readAt.Sub(previous.readAt)
	if interval <= 0 {
		return 0
	}

	return cpuPercent(
		float64(containerDelta) * float64(current.cpuUnitNanos) / float64(interval.Nanoseconds()) * 100,
	)
}

func containerRate(previous, current uint64, previousAt, currentAt time.Time) float64 {
	interval := currentAt.Sub(previousAt).Seconds()

	return rate(previous, current, interval)
}

func containerName(summary container.Summary) string {
	if len(summary.Names) == 0 {
		return ""
	}

	return sanitize(strings.TrimPrefix(summary.Names[0], "/"), 256)
}
