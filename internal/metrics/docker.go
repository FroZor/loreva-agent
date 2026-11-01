package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
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

	// containerLimitsInterval bounds how long a container's CPU limit is
	// reused before Docker is asked again; limits change only on update.
	containerLimitsInterval = time.Minute
	// defaultCPUPeriod is the CFS period Docker applies when only a quota is set.
	defaultCPUPeriod = 100_000
	maxCPUSetSize    = 1 << 16
)

type containerObservation struct {
	metric        protocol.ContainerMetrics
	raw           rawContainer
	inspection    containerInspection
	limitsUnknown bool
}

// containerInspection is what the collector needs from container.inspect.
// It is read once per container start, not on every sample.
type containerInspection struct {
	known         bool
	cpuLimitCores float64
	pid           int
	// hostNetwork marks a container that shares the host's network, whose
	// traffic is the host's and is not counted for the container.
	hostNetwork bool
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

	now := time.Now()
	if collector.docker.needsList(now, collector.listedAt) {
		result, err := collector.dockerClient.ContainerList(ctx, client.ContainerListOptions{})
		if err != nil {
			collector.nextDockerProbe = now.Add(dockerProbeInterval)
			*issues = append(*issues, issue("containers.docker", classifyError(err)))
			return []protocol.ContainerMetrics{}
		}
		collector.listed = result.Items
		collector.listedAt = now
	}
	collector.nextDockerProbe = time.Time{}
	collector.inspectMu.Lock()
	for id := range collector.docker.takeChanged() {
		delete(collector.inspected, id)
	}
	collector.inspectMu.Unlock()

	containers := collector.listed
	truncated := false
	if len(containers) > maxContainers {
		containers = containers[:maxContainers]
		truncated = true
	}

	keys := make(map[string]string, len(containers))
	for _, summary := range containers {
		keys[sanitize(summary.ID, 128)] = ContainerKey(containerName(summary), composeLabels(summary.Labels))
	}
	collector.containerKeys = keys

	observations := make([]containerObservation, 0, len(containers))
	nextRaw := make(map[string]rawContainer, len(containers))
	partial := false
	limitsUnknown := false

	for collection := range collector.collectContainerObservations(ctx, containers) {
		if collection.err != nil {
			partial = true
			continue
		}
		limitsUnknown = limitsUnknown || collection.observation.limitsUnknown

		observations = append(observations, collection.observation)
		nextRaw[collection.summary.ID] = collection.observation.raw
	}

	collector.containers = nextRaw
	collector.inspectMu.Lock()
	listedIDs := keysByID(containers)
	for id := range collector.inspected {
		if _, listed := listedIDs[id]; !listed {
			delete(collector.inspected, id)
		}
	}
	collector.inspectMu.Unlock()
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
	if limitsUnknown {
		*issues = append(*issues, issue("containers.docker.limits", "partial"))
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
	inspection := collector.inspect(ctx, summary.ID)
	previous, hasPrevious := collector.containers[summary.ID]

	if collector.cgroupRoot != "" && inspection.pid > 0 {
		if reading, err := readContainerCgroup(ctx, collector.cgroupRoot, summary.ID, inspection.pid, !inspection.hostNetwork); err == nil {
			current := reading.raw(collector.onlineCPUs())
			current.cpuLimitCores = inspection.cpuLimitCores
			metric := containerMetric(summary, previous, hasPrevious, current)
			metric.CPU.ThrottledSecondsTotal = reading.throttledSeconds
			metric.CPU.ThrottledPeriodsTotal = reading.throttledPeriods
			metric.Memory = reading.memory(collector.hostMemory)
			metric.PIDs = protocol.ContainerPIDMetrics{Current: reading.pids, Limit: reading.pidsLimit}

			return containerObservation{metric: metric, raw: current, inspection: inspection, limitsUnknown: !inspection.known}, nil
		}
	}

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
	current.cpuLimitCores = inspection.cpuLimitCores

	metric := containerMetric(summary, previous, hasPrevious, current)
	metric.CPU.ThrottledSecondsTotal = float64(stats.CPUStats.ThrottlingData.ThrottledTime) / float64(time.Second)
	metric.CPU.ThrottledPeriodsTotal = stats.CPUStats.ThrottlingData.ThrottledPeriods
	metric.Memory = containerMemory(stats.MemoryStats)
	metric.PIDs = protocol.ContainerPIDMetrics{
		Current: stats.PidsStats.Current,
		Limit:   stats.PidsStats.Limit,
	}
	if stats.PidsStats.Current == 0 && stats.NumProcs > 0 {
		metric.PIDs.Current = uint64(stats.NumProcs)
	}

	return containerObservation{metric: metric, raw: current, inspection: inspection, limitsUnknown: !inspection.known}, nil
}

// containerMetric fills the identity and the rates of a container from two
// readings of its counters.
func containerMetric(summary container.Summary, previous rawContainer, hasPrevious bool, current rawContainer) protocol.ContainerMetrics {
	metric := protocol.ContainerMetrics{
		ContainerID: sanitize(summary.ID, 128),
		Runtime:     "docker",
		Name:        containerName(summary),
		State:       sanitize(string(summary.State), 64),
		CPU: protocol.ContainerCPUMetrics{
			OnlineCPUs: current.onlineCPUs,
			LimitCores: containerLimitCores(current),
		},
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

	return metric
}

// inspectedContainer is a cached inspection and when it was read.
type inspectedContainer struct {
	containerInspection
	readAt time.Time
}

func keysByID(containers []container.Summary) map[string]struct{} {
	result := make(map[string]struct{}, len(containers))
	for _, summary := range containers {
		result[summary.ID] = struct{}{}
	}

	return result
}

// inspect returns the container's limits, process and network mode. They
// are read once per container start; Docker events mark them stale, and a
// failed read is tried again after containerLimitsInterval.
func (collector *Collector) inspect(ctx context.Context, containerID string) containerInspection {
	collector.inspectMu.Lock()
	cached, found := collector.inspected[containerID]
	collector.inspectMu.Unlock()
	if found && (cached.known || time.Since(cached.readAt) < containerLimitsInterval) {
		return cached.containerInspection
	}

	result := inspectedContainer{readAt: time.Now()}
	inspection, err := collector.dockerClient.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err == nil && inspection.Container.HostConfig != nil {
		result.known = true
		result.cpuLimitCores = cpuLimitCores(inspection.Container.HostConfig.Resources)
		result.hostNetwork = inspection.Container.HostConfig.NetworkMode.IsHost()
		if inspection.Container.State != nil {
			result.pid = inspection.Container.State.Pid
		}
	}

	collector.inspectMu.Lock()
	collector.inspected[containerID] = result
	collector.inspectMu.Unlock()

	return result.containerInspection
}

// cpuLimitCores returns the most logical CPUs a container may use according
// to its CFS quota and cpuset, or 0 when neither limits it.
func cpuLimitCores(resources container.Resources) float64 {
	limit := 0.0
	switch {
	case resources.NanoCPUs > 0:
		limit = float64(resources.NanoCPUs) / 1e9
	case resources.CPUQuota > 0:
		period := resources.CPUPeriod
		if period <= 0 {
			period = defaultCPUPeriod
		}
		limit = float64(resources.CPUQuota) / float64(period)
	}

	cpus := cpusetSize(resources.CpusetCpus)
	if cpus > 0 && (limit == 0 || float64(cpus) < limit) {
		limit = float64(cpus)
	}

	return limit
}

// cpusetSize counts the CPUs in a cpuset list such as "0-3,8". It returns 0
// for an empty or malformed list.
func cpusetSize(list string) int {
	if list == "" {
		return 0
	}

	count := 0
	for _, part := range strings.Split(list, ",") {
		low, high, isRange := strings.Cut(part, "-")
		if !isRange {
			high = low
		}

		first, err := strconv.Atoi(low)
		if err != nil || first < 0 {
			return 0
		}
		last, err := strconv.Atoi(high)
		if err != nil || last < first || last-first >= maxCPUSetSize {
			return 0
		}

		count += last - first + 1
		if count > maxCPUSetSize {
			return 0
		}
	}

	return count
}

// containerLimitCores reports the CPU limit only when it is tighter than the
// CPUs the container can see anyway.
func containerLimitCores(raw rawContainer) *float64 {
	if raw.cpuLimitCores <= 0 || raw.cpuLimitCores >= float64(raw.onlineCPUs) {
		return nil
	}

	limit := raw.cpuLimitCores

	return &limit
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
