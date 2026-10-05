// Package metrics collects bounded resource-usage samples from cumulative OS counters.
package metrics

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/moby/moby/client"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/FroZor/loreva-agent/internal/dockerapi"
	"github.com/FroZor/loreva-agent/internal/observation"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/specifications"
)

const (
	maxProcessCandidates = 1024
	maxProcessItems      = 256
)

// Snapshot contains one measured interval and the scope visible to the agent.
type Snapshot struct {
	ObservedAt       time.Time
	Interval         time.Duration
	ObservationScope string
	Node             protocol.NodeMetrics
	Containers       []protocol.ContainerMetrics
	CollectionIssues []protocol.CollectionIssue
}

type rawCounters struct {
	at        time.Time
	cpuTotal  []cpu.TimesStat
	cpuPerCPU []cpu.TimesStat
	disk      map[string]disk.IOCountersStat
	network   map[string]gnet.IOCountersStat
	swap      *mem.SwapMemoryStat
	processes map[processKey]rawProcess
	issues    []protocol.CollectionIssue
}

type processKey struct {
	pid       int32
	startedMS int64
}

type rawProcess struct {
	cpuSeconds float64
	readBytes  uint64
	writeBytes uint64
}

type rawContainer struct {
	readAt          time.Time
	cpuTotal        uint64
	systemCPU       uint64
	onlineCPUs      uint32
	cpuUnitNanos    uint64
	cpuLimitCores   float64
	limitsReadAt    time.Time
	readBytes       uint64
	writeBytes      uint64
	readOperations  uint64
	writeOperations uint64
	rxBytes         uint64
	txBytes         uint64
	rxPackets       uint64
	txPackets       uint64
}

type processObservation struct {
	metric  protocol.ProcessMetric
	raw     rawProcess
	status  string
	partial bool
}

type gpuDevice struct {
	id       string
	vendorID string
}

// Collector owns the previous counters required to calculate interval rates.
type Collector struct {
	mu               sync.Mutex
	previous         rawCounters
	observationScope string
	gpus             []gpuDevice
	nvidiaSMIPath    string
	dockerClient     *client.Client
	containers       map[string]rawContainer
	nextDockerProbe  time.Time
	startupIssues    []protocol.CollectionIssue
}

// NewCollector primes counter baselines without delaying the caller.
func NewCollector(ctx context.Context) *Collector {
	environment := observation.Detect(ctx)
	collector := &Collector{observationScope: environment.Scope}
	collector.containers = make(map[string]rawContainer)
	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		collector.startupIssues = append(collector.startupIssues, issue("containers.docker", classifyError(err)))
	} else if err := dockerapi.ValidateEndpoint(dockerClient.DaemonHost()); err != nil {
		collector.startupIssues = append(collector.startupIssues, issue("containers.docker", "insecure_endpoint"))
		if closeErr := dockerClient.Close(); closeErr != nil {
			collector.startupIssues = append(collector.startupIssues, issue("containers.docker", "cleanup_failed"))
		}
	} else {
		collector.dockerClient = dockerClient
	}

	snapshot, err := specifications.Collect(ctx)
	if err == nil {
		collector.observationScope = snapshot.ObservationScope
		collector.gpus = make([]gpuDevice, 0, len(snapshot.Specifications.GPUs))
		for _, gpu := range snapshot.Specifications.GPUs {
			collector.gpus = append(collector.gpus, gpuDevice{id: gpu.ID, vendorID: gpu.VendorID})
		}
		collector.nvidiaSMIPath = findNVIDIASMI(collector.gpus)
	}

	collector.previous = collectRawCounters(ctx, time.Now().UTC(), nil)

	return collector
}

// Close releases idle runtime-client resources.
func (collector *Collector) Close() error {
	if collector.dockerClient == nil {
		return nil
	}

	return collector.dockerClient.Close()
}

// Collect returns a best-effort sample calculated from the preceding counters.
func (collector *Collector) Collect(ctx context.Context) (Snapshot, error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	observedAt := time.Now().UTC()
	current := collectRawCounters(ctx, observedAt, collector.previous.processes)
	interval := observedAt.Sub(collector.previous.at)
	if collector.previous.at.IsZero() || interval <= 0 {
		collector.previous = current
		return Snapshot{}, errors.New("metrics counter baseline is not ready")
	}

	issues := append([]protocol.CollectionIssue(nil), collector.startupIssues...)
	issues = append(issues, current.issues...)
	node := protocol.NodeMetrics{
		CPU:       collectCPU(ctx, collector.previous, current, &issues),
		Memory:    collectMemory(collector.previous.swap, current.swap, interval, &issues),
		Storage:   collectStorage(ctx, collector.previous.disk, current.disk, interval, &issues),
		Network:   collectNetwork(collector.previous.network, current.network, interval, &issues),
		GPUs:      collector.collectGPUs(ctx, &issues),
		Processes: collectProcesses(ctx, collector.previous.processes, interval, &current, &issues),
	}
	containers := collector.collectContainers(ctx, &issues)

	collector.previous = current

	return Snapshot{
		ObservedAt:       observedAt,
		Interval:         interval,
		ObservationScope: collector.observationScope,
		Node:             node,
		Containers:       containers,
		CollectionIssues: deduplicateIssues(issues),
	}, nil
}

func collectRawCounters(ctx context.Context, observedAt time.Time, previousProcesses map[processKey]rawProcess) rawCounters {
	counters := rawCounters{
		at:        observedAt,
		disk:      make(map[string]disk.IOCountersStat),
		network:   make(map[string]gnet.IOCountersStat),
		processes: previousProcesses,
	}

	var err error
	counters.cpuTotal, err = cpu.TimesWithContext(ctx, false)
	if err != nil {
		counters.issues = append(counters.issues, issue("cpu", classifyError(err)))
	}
	counters.cpuPerCPU, err = cpu.TimesWithContext(ctx, true)
	if err != nil {
		counters.issues = append(counters.issues, issue("cpu.logical", classifyError(err)))
	}
	counters.disk, err = disk.IOCountersWithContext(ctx)
	if err != nil {
		counters.issues = append(counters.issues, issue("storage.devices", classifyError(err)))
	}

	networkCounters, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		counters.issues = append(counters.issues, issue("network", classifyError(err)))
	} else {
		for _, networkCounter := range networkCounters {
			counters.network[networkCounter.Name] = networkCounter
		}
	}

	counters.swap, err = mem.SwapMemoryWithContext(ctx)
	if err != nil {
		counters.issues = append(counters.issues, issue("memory.swap", classifyError(err)))
	}

	return counters
}

func collectCPU(
	ctx context.Context,
	previous, current rawCounters,
	issues *[]protocol.CollectionIssue,
) protocol.CPUMetrics {
	result := protocol.CPUMetrics{Logical: []protocol.LogicalProcessorMetrics{}}

	if len(previous.cpuTotal) == 0 || len(current.cpuTotal) == 0 {
		*issues = append(*issues, issue("cpu", "collection_failed"))
	} else {
		result.Total = cpuUtilization(previous.cpuTotal[0], current.cpuTotal[0])
	}

	if len(previous.cpuPerCPU) == 0 || len(previous.cpuPerCPU) != len(current.cpuPerCPU) {
		*issues = append(*issues, issue("cpu.logical", "collection_failed"))
	} else {
		result.Logical = make([]protocol.LogicalProcessorMetrics, 0, len(current.cpuPerCPU))
		for index, currentCPU := range current.cpuPerCPU {
			utilization := cpuUtilization(previous.cpuPerCPU[index], currentCPU)
			result.Logical = append(result.Logical, protocol.LogicalProcessorMetrics{
				ID:            "cpu:" + strconv.Itoa(index),
				UsagePercent:  utilization.UsagePercent,
				UserPercent:   utilization.UserPercent,
				SystemPercent: utilization.SystemPercent,
				IOWaitPercent: utilization.IOWaitPercent,
				StealPercent:  utilization.StealPercent,
				IdlePercent:   utilization.IdlePercent,
			})
		}
	}

	average, err := load.AvgWithContext(ctx)
	if err == nil {
		result.LoadAverage = &protocol.LoadAverageMetrics{
			OneMinute:      finiteNonNegative(average.Load1),
			FiveMinutes:    finiteNonNegative(average.Load5),
			FifteenMinutes: finiteNonNegative(average.Load15),
		}
	}

	return result
}

func cpuUtilization(previous, current cpu.TimesStat) protocol.CPUUtilizationMetrics {
	total := counterDelta(cpuTotal(previous), cpuTotal(current))
	if total <= 0 {
		return protocol.CPUUtilizationMetrics{}
	}

	user := counterDelta(previous.User+previous.Nice, current.User+current.Nice) / total * 100
	system := counterDelta(
		previous.System+previous.Irq+previous.Softirq,
		current.System+current.Irq+current.Softirq,
	) / total * 100
	iowait := counterDelta(previous.Iowait, current.Iowait) / total * 100
	steal := counterDelta(previous.Steal, current.Steal) / total * 100
	idle := counterDelta(previous.Idle, current.Idle) / total * 100
	usage := 100 - idle - iowait

	return protocol.CPUUtilizationMetrics{
		UsagePercent:  percent(usage),
		UserPercent:   percent(user),
		SystemPercent: percent(system),
		IOWaitPercent: percent(iowait),
		StealPercent:  percent(steal),
		IdlePercent:   percent(idle),
	}
}

func cpuTotal(value cpu.TimesStat) float64 {
	return value.User + value.Nice + value.System + value.Idle + value.Iowait + value.Irq + value.Softirq + value.Steal
}

func collectMemory(
	previousSwap, currentSwap *mem.SwapMemoryStat,
	interval time.Duration,
	issues *[]protocol.CollectionIssue,
) protocol.MemoryMetrics {
	result := protocol.MemoryMetrics{}

	memory, err := mem.VirtualMemory()
	if err != nil {
		*issues = append(*issues, issue("memory", classifyError(err)))
	} else {
		result.UsedBytes = memory.Used
		result.AvailableBytes = memory.Available
		result.CachedBytes = memory.Cached
		result.BuffersBytes = memory.Buffers
	}

	if currentSwap == nil {
		*issues = append(*issues, issue("memory.swap", "collection_failed"))
		return result
	}

	result.SwapUsedBytes = currentSwap.Used
	if previousSwap == nil {
		return result
	}

	seconds := interval.Seconds()
	if seconds <= 0 {
		return result
	}
	if previousSwap.PgFault != 0 || currentSwap.PgFault != 0 {
		value := float64(counterDeltaUint(previousSwap.PgFault, currentSwap.PgFault)) / seconds
		result.PageFaultsPerSecond = &value
	}
	if previousSwap.PgMajFault != 0 || currentSwap.PgMajFault != 0 {
		value := float64(counterDeltaUint(previousSwap.PgMajFault, currentSwap.PgMajFault)) / seconds
		result.MajorPageFaultsPerSecond = &value
	}

	return result
}

func collectStorage(
	ctx context.Context,
	previous, current map[string]disk.IOCountersStat,
	interval time.Duration,
	issues *[]protocol.CollectionIssue,
) protocol.StorageMetrics {
	result := protocol.StorageMetrics{
		Devices:     []protocol.StorageDeviceMetrics{},
		Filesystems: []protocol.FilesystemMetrics{},
	}
	seconds := interval.Seconds()
	if seconds <= 0 {
		return result
	}

	deviceNames := make([]string, 0, len(current))
	for name := range current {
		deviceNames = append(deviceNames, name)
	}
	sort.Strings(deviceNames)

	for _, name := range deviceNames {
		currentDevice := current[name]
		previousDevice, exists := previous[name]
		if !exists {
			continue
		}

		result.Devices = append(result.Devices, protocol.StorageDeviceMetrics{
			DeviceID:                 "storage:" + sanitizeID(name),
			ReadBytesPerSecond:       rate(previousDevice.ReadBytes, currentDevice.ReadBytes, seconds),
			WriteBytesPerSecond:      rate(previousDevice.WriteBytes, currentDevice.WriteBytes, seconds),
			ReadOperationsPerSecond:  rate(previousDevice.ReadCount, currentDevice.ReadCount, seconds),
			WriteOperationsPerSecond: rate(previousDevice.WriteCount, currentDevice.WriteCount, seconds),
			IOUtilizationPercent:     percent(float64(counterDeltaUint(previousDevice.IoTime, currentDevice.IoTime)) / interval.Seconds() / 10),
			QueueDepth:               float64(currentDevice.IopsInProgress),
		})
	}

	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		*issues = append(*issues, issue("storage.filesystems", classifyError(err)))
		return result
	}

	seen := make(map[string]struct{}, len(partitions))
	unreadable := 0
	for _, partition := range partitions {
		if _, exists := seen[partition.Mountpoint]; exists {
			continue
		}
		seen[partition.Mountpoint] = struct{}{}

		usage, err := disk.UsageWithContext(ctx, hostPath(partition.Mountpoint))
		if err != nil {
			unreadable++
			continue
		}

		filesystem := protocol.FilesystemMetrics{
			FilesystemID:   "filesystem:" + sanitizeID(partition.Device),
			Mountpoint:     sanitize(partition.Mountpoint, 1024),
			UsedBytes:      usage.Used,
			AvailableBytes: usage.Free,
			UsedPercent:    percent(usage.UsedPercent),
		}
		if usage.InodesTotal > 0 {
			value := percent(usage.InodesUsedPercent)
			filesystem.InodesUsedPercent = &value
		}

		result.Filesystems = append(result.Filesystems, filesystem)
	}

	switch {
	case len(result.Filesystems) == 0:
		*issues = append(*issues, issue("storage.filesystems", "not_available"))
	case unreadable > 0:
		*issues = append(*issues, issue("storage.filesystems", "partial"))
	}

	return result
}

func collectNetwork(
	previous, current map[string]gnet.IOCountersStat,
	interval time.Duration,
	issues *[]protocol.CollectionIssue,
) []protocol.NetworkMetrics {
	seconds := interval.Seconds()
	if seconds <= 0 {
		return []protocol.NetworkMetrics{}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		*issues = append(*issues, issue("network", classifyError(err)))
	}
	interfaceIDs := make(map[string]string, len(interfaces))
	for _, networkInterface := range interfaces {
		interfaceIDs[networkInterface.Name] = "network:" + strconv.Itoa(networkInterface.Index)
	}

	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]protocol.NetworkMetrics, 0, len(names))
	for _, name := range names {
		currentInterface := current[name]
		previousInterface, exists := previous[name]
		if !exists {
			continue
		}

		interfaceID := interfaceIDs[name]
		if interfaceID == "" {
			interfaceID = "network-name:" + sanitizeID(name)
		}

		result = append(result, protocol.NetworkMetrics{
			InterfaceID:        interfaceID,
			RXBytesPerSecond:   rate(previousInterface.BytesRecv, currentInterface.BytesRecv, seconds),
			TXBytesPerSecond:   rate(previousInterface.BytesSent, currentInterface.BytesSent, seconds),
			RXPacketsPerSecond: rate(previousInterface.PacketsRecv, currentInterface.PacketsRecv, seconds),
			TXPacketsPerSecond: rate(previousInterface.PacketsSent, currentInterface.PacketsSent, seconds),
			RXErrorsPerSecond:  rate(previousInterface.Errin, currentInterface.Errin, seconds),
			TXErrorsPerSecond:  rate(previousInterface.Errout, currentInterface.Errout, seconds),
			RXDropsPerSecond:   rate(previousInterface.Dropin, currentInterface.Dropin, seconds),
			TXDropsPerSecond:   rate(previousInterface.Dropout, currentInterface.Dropout, seconds),
		})
	}

	return result
}

func collectProcesses(
	ctx context.Context,
	previous map[processKey]rawProcess,
	interval time.Duration,
	current *rawCounters,
	issues *[]protocol.CollectionIssue,
) protocol.ProcessMetrics {
	result := protocol.ProcessMetrics{Items: []protocol.ProcessMetric{}}
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		*issues = append(*issues, issue("processes", classifyError(err)))
		return result
	}

	result.Total = len(processes)
	sort.Slice(processes, func(left, right int) bool {
		return processes[left].Pid < processes[right].Pid
	})
	if len(processes) > maxProcessCandidates {
		processes = processes[:maxProcessCandidates]
		result.Truncated = true
	}

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

func counterDelta(previous, current float64) float64 {
	if current < previous {
		return 0
	}

	return current - previous
}

func counterDeltaUint(previous, current uint64) uint64 {
	if current < previous {
		return 0
	}

	return current - previous
}

func rate(previous, current uint64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}

	return finiteNonNegative(float64(counterDeltaUint(previous, current)) / seconds)
}

func percent(value float64) float64 {
	value = finiteNonNegative(value)
	if value > 100 {
		return 100
	}

	return value
}

func cpuPercent(value float64) float64 {
	value = finiteNonNegative(value)
	if value > 409600 {
		return 409600
	}

	return value
}

func finiteNonNegative(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}

	return value
}

func issue(component, code string) protocol.CollectionIssue {
	return protocol.CollectionIssue{Component: component, Code: code}
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.Is(err, os.ErrNotExist):
		return "not_available"
	default:
		return "collection_failed"
	}
}

func deduplicateIssues(issues []protocol.CollectionIssue) []protocol.CollectionIssue {
	seen := make(map[protocol.CollectionIssue]struct{}, len(issues))
	result := make([]protocol.CollectionIssue, 0, len(issues))

	for _, collectionIssue := range issues {
		if collectionIssue.Component == "" || collectionIssue.Code == "" {
			continue
		}
		if _, exists := seen[collectionIssue]; exists {
			continue
		}

		seen[collectionIssue] = struct{}{}
		result = append(result, collectionIssue)
	}

	sort.Slice(result, func(left, right int) bool {
		if result[left].Component == result[right].Component {
			return result[left].Code < result[right].Code
		}
		return result[left].Component < result[right].Component
	})

	return result
}

func sanitize(value string, limit int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	if len(value) > limit {
		for limit > 0 && !utf8.RuneStart(value[limit]) {
			limit--
		}
		value = value[:limit]
	}

	return value
}

func sanitizeID(value string) string {
	value = sanitize(value, 128)

	return strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(value)
}

// hostPath maps a host mount point into this process's file system. When the
// agent runs in a container with the host root mounted read-only (HOST_ROOT,
// the same variable gopsutil uses for HOST_PROC and friends), mount points
// listed from the host's /proc are reachable only below that root.
func hostPath(mountpoint string) string {
	root := os.Getenv("HOST_ROOT")
	if root == "" || !filepath.IsAbs(mountpoint) || filepath.Clean(mountpoint) != mountpoint {
		return mountpoint
	}

	return filepath.Join(root, mountpoint)
}
