// Package metrics collects bounded resource-usage samples from cumulative OS counters.
package metrics

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/FroZor/loreva-agent/internal/dockerapi"
	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/hostnet"
	"github.com/FroZor/loreva-agent/internal/observation"
	"github.com/FroZor/loreva-agent/internal/procfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/specifications"
)

const (
	maxProcessItems = 256
	// maxNetworkInterfaces bounds the interfaces of one sample, as the
	// contract does; a Docker host has one veth interface per container.
	maxNetworkInterfaces = 256
)

// Snapshot contains one measured interval and the scope visible to the agent.
type Snapshot struct {
	ObservedAt       time.Time
	Interval         time.Duration
	ObservationScope string
	Node             protocol.NodeMetrics
	Containers       []protocol.ContainerMetrics
	CollectionIssues []protocol.CollectionIssue
	// ContainersFresh is false when Containers repeats the last reading
	// because containers are read less often than the node.
	ContainersFresh bool
	// ContainerKeys maps a container ID to its stable identity: the compose
	// project, service and replica, or the container name. A recreated
	// container keeps its identity.
	ContainerKeys map[string]string
	// Interfaces maps the ID of each physical or primary interface to its
	// name; bridges, veth pairs, loopback and tunnels are left out.
	Interfaces map[string]string
	// Disks lists the IDs of whole block devices; partitions, loop, zram
	// and device-mapper devices are left out.
	Disks []string
	// ContainerEvents are the lifecycle changes Docker reported since the
	// previous sample.
	ContainerEvents []ContainerEvent
}

// Demand is what readers are watching right now. The collector reads the
// costly parts only while someone looks at them.
type Demand struct {
	// Processes is how many processes a reader shows; zero skips the
	// process table.
	Processes int
	// Containers reads containers on every sample instead of every
	// idleContainerInterval.
	Containers bool
	// Detail reads GPUs and sensors on every sample.
	Detail bool
}

const (
	// idleContainerInterval is how often containers are read while nobody
	// watches them; their history averages stay exact because they come
	// from cumulative counters.
	idleContainerInterval = 5 * time.Second
	idleGPUInterval       = 5 * time.Second
	idleSensorInterval    = 10 * time.Second
	filesystemInterval    = 10 * time.Second
	raidInterval          = 30 * time.Second
)

type rawCounters struct {
	at        time.Time
	cpuTotal  []cpu.TimesStat
	cpuPerCPU []cpu.TimesStat
	disk      map[string]disk.IOCountersStat
	network   map[string]gnet.IOCountersStat
	swap      *mem.SwapMemoryStat
	kernel    *kernelCounters
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
	hasIO      bool
	identity   *procfs.Identity
}

type rawContainer struct {
	readAt          time.Time
	cpuTotal        uint64
	systemCPU       uint64
	onlineCPUs      uint32
	cpuUnitNanos    uint64
	cpuLimitCores   float64
	readBytes       uint64
	writeBytes      uint64
	readOperations  uint64
	writeOperations uint64
	rxBytes         uint64
	txBytes         uint64
	rxPackets       uint64
	txPackets       uint64
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
	users            userCache

	// Cached readings of the parts read less often than every sample.
	containerCache   []protocol.ContainerMetrics
	containerKeys    map[string]string
	containersReadAt time.Time
	gpuCache         []protocol.GPUMetrics
	gpuReadAt        time.Time
	sensorCache      []protocol.SensorMetrics
	sensorsReadAt    time.Time
	filesystemCache  []protocol.FilesystemMetrics
	filesystemIssues []protocol.CollectionIssue
	filesystemsAt    time.Time
	raidCache        []protocol.RAIDMetrics
	raidReadAt       time.Time
	docker           *dockerWatch
	listed           []container.Summary
	listedAt         time.Time
	inspectMu        sync.Mutex
	inspected        map[string]inspectedContainer
	// cgroupRoot is the host's cgroup v2 mount, or "" when containers are
	// read through the Docker stats API.
	cgroupRoot string
	hostMemory uint64
}

// NewCollector primes counter baselines without delaying the caller.
func NewCollector(ctx context.Context) *Collector {
	environment := observation.Detect(ctx)
	collector := &Collector{observationScope: environment.Scope}
	collector.containers = make(map[string]rawContainer)
	collector.inspected = make(map[string]inspectedContainer)
	collector.docker = newDockerWatch()
	collector.cgroupRoot = findCgroupRoot()
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
		go collector.docker.run(ctx, dockerClient)
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
// demand decides which costly parts are read on this sample.
func (collector *Collector) Collect(ctx context.Context, demand Demand) (Snapshot, error) {
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
		CPU:     collectCPU(ctx, collector.previous, current, &issues),
		Memory:  collectMemory(current.swap, &issues),
		Storage: collectDevices(collector.previous.disk, current.disk, interval),
		GPUs:    collector.cachedGPUs(ctx, observedAt, demand.Detail, &issues),
		Sensors: collector.cachedSensors(observedAt, demand.Detail),
	}
	network, interfaceNames := collectNetwork(collector.previous.network, current.network, interval, &issues)
	node.Network = network
	node.Storage.Filesystems = collector.cachedFilesystems(ctx, observedAt, &issues)
	node.Storage.RAID = collector.cachedRAID(observedAt)
	if demand.Processes > 0 {
		node.Processes = collectProcesses(ctx, collector.previous.processes, interval, &current, &collector.users, &issues)
	} else {
		// Without a reader the process table is not read, so the next
		// reader starts with fresh baselines.
		node.Processes = protocol.ProcessMetrics{Items: []protocol.ProcessMetric{}}
		current.processes = nil
	}
	applyKernelRates(collector.previous.kernel, current.kernel, interval, &node.CPU, &node.Memory)
	node.TCP = tcpMetrics(collector.previous.kernel, current.kernel, interval)
	collector.hostMemory = node.Memory.TotalBytes

	fresh := demand.Containers || collector.containersReadAt.IsZero() ||
		observedAt.Sub(collector.containersReadAt) >= idleContainerInterval-idleSlack
	if fresh {
		collector.containerCache = collector.collectContainers(ctx, &issues)
		collector.containersReadAt = observedAt
	}

	collector.previous = current

	return Snapshot{
		ObservedAt:       observedAt,
		Interval:         interval,
		ObservationScope: collector.observationScope,
		Node:             node,
		Containers:       collector.containerCache,
		CollectionIssues: deduplicateIssues(issues),
		ContainersFresh:  fresh,
		ContainerKeys:    collector.containerKeys,
		Interfaces:       keyInterfaces(interfaceNames),
		Disks:            keyDisks(node.Storage.Devices),
		ContainerEvents:  collector.docker.takeEvents(),
	}, nil
}

// idleSlack lets a reading that is due within the next sample count as due,
// so a 1-second ticker does not stretch a 5-second interval to 6.
const idleSlack = 500 * time.Millisecond

// onlineCPUs is the number of logical CPUs of the node.
func (collector *Collector) onlineCPUs() uint32 {
	if count := len(collector.previous.cpuPerCPU); count > 0 {
		return uint32(count)
	}

	return uint32(max(runtime.NumCPU(), 1))
}

func due(last, now time.Time, every time.Duration) bool {
	return last.IsZero() || now.Sub(last) >= every-idleSlack
}

func (collector *Collector) cachedGPUs(ctx context.Context, now time.Time, detail bool, issues *[]protocol.CollectionIssue) []protocol.GPUMetrics {
	if detail || due(collector.gpuReadAt, now, idleGPUInterval) {
		collector.gpuCache = collector.collectGPUs(ctx, issues)
		collector.gpuReadAt = now
	}

	return collector.gpuCache
}

func (collector *Collector) cachedSensors(now time.Time, detail bool) []protocol.SensorMetrics {
	if detail || due(collector.sensorsReadAt, now, idleSensorInterval) {
		collector.sensorCache = collectSensors()
		collector.sensorsReadAt = now
	}

	return collector.sensorCache
}

func (collector *Collector) cachedFilesystems(ctx context.Context, now time.Time, issues *[]protocol.CollectionIssue) []protocol.FilesystemMetrics {
	if due(collector.filesystemsAt, now, filesystemInterval) {
		var found []protocol.CollectionIssue
		collector.filesystemCache = collectFilesystems(ctx, &found)
		collector.filesystemIssues = found
		collector.filesystemsAt = now
	}
	*issues = append(*issues, collector.filesystemIssues...)

	return collector.filesystemCache
}

func (collector *Collector) cachedRAID(now time.Time) []protocol.RAIDMetrics {
	if due(collector.raidReadAt, now, raidInterval) {
		collector.raidCache = collectRAID()
		collector.raidReadAt = now
	}

	return collector.raidCache
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

	var networkCounters []gnet.IOCountersStat
	if path := hostnet.NetPath("dev"); path != "" {
		networkCounters, err = gnet.IOCountersByFileWithContext(ctx, true, path)
	} else {
		networkCounters, err = gnet.IOCountersWithContext(ctx, true)
	}
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

	if kernel, ok := readKernelCounters(); ok {
		counters.kernel = &kernel
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

	if len(previous.cpuPerCPU) == 0 || len(current.cpuPerCPU) == 0 {
		*issues = append(*issues, issue("cpu.logical", "collection_failed"))
	} else {
		// A processor is matched by its number, not its position: the list
		// skips offline processors and changes when one goes on or off line.
		before := make(map[string]cpu.TimesStat, len(previous.cpuPerCPU))
		for _, previousCPU := range previous.cpuPerCPU {
			before[previousCPU.CPU] = previousCPU
		}

		result.Logical = make([]protocol.LogicalProcessorMetrics, 0, len(current.cpuPerCPU))
		for index, currentCPU := range current.cpuPerCPU {
			previousCPU, exists := before[currentCPU.CPU]
			if !exists {
				continue
			}

			utilization := cpuUtilization(previousCPU, currentCPU)
			result.Logical = append(result.Logical, protocol.LogicalProcessorMetrics{
				ID:            logicalCPUID(currentCPU.CPU, index),
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

func collectMemory(swap *mem.SwapMemoryStat, issues *[]protocol.CollectionIssue) protocol.MemoryMetrics {
	result := protocol.MemoryMetrics{}

	memory, err := mem.VirtualMemory()
	if err != nil {
		*issues = append(*issues, issue("memory", classifyError(err)))
	} else {
		result.TotalBytes = memory.Total
		result.UsedBytes = memory.Used
		result.AvailableBytes = memory.Available
		result.CachedBytes = memory.Cached
		result.BuffersBytes = memory.Buffers
	}

	if swap == nil {
		*issues = append(*issues, issue("memory.swap", "collection_failed"))
		return result
	}
	result.SwapTotalBytes = swap.Total
	result.SwapUsedBytes = swap.Used

	return result
}

// collectDevices returns the block-device rates; file systems and RAID are
// read on their own schedule.
func collectDevices(
	previous, current map[string]disk.IOCountersStat,
	interval time.Duration,
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
			// The average queue over the interval, as aqu-sz of iostat:
			// weighted I/O milliseconds per elapsed millisecond.
			QueueDepth:      float64(counterDeltaUint(previousDevice.WeightedIO, currentDevice.WeightedIO)) / (seconds * 1000),
			ReadBytesTotal:  currentDevice.ReadBytes,
			WriteBytesTotal: currentDevice.WriteBytes,
		})
	}

	return result
}

func collectFilesystems(ctx context.Context, issues *[]protocol.CollectionIssue) []protocol.FilesystemMetrics {
	result := []protocol.FilesystemMetrics{}
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		*issues = append(*issues, issue("storage.filesystems", classifyError(err)))
		return result
	}

	seen := make(map[string]struct{}, len(partitions))
	ids := make(map[string]int, len(partitions))
	unreadable := 0
	for _, partition := range partitions {
		if _, exists := seen[partition.Mountpoint]; exists {
			continue
		}
		seen[partition.Mountpoint] = struct{}{}

		usage, err := disk.UsageWithContext(ctx, hostfs.Root(partition.Mountpoint))
		if err != nil {
			unreadable++
			continue
		}

		// One device can be mounted several times (btrfs subvolumes, bind
		// mounts), so the mount point names the file system.
		filesystemID := "filesystem:" + sanitizeID(partition.Mountpoint)
		ids[filesystemID]++
		if count := ids[filesystemID]; count > 1 {
			filesystemID += ":" + strconv.Itoa(count)
		}

		filesystem := protocol.FilesystemMetrics{
			FilesystemID:   filesystemID,
			Mountpoint:     sanitize(partition.Mountpoint, 1024),
			Device:         sanitize(partition.Device, 1024),
			FilesystemType: sanitize(partition.Fstype, 64),
			TotalBytes:     usage.Total,
			UsedBytes:      usage.Used,
			AvailableBytes: usage.Free,
			UsedPercent:    percent(usage.UsedPercent),
		}
		if usage.InodesTotal > 0 {
			value := percent(usage.InodesUsedPercent)
			filesystem.InodesUsedPercent = &value
		}

		result = append(result, filesystem)
	}

	switch {
	case len(result) == 0:
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
) ([]protocol.NetworkMetrics, map[string]string) {
	seconds := interval.Seconds()
	if seconds <= 0 {
		return []protocol.NetworkMetrics{}, nil
	}

	interfaces, err := hostnet.Interfaces()
	if err != nil {
		*issues = append(*issues, issue("network", classifyError(err)))
	}
	interfaceIDs := make(map[string]string, len(interfaces))
	for _, networkInterface := range interfaces {
		interfaceIDs[networkInterface.Name] = networkInterface.ID()
	}

	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]protocol.NetworkMetrics, 0, min(len(names), maxNetworkInterfaces))
	reported := make(map[string]string, len(names))
	for _, name := range names {
		currentInterface := current[name]
		previousInterface, exists := previous[name]
		if !exists {
			continue
		}
		if len(result) == maxNetworkInterfaces {
			*issues = append(*issues, issue("network", "truncated"))
			break
		}

		interfaceID := interfaceIDs[name]
		if interfaceID == "" {
			interfaceID = "network-name:" + sanitizeID(name)
		}
		reported[interfaceID] = name

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
			RXBytesTotal:       currentInterface.BytesRecv,
			TXBytesTotal:       currentInterface.BytesSent,
		})
	}

	return result, reported
}

// logicalCPUID names a processor as the specifications do, "cpu:<number>",
// from its kernel name such as "cpu5"; index is the fallback for a name
// without a number.
func logicalCPUID(name string, index int) string {
	number, err := strconv.Atoi(strings.TrimPrefix(name, "cpu"))
	if err != nil || number < 0 {
		number = index
	}

	return "cpu:" + strconv.Itoa(number)
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
