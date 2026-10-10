// Package specifications collects hardware visible to the agent process.
package specifications

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/hostnet"
	"github.com/FroZor/loreva-agent/internal/observation"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	issueCollectionFailed = "collection_failed"
	issueNotAvailable     = "not_available"
	issuePermissionDenied = "permission_denied"
	issueTruncated        = "truncated"
	issueTimeout          = "timeout"
	maxSpecificationsJSON = 480 * 1024
)

// Snapshot contains specifications and the scope in which they were observed.
type Snapshot struct {
	ObservationScope string
	Specifications   protocol.NodeSpecifications
}

// Collect returns a bounded best-effort hardware snapshot.
func Collect(ctx context.Context) (Snapshot, error) {
	system, scope, systemIssues, err := collectSystem(ctx)
	if err != nil {
		return Snapshot{}, err
	}

	cpuSpecifications, cpuIssues := collectCPU(ctx)
	memorySpecifications, memoryIssues := collectMemory(ctx)
	platform := collectPlatform(ctx)
	interfaces, interfaceIssues := collectNetworkInterfaces(platform.networkInterfaces)

	for index := range cpuSpecifications.LogicalProcessors {
		processorID := cpuSpecifications.LogicalProcessors[index].ID
		if numaNodeID := platform.logicalProcessorNUMA[processorID]; numaNodeID != "" {
			cpuSpecifications.LogicalProcessors[index].NUMANodeID = numaNodeID
		}
	}
	applyCPUDetails(&cpuSpecifications, platform.cpuDetails, platform.offlineProcessors)
	cpuSpecifications.NUMANodes = platform.numaNodes
	system.Platform = platform.platform
	system.Timezone = platform.timezone
	system.InitSystem = platform.initSystem
	memorySpecifications.Modules = platform.memoryModules
	if installedBytes := installedMemoryBytes(platform.memoryModules); installedBytes > memorySpecifications.TotalBytes {
		memorySpecifications.TotalBytes = installedBytes
	}

	issues := append(systemIssues, cpuIssues...)
	issues = append(issues, memoryIssues...)
	issues = append(issues, platform.issues...)
	issues = append(issues, interfaceIssues...)

	nodeSpecifications := protocol.NodeSpecifications{
		System:            system,
		CPU:               cpuSpecifications,
		Memory:            memorySpecifications,
		GPUs:              platform.gpus,
		StorageDevices:    platform.storageDevices,
		NetworkInterfaces: interfaces,
		CollectionIssues:  deduplicateIssues(issues),
	}
	normalizeSpecificationCollections(&nodeSpecifications)

	if err := fitSpecificationsToBudget(&nodeSpecifications); err != nil {
		return Snapshot{}, err
	}

	return Snapshot{
		ObservationScope: scope,
		Specifications:   nodeSpecifications,
	}, nil
}

func installedMemoryBytes(modules []protocol.MemoryModuleSpecifications) uint64 {
	var total uint64
	for _, module := range modules {
		if math.MaxUint64-total < module.SizeBytes {
			return 0
		}

		total += module.SizeBytes
	}

	return total
}

func normalizeSpecificationCollections(specifications *protocol.NodeSpecifications) {
	if specifications.CPU.Packages == nil {
		specifications.CPU.Packages = []protocol.CPUPackageSpecifications{}
	}
	for index := range specifications.CPU.Packages {
		cpuPackage := &specifications.CPU.Packages[index]
		if cpuPackage.Caches == nil {
			cpuPackage.Caches = []protocol.CPUCacheSpecifications{}
		}
		if cpuPackage.Flags == nil {
			cpuPackage.Flags = []string{}
		}
	}
	if specifications.CPU.NUMANodes == nil {
		specifications.CPU.NUMANodes = []protocol.NUMANodeSpecifications{}
	}
	if specifications.CPU.LogicalProcessors == nil {
		specifications.CPU.LogicalProcessors = []protocol.LogicalProcessorSpecifications{}
	}
	if specifications.Memory.Modules == nil {
		specifications.Memory.Modules = []protocol.MemoryModuleSpecifications{}
	}
	if specifications.GPUs == nil {
		specifications.GPUs = []protocol.GPUSpecifications{}
	}
	if specifications.StorageDevices == nil {
		specifications.StorageDevices = []protocol.StorageDeviceSpecifications{}
	}
	if specifications.NetworkInterfaces == nil {
		specifications.NetworkInterfaces = []protocol.NetworkInterfaceSpecifications{}
	}
}

func fitSpecificationsToBudget(specifications *protocol.NodeSpecifications) error {
	baseIssues := append([]protocol.CollectionIssue(nil), specifications.CollectionIssues...)
	truncated := make(map[string]struct{})

	for {
		specifications.CollectionIssues = append([]protocol.CollectionIssue(nil), baseIssues...)
		for component := range truncated {
			specifications.CollectionIssues = append(specifications.CollectionIssues, protocol.CollectionIssue{
				Component: component,
				Code:      issueTruncated,
			})
		}
		specifications.CollectionIssues = deduplicateIssues(specifications.CollectionIssues)

		data, err := json.Marshal(specifications)
		if err != nil {
			return fmt.Errorf("size specifications snapshot: %w", err)
		}
		if len(data) <= maxSpecificationsJSON {
			break
		}

		switch {
		case len(specifications.CPU.LogicalProcessors) > 0:
			specifications.CPU.LogicalProcessors = specifications.CPU.LogicalProcessors[:len(specifications.CPU.LogicalProcessors)/2]
			truncated["cpu.logical_processors"] = struct{}{}
		case len(specifications.Memory.Modules) > 0:
			specifications.Memory.Modules = specifications.Memory.Modules[:len(specifications.Memory.Modules)/2]
			truncated["memory.modules"] = struct{}{}
		case len(specifications.StorageDevices) > 0:
			specifications.StorageDevices = specifications.StorageDevices[:len(specifications.StorageDevices)/2]
			truncated["storage_devices"] = struct{}{}
		case len(specifications.GPUs) > 0:
			specifications.GPUs = specifications.GPUs[:len(specifications.GPUs)/2]
			truncated["gpus"] = struct{}{}
		case len(specifications.NetworkInterfaces) > 0:
			specifications.NetworkInterfaces = specifications.NetworkInterfaces[:len(specifications.NetworkInterfaces)/2]
			truncated["network_interfaces"] = struct{}{}
		case len(specifications.CPU.NUMANodes) > 0:
			specifications.CPU.NUMANodes = specifications.CPU.NUMANodes[:len(specifications.CPU.NUMANodes)/2]
			truncated["cpu.numa_nodes"] = struct{}{}
		default:
			return fmt.Errorf("specifications snapshot exceeds %d bytes without optional entries", maxSpecificationsJSON)
		}
	}

	return nil
}

func collectSystem(ctx context.Context) (protocol.SystemSpecifications, string, []protocol.CollectionIssue, error) {
	hostname, err := hostHostname()
	if err != nil {
		return protocol.SystemSpecifications{}, "", nil, fmt.Errorf("read system hostname: %w", err)
	}

	system := protocol.SystemSpecifications{
		Hostname:     sanitize(hostname, 255),
		Architecture: runtime.GOARCH,
		OS: protocol.OSSpecifications{
			Type: runtime.GOOS,
		},
	}
	issues := make([]protocol.CollectionIssue, 0, 3)

	platform, _, version, err := host.PlatformInformationWithContext(ctx)
	if err != nil {
		issues = append(issues, issue("system.os", err))
	} else {
		system.OS.Name = sanitize(platform, 128)
		system.OS.Version = sanitize(version, 128)
	}

	if bootSeconds, err := host.BootTimeWithContext(ctx); err == nil && bootSeconds > 0 {
		bootTime := time.Unix(int64(bootSeconds), 0).UTC()
		system.BootTime = &bootTime
	}

	kernelVersion, err := host.KernelVersionWithContext(ctx)
	if err != nil {
		issues = append(issues, issue("system.kernel", err))
	} else {
		system.OS.KernelVersion = sanitize(kernelVersion, 128)
	}

	environment := observation.Detect(ctx)
	if environment.Error != nil {
		issues = append(issues, issue("system.virtualization", environment.Error))
	}

	if environment.System != "" {
		kind := "virtual_machine"
		if environment.Scope == protocol.ObservationScopeRuntime {
			kind = "container"
		}
		if environment.Role == "host" {
			kind = "host"
		}

		system.Virtualization = &protocol.VirtualizationSpecifications{
			Kind:     kind,
			Provider: sanitize(environment.System, 64),
		}
	}

	return system, environment.Scope, issues, nil
}

// hostHostname returns the host's name. In a container that does not share
// the host's UTS namespace, os.Hostname is the container's ID, so the host's
// /etc/hostname is preferred there.
func hostHostname() (string, error) {
	if hostfs.Containerized() {
		if data, err := os.ReadFile(hostfs.Etc("hostname")); err == nil {
			if name := strings.TrimSpace(string(data)); name != "" {
				return name, nil
			}
		}
	}

	return os.Hostname()
}

func collectCPU(ctx context.Context) (protocol.CPUSpecifications, []protocol.CollectionIssue) {
	specifications := protocol.CPUSpecifications{Architecture: runtime.GOARCH}
	issues := make([]protocol.CollectionIssue, 0, 3)

	logicalCount, err := cpu.CountsWithContext(ctx, true)
	if err != nil || logicalCount <= 0 {
		logicalCount = runtime.NumCPU()
		if err != nil {
			issues = append(issues, issue("cpu.logical_count", err))
		}
	}
	specifications.LogicalProcessorCount = logicalCount

	physicalCount, err := cpu.CountsWithContext(ctx, false)
	if err != nil {
		issues = append(issues, issue("cpu.physical_count", err))
	} else if physicalCount > 0 {
		specifications.PhysicalCoreCount = physicalCount
	}

	information, err := cpu.InfoWithContext(ctx)
	if err != nil {
		issues = append(issues, issue("cpu.topology", err))
		information = nil
	}

	specifications.Packages, specifications.LogicalProcessors = normalizeCPU(information, logicalCount, physicalCount)

	return specifications, issues
}

type packageBuilder struct {
	packageSpecifications protocol.CPUPackageSpecifications
	coreIDs               map[string]struct{}
	logicalProcessorIDs   []int
}

func normalizeCPU(information []cpu.InfoStat, logicalCount, physicalCount int) (
	[]protocol.CPUPackageSpecifications,
	[]protocol.LogicalProcessorSpecifications,
) {
	builders := make([]*packageBuilder, 0)
	packageIndexes := make(map[string]int)
	logicalProcessors := make([]protocol.LogicalProcessorSpecifications, 0, logicalCount)

	perLogicalProcessor := len(information) > 1 && len(information) >= logicalCount
	for index, info := range information {
		key := info.PhysicalID
		if key == "" {
			if perLogicalProcessor {
				key = "0"
			} else {
				key = strconv.Itoa(index)
			}
		}

		packageIndex, exists := packageIndexes[key]
		if !exists {
			packageIndex = len(builders)
			packageIndexes[key] = packageIndex
			builders = append(builders, &packageBuilder{
				packageSpecifications: protocol.CPUPackageSpecifications{
					ID:              "package:" + strconv.Itoa(packageIndex),
					Vendor:          sanitize(info.VendorID, 128),
					Model:           sanitize(info.ModelName, 256),
					Socket:          sanitize(info.PhysicalID, 64),
					Family:          sanitize(info.Family, 32),
					ModelID:         sanitize(info.Model, 32),
					Stepping:        steppingText(info),
					Microcode:       sanitize(info.Microcode, 64),
					BaseFrequencyHz: nominalFrequencyHz(info.ModelName),
					Flags:           cpuFlags(info.Flags),
				},
				coreIDs: make(map[string]struct{}),
			})
		}

		builder := builders[packageIndex]
		if builder.packageSpecifications.Vendor == "" {
			builder.packageSpecifications.Vendor = sanitize(info.VendorID, 128)
		}
		if builder.packageSpecifications.Model == "" {
			builder.packageSpecifications.Model = sanitize(info.ModelName, 256)
		}
		if info.Mhz > 0 && info.Mhz <= math.MaxUint64/1_000_000 {
			frequency := uint64(info.Mhz * 1_000_000)
			if frequency > builder.packageSpecifications.FrequencyHz {
				builder.packageSpecifications.FrequencyHz = frequency
			}
		}

		if perLogicalProcessor {
			processorID := int(info.CPU)
			if processorID < 0 {
				processorID = index
			}
			coreID := ""
			if info.CoreID != "" {
				coreID = builder.packageSpecifications.ID + "/core:" + sanitizeID(info.CoreID)
				builder.coreIDs[coreID] = struct{}{}
			}

			builder.logicalProcessorIDs = append(builder.logicalProcessorIDs, processorID)
			logicalProcessors = append(logicalProcessors, protocol.LogicalProcessorSpecifications{
				ID:        "cpu:" + strconv.Itoa(processorID),
				PackageID: builder.packageSpecifications.ID,
				CoreID:    coreID,
				Online:    true,
			})
		}
	}

	if len(builders) == 0 {
		builders = append(builders, &packageBuilder{
			packageSpecifications: protocol.CPUPackageSpecifications{ID: "package:0"},
			coreIDs:               make(map[string]struct{}),
		})
	}

	if len(logicalProcessors) == 0 {
		for processorID := range logicalCount {
			packageIndex := packageForProcessor(builders, processorID)
			packageID := builders[packageIndex].packageSpecifications.ID
			builders[packageIndex].logicalProcessorIDs = append(builders[packageIndex].logicalProcessorIDs, processorID)
			logicalProcessors = append(logicalProcessors, protocol.LogicalProcessorSpecifications{
				ID:        "cpu:" + strconv.Itoa(processorID),
				PackageID: packageID,
				Online:    true,
			})
		}
	}

	packages := make([]protocol.CPUPackageSpecifications, 0, len(builders))
	for _, builder := range builders {
		builder.packageSpecifications.LogicalProcessorCount = len(builder.logicalProcessorIDs)
		builder.packageSpecifications.PhysicalCoreCount = len(builder.coreIDs)
		if builder.packageSpecifications.PhysicalCoreCount == 0 && len(builders) == 1 {
			builder.packageSpecifications.PhysicalCoreCount = physicalCount
		}
		packages = append(packages, builder.packageSpecifications)
	}

	sort.Slice(logicalProcessors, func(left, right int) bool {
		return logicalProcessorNumber(logicalProcessors[left].ID) < logicalProcessorNumber(logicalProcessors[right].ID)
	})

	return packages, logicalProcessors
}

// applyCPUDetails adds sysfs frequencies and caches to the packages they
// belong to, and lists present processors that are offline.
func applyCPUDetails(specifications *protocol.CPUSpecifications, details map[string]cpuPackageDetails, offline []int) {
	for index := range specifications.Packages {
		cpuPackage := &specifications.Packages[index]
		socket := cpuPackage.Socket
		if socket == "" {
			socket = "0"
		}
		item, exists := details[socket]
		if !exists {
			continue
		}
		if item.baseFrequencyHz > 0 {
			cpuPackage.BaseFrequencyHz = item.baseFrequencyHz
		}
		cpuPackage.MinFrequencyHz = item.minFrequencyHz
		cpuPackage.MaxFrequencyHz = item.maxFrequencyHz
		cpuPackage.Caches = item.caches
	}

	for _, processor := range offline {
		specifications.LogicalProcessors = append(specifications.LogicalProcessors, protocol.LogicalProcessorSpecifications{
			ID:     "cpu:" + strconv.Itoa(processor),
			Online: false,
		})
	}
	sort.Slice(specifications.LogicalProcessors, func(left, right int) bool {
		return logicalProcessorNumber(specifications.LogicalProcessors[left].ID) <
			logicalProcessorNumber(specifications.LogicalProcessors[right].ID)
	})
}

// nominalFrequencyHz reads the rated clock that Intel puts in the model
// name, such as "Intel(R) Xeon(R) Gold 6226R CPU @ 2.90GHz".
func nominalFrequencyHz(modelName string) uint64 {
	_, rated, found := strings.Cut(modelName, "@")
	if !found {
		return 0
	}
	rated = strings.TrimSpace(rated)
	value, isGHz := strings.CutSuffix(rated, "GHz")
	multiplier := 1e9
	if !isGHz {
		if value, found = strings.CutSuffix(rated, "MHz"); !found {
			return 0
		}
		multiplier = 1e6
	}
	number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || number <= 0 || number > 100 && isGHz {
		return 0
	}

	return uint64(math.Round(number * multiplier))
}

// cpuFlags returns the feature flags, such as avx2 or vmx, sorted and
// bounded.
func cpuFlags(flags []string) []string {
	const maxFlags = 512
	result := make([]string, 0, min(len(flags), maxFlags))
	for _, flag := range flags {
		if flag = sanitizeID(flag); flag != "" && len(result) < maxFlags {
			result = append(result, flag)
		}
	}
	sort.Strings(result)

	return slices.Compact(result)
}

// steppingText reports the stepping only when the processor reports its
// family, since stepping 0 is a real revision.
func steppingText(info cpu.InfoStat) string {
	if info.Family == "" || info.Stepping < 0 {
		return ""
	}

	return strconv.Itoa(int(info.Stepping))
}

func collectMemory(ctx context.Context) (protocol.MemorySpecifications, []protocol.CollectionIssue) {
	memory, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return protocol.MemorySpecifications{}, []protocol.CollectionIssue{issue("memory.total", err)}
	}

	return protocol.MemorySpecifications{TotalBytes: memory.Total}, nil
}

func collectNetworkInterfaces(metadata map[string]networkInterfaceMetadata) (
	[]protocol.NetworkInterfaceSpecifications,
	[]protocol.CollectionIssue,
) {
	interfaces, err := hostnet.Interfaces()
	if err != nil {
		return nil, []protocol.CollectionIssue{issue("network_interfaces", err)}
	}

	result := make([]protocol.NetworkInterfaceSpecifications, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		interfaceMetadata := metadata[networkInterface.Name]
		physical := len(networkInterface.HardwareAddr) > 0 && networkInterface.Flags&net.FlagLoopback == 0
		if interfaceMetadata.physicalKnown {
			physical = interfaceMetadata.physical
		}

		kind := "virtual"
		if networkInterface.Flags&net.FlagLoopback != 0 {
			kind = "loopback"
		} else if networkInterface.Flags&net.FlagPointToPoint != 0 {
			kind = "point_to_point"
		} else if physical {
			kind = "ethernet"
		}

		result = append(result, protocol.NetworkInterfaceSpecifications{
			ID:            networkInterface.ID(),
			Name:          sanitize(networkInterface.Name, 255),
			Kind:          kind,
			Physical:      physical,
			MTU:           networkInterface.MTU,
			MaxSpeedBPS:   interfaceMetadata.maxSpeedBPS,
			Driver:        interfaceMetadata.driver,
			DriverVersion: interfaceMetadata.driverVersion,
		})
	}

	return result, nil
}

func packageForProcessor(builders []*packageBuilder, processorID int) int {
	if len(builders) <= 1 {
		return 0
	}

	return processorID % len(builders)
}

func logicalProcessorNumber(id string) int {
	number, _ := strconv.Atoi(strings.TrimPrefix(id, "cpu:"))
	return number
}

func issue(component string, err error) protocol.CollectionIssue {
	code := issueCollectionFailed
	if errors.Is(err, context.DeadlineExceeded) {
		code = issueTimeout
	} else if errors.Is(err, os.ErrPermission) {
		code = issuePermissionDenied
	} else if errors.Is(err, os.ErrNotExist) {
		code = issueNotAvailable
	}

	return protocol.CollectionIssue{Component: component, Code: code}
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
	value = sanitize(value, 64)
	return strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(value)
}
