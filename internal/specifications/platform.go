package specifications

import (
	"github.com/FroZor/loreva-agent/internal/protocol"
)

type networkInterfaceMetadata struct {
	physicalKnown bool
	physical      bool
	maxSpeedBPS   uint64
	driver        string
	driverVersion string
}

// cpuPackageDetails are the sysfs facts about one physical package.
type cpuPackageDetails struct {
	baseFrequencyHz uint64
	minFrequencyHz  uint64
	maxFrequencyHz  uint64
	caches          []protocol.CPUCacheSpecifications
}

type platformSpecifications struct {
	cpuDetails           map[string]cpuPackageDetails
	offlineProcessors    []int
	platform             *protocol.PlatformSpecifications
	timezone             string
	initSystem           string
	memoryModules        []protocol.MemoryModuleSpecifications
	gpus                 []protocol.GPUSpecifications
	storageDevices       []protocol.StorageDeviceSpecifications
	numaNodes            []protocol.NUMANodeSpecifications
	logicalProcessorNUMA map[string]string
	networkInterfaces    map[string]networkInterfaceMetadata
	issues               []protocol.CollectionIssue
}
