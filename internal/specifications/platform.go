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

type platformSpecifications struct {
	memoryModules        []protocol.MemoryModuleSpecifications
	gpus                 []protocol.GPUSpecifications
	storageDevices       []protocol.StorageDeviceSpecifications
	numaNodes            []protocol.NUMANodeSpecifications
	logicalProcessorNUMA map[string]string
	networkInterfaces    map[string]networkInterfaceMetadata
	issues               []protocol.CollectionIssue
}
