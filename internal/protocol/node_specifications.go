package protocol

import "time"

const (
	NodeSpecificationsSchemaVersion = 1
	NodeSpecificationsReportType    = "node.specifications.report"
	NodeSpecificationsAcceptedType  = "node.specifications.accepted"
	NodeSpecificationsRejectedType  = "node.specifications.rejected"
	ObservationScopeHost            = "host"
	ObservationScopeRuntime         = "runtime"
)

// NodeSpecificationsReport describes hardware visible to the agent.
type NodeSpecificationsReport struct {
	Type             string             `json:"type"`
	SchemaVersion    int                `json:"schema_version"`
	RequestID        string             `json:"request_id"`
	ObservedAt       time.Time          `json:"observed_at"`
	ObservationScope string             `json:"observation_scope"`
	Specifications   NodeSpecifications `json:"specifications"`
}

// NodeSpecificationsAccepted acknowledges a committed specifications snapshot.
type NodeSpecificationsAccepted struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Revision  int64  `json:"revision"`
}

// NodeSpecifications is a static hardware snapshot. Dynamic utilization is reported separately.
type NodeSpecifications struct {
	System            SystemSpecifications             `json:"system"`
	CPU               CPUSpecifications                `json:"cpu"`
	Memory            MemorySpecifications             `json:"memory"`
	GPUs              []GPUSpecifications              `json:"gpus"`
	StorageDevices    []StorageDeviceSpecifications    `json:"storage_devices"`
	NetworkInterfaces []NetworkInterfaceSpecifications `json:"network_interfaces"`
	CollectionIssues  []CollectionIssue                `json:"collection_issues,omitempty"`
}

// SystemSpecifications describes the operating system visible to the agent.
type SystemSpecifications struct {
	Hostname       string                        `json:"hostname"`
	Architecture   string                        `json:"architecture"`
	OS             OSSpecifications              `json:"os"`
	Virtualization *VirtualizationSpecifications `json:"virtualization,omitempty"`
}

// OSSpecifications identifies the operating system without a host-unique identifier.
type OSSpecifications struct {
	Type          string `json:"type"`
	Name          string `json:"name,omitempty"`
	Version       string `json:"version,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
}

// VirtualizationSpecifications describes an observed VM or container boundary.
type VirtualizationSpecifications struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider,omitempty"`
}

// CPUSpecifications contains package and logical-processor topology.
type CPUSpecifications struct {
	Architecture          string                           `json:"architecture"`
	PhysicalCoreCount     int                              `json:"physical_core_count"`
	LogicalProcessorCount int                              `json:"logical_processor_count"`
	Packages              []CPUPackageSpecifications       `json:"packages"`
	NUMANodes             []NUMANodeSpecifications         `json:"numa_nodes"`
	LogicalProcessors     []LogicalProcessorSpecifications `json:"logical_processors"`
}

// CPUPackageSpecifications describes one physical CPU package.
type CPUPackageSpecifications struct {
	ID                    string `json:"id"`
	Vendor                string `json:"vendor,omitempty"`
	Model                 string `json:"model,omitempty"`
	Socket                string `json:"socket,omitempty"`
	PhysicalCoreCount     int    `json:"physical_core_count,omitempty"`
	LogicalProcessorCount int    `json:"logical_processor_count,omitempty"`
	FrequencyHz           uint64 `json:"frequency_hz,omitempty"`
}

// NUMANodeSpecifications describes memory assigned to one NUMA node.
type NUMANodeSpecifications struct {
	ID          string `json:"id"`
	MemoryBytes uint64 `json:"memory_bytes,omitempty"`
}

// LogicalProcessorSpecifications maps a metric CPU identifier to its topology.
type LogicalProcessorSpecifications struct {
	ID         string `json:"id"`
	PackageID  string `json:"package_id,omitempty"`
	CoreID     string `json:"core_id,omitempty"`
	NUMANodeID string `json:"numa_node_id,omitempty"`
	Online     bool   `json:"online"`
}

// MemorySpecifications describes installed memory capacity and modules.
type MemorySpecifications struct {
	TotalBytes uint64                       `json:"total_bytes"`
	Modules    []MemoryModuleSpecifications `json:"modules"`
}

// MemoryModuleSpecifications describes one physical memory module without serial identifiers.
type MemoryModuleSpecifications struct {
	ID           string `json:"id"`
	Locator      string `json:"locator,omitempty"`
	SizeBytes    uint64 `json:"size_bytes"`
	Type         string `json:"type,omitempty"`
	SpeedMTS     uint64 `json:"speed_mt_s,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	PartNumber   string `json:"part_number,omitempty"`
}

// GPUSpecifications describes one graphics or compute adapter.
type GPUSpecifications struct {
	ID            string `json:"id"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`
	VendorID      string `json:"vendor_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	MemoryBytes   uint64 `json:"memory_bytes,omitempty"`
	Driver        string `json:"driver,omitempty"`
	DriverVersion string `json:"driver_version,omitempty"`
}

// StorageDeviceSpecifications describes one physical or virtual block device.
type StorageDeviceSpecifications struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Vendor         string `json:"vendor,omitempty"`
	Model          string `json:"model,omitempty"`
	MediaType      string `json:"media_type,omitempty"`
	Transport      string `json:"transport,omitempty"`
	CapacityBytes  uint64 `json:"capacity_bytes,omitempty"`
	BlockSizeBytes uint64 `json:"block_size_bytes,omitempty"`
	Removable      bool   `json:"removable"`
}

// NetworkInterfaceSpecifications describes NIC hardware without addresses.
type NetworkInterfaceSpecifications struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind,omitempty"`
	Physical      bool   `json:"physical"`
	MTU           int    `json:"mtu,omitempty"`
	MaxSpeedBPS   uint64 `json:"max_speed_bps,omitempty"`
	Driver        string `json:"driver,omitempty"`
	DriverVersion string `json:"driver_version,omitempty"`
}

// CollectionIssue safely explains why a section is partial without exposing raw system errors.
type CollectionIssue struct {
	Component string `json:"component"`
	Code      string `json:"code"`
}
