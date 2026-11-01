package protocol

import "time"

// NodeMetrics contains dynamic resource usage visible to the agent.
type NodeMetrics struct {
	CPU     CPUMetrics       `json:"cpu"`
	Memory  MemoryMetrics    `json:"memory"`
	Storage StorageMetrics   `json:"storage"`
	Network []NetworkMetrics `json:"network"`
	TCP     *TCPMetrics      `json:"tcp,omitempty"`
	GPUs    []GPUMetrics     `json:"gpus"`
	// Sensors is left out when the node exposes no hardware monitoring.
	Sensors   []SensorMetrics `json:"sensors,omitempty"`
	Processes ProcessMetrics  `json:"processes"`
}

// CPUMetrics contains aggregate and per-logical-processor utilization.
type CPUMetrics struct {
	Total                    CPUUtilizationMetrics     `json:"total"`
	Logical                  []LogicalProcessorMetrics `json:"logical"`
	LoadAverage              *LoadAverageMetrics       `json:"load_average,omitempty"`
	ContextSwitchesPerSecond *float64                  `json:"context_switches_per_second,omitempty"`
	InterruptsPerSecond      *float64                  `json:"interrupts_per_second,omitempty"`
}

// CPUUtilizationMetrics is the percentage of an observation interval spent in each CPU mode.
type CPUUtilizationMetrics struct {
	UsagePercent  float64 `json:"usage_percent"`
	UserPercent   float64 `json:"user_percent"`
	SystemPercent float64 `json:"system_percent"`
	IOWaitPercent float64 `json:"iowait_percent"`
	StealPercent  float64 `json:"steal_percent"`
	IdlePercent   float64 `json:"idle_percent"`
}

// LogicalProcessorMetrics identifies utilization for one logical CPU from specifications.
type LogicalProcessorMetrics struct {
	ID            string  `json:"id"`
	UsagePercent  float64 `json:"usage_percent"`
	UserPercent   float64 `json:"user_percent"`
	SystemPercent float64 `json:"system_percent"`
	IOWaitPercent float64 `json:"iowait_percent"`
	StealPercent  float64 `json:"steal_percent"`
	IdlePercent   float64 `json:"idle_percent"`
}

// LoadAverageMetrics contains scheduler load supplied by supported operating systems.
type LoadAverageMetrics struct {
	OneMinute      float64 `json:"1m"`
	FiveMinutes    float64 `json:"5m"`
	FifteenMinutes float64 `json:"15m"`
}

// MemoryMetrics contains current memory gauges and paging rates.
type MemoryMetrics struct {
	TotalBytes               uint64   `json:"total_bytes"`
	UsedBytes                uint64   `json:"used_bytes"`
	AvailableBytes           uint64   `json:"available_bytes"`
	CachedBytes              uint64   `json:"cached_bytes"`
	BuffersBytes             uint64   `json:"buffers_bytes"`
	SwapTotalBytes           uint64   `json:"swap_total_bytes"`
	SwapUsedBytes            uint64   `json:"swap_used_bytes"`
	PageFaultsPerSecond      *float64 `json:"page_faults_per_second,omitempty"`
	MajorPageFaultsPerSecond *float64 `json:"major_page_faults_per_second,omitempty"`
}

// StorageMetrics contains block-device rates and filesystem gauges.
type StorageMetrics struct {
	Devices     []StorageDeviceMetrics `json:"devices"`
	Filesystems []FilesystemMetrics    `json:"filesystems"`
	// RAID is left out when the node has no software RAID.
	RAID []RAIDMetrics `json:"raid,omitempty"`
}

// RAIDMetrics is the state of one Linux software RAID (md) array. Degraded
// counts missing members; FailedMembers names members marked faulty.
// SyncPercent is set while the array resyncs, recovers, or is checked.
type RAIDMetrics struct {
	DeviceID      string   `json:"device_id"`
	Level         string   `json:"level"`
	State         string   `json:"state"`
	Disks         int      `json:"disks"`
	Degraded      int      `json:"degraded"`
	FailedMembers []string `json:"failed_members"`
	SyncAction    string   `json:"sync_action,omitempty"`
	SyncPercent   *float64 `json:"sync_percent,omitempty"`
}

// StorageDeviceMetrics contains rates for one device from specifications.
type StorageDeviceMetrics struct {
	DeviceID                 string  `json:"device_id"`
	ReadBytesPerSecond       float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond      float64 `json:"write_bytes_per_second"`
	ReadOperationsPerSecond  float64 `json:"read_operations_per_second"`
	WriteOperationsPerSecond float64 `json:"write_operations_per_second"`
	IOUtilizationPercent     float64 `json:"io_utilization_percent"`
	QueueDepth               float64 `json:"queue_depth"`
	ReadBytesTotal           uint64  `json:"read_bytes_total"`
	WriteBytesTotal          uint64  `json:"write_bytes_total"`
}

// FilesystemMetrics contains current capacity for one mounted filesystem.
type FilesystemMetrics struct {
	FilesystemID      string   `json:"filesystem_id"`
	Mountpoint        string   `json:"mountpoint"`
	Device            string   `json:"device"`
	FilesystemType    string   `json:"filesystem_type"`
	TotalBytes        uint64   `json:"total_bytes"`
	UsedBytes         uint64   `json:"used_bytes"`
	AvailableBytes    uint64   `json:"available_bytes"`
	UsedPercent       float64  `json:"used_percent"`
	InodesUsedPercent *float64 `json:"inodes_used_percent,omitempty"`
}

// NetworkMetrics contains receive and transmit rates for one interface.
type NetworkMetrics struct {
	InterfaceID        string  `json:"interface_id"`
	RXBytesPerSecond   float64 `json:"rx_bytes_per_second"`
	TXBytesPerSecond   float64 `json:"tx_bytes_per_second"`
	RXPacketsPerSecond float64 `json:"rx_packets_per_second"`
	TXPacketsPerSecond float64 `json:"tx_packets_per_second"`
	RXErrorsPerSecond  float64 `json:"rx_errors_per_second"`
	TXErrorsPerSecond  float64 `json:"tx_errors_per_second"`
	RXDropsPerSecond   float64 `json:"rx_drops_per_second"`
	TXDropsPerSecond   float64 `json:"tx_drops_per_second"`
	RXBytesTotal       uint64  `json:"rx_bytes_total"`
	TXBytesTotal       uint64  `json:"tx_bytes_total"`
}

// TCPMetrics summarizes the TCP stack of the host's network namespace for
// IPv4 and IPv6 together. Gauges are current counts; rates are per second.
type TCPMetrics struct {
	Established                    uint64  `json:"established"`
	TimeWait                       uint64  `json:"time_wait"`
	Orphaned                       uint64  `json:"orphaned"`
	InUse                          uint64  `json:"in_use"`
	ActiveOpensPerSecond           float64 `json:"active_opens_per_second"`
	PassiveOpensPerSecond          float64 `json:"passive_opens_per_second"`
	FailedAttemptsPerSecond        float64 `json:"failed_attempts_per_second"`
	ResetsSentPerSecond            float64 `json:"resets_sent_per_second"`
	RetransmittedSegmentsPerSecond float64 `json:"retransmitted_segments_per_second"`
}

// SensorMetrics is one hardware monitoring reading: a temperature in
// degrees Celsius or a fan speed in revolutions per minute.
type SensorMetrics struct {
	SensorID string  `json:"sensor_id"`
	Chip     string  `json:"chip"`
	Label    string  `json:"label"`
	Type     string  `json:"type"`
	Value    float64 `json:"value"`
	// CriticalCelsius is the chip's critical temperature, when it has one.
	CriticalCelsius *float64 `json:"critical_celsius,omitempty"`
}

// GPUMetrics contains dynamic telemetry for one GPU from specifications.
type GPUMetrics struct {
	GPUID              string   `json:"gpu_id"`
	UtilizationPercent *float64 `json:"utilization_percent,omitempty"`
	MemoryUsedBytes    *uint64  `json:"memory_used_bytes,omitempty"`
	TemperatureCelsius *float64 `json:"temperature_celsius,omitempty"`
	PowerWatts         *float64 `json:"power_watts,omitempty"`
	FanPercent         *float64 `json:"fan_percent,omitempty"`
	ClockHz            *uint64  `json:"clock_hz,omitempty"`
}

// ProcessMetrics contains process counts and bounded per-process usage.
type ProcessMetrics struct {
	Total     int             `json:"total"`
	Running   int             `json:"running"`
	Sleeping  int             `json:"sleeping"`
	Blocked   int             `json:"blocked"`
	Zombie    int             `json:"zombie"`
	Threads   int             `json:"threads"`
	Truncated bool            `json:"truncated"`
	Items     []ProcessMetric `json:"items"`
}

// ProcessMetric identifies a process by PID and start time to survive PID reuse.
type ProcessMetric struct {
	PID                 int32     `json:"pid"`
	ParentPID           int32     `json:"parent_pid"`
	StartedAt           time.Time `json:"started_at"`
	Name                string    `json:"name"`
	State               string    `json:"state,omitempty"`
	UID                 *uint32   `json:"uid,omitempty"`
	User                string    `json:"user,omitempty"`
	CPUPercent          float64   `json:"cpu_percent"`
	MemoryRSSBytes      uint64    `json:"memory_rss_bytes"`
	MemoryVirtualBytes  uint64    `json:"memory_virtual_bytes"`
	ReadBytesPerSecond  float64   `json:"read_bytes_per_second"`
	WriteBytesPerSecond float64   `json:"write_bytes_per_second"`
	Threads             int32     `json:"threads"`
	FileDescriptors     *int32    `json:"file_descriptors,omitempty"`
	ContainerID         string    `json:"container_id,omitempty"`
}

// ContainerMetrics contains runtime resource usage for one container.
type ContainerMetrics struct {
	ContainerID string                  `json:"container_id"`
	Runtime     string                  `json:"runtime"`
	Name        string                  `json:"name"`
	State       string                  `json:"state"`
	CPU         ContainerCPUMetrics     `json:"cpu"`
	Memory      ContainerMemoryMetrics  `json:"memory"`
	Storage     ContainerStorageMetrics `json:"storage"`
	Network     ContainerNetworkMetrics `json:"network"`
	PIDs        ContainerPIDMetrics     `json:"pids"`
}

// ContainerCPUMetrics follows the single-logical-core percentage convention:
// 100 is one fully busy logical CPU, so UsagePercent can reach
// OnlineCPUs*100. LimitCores is set only when a quota or cpuset caps the
// container below OnlineCPUs.
type ContainerCPUMetrics struct {
	UsagePercent          float64  `json:"usage_percent"`
	OnlineCPUs            uint32   `json:"online_cpus"`
	LimitCores            *float64 `json:"limit_cores,omitempty"`
	ThrottledSecondsTotal float64  `json:"throttled_seconds_total"`
	ThrottledPeriodsTotal uint64   `json:"throttled_periods_total"`
}

// ContainerMemoryMetrics contains current cgroup or job-object memory usage.
type ContainerMemoryMetrics struct {
	UsedBytes      uint64  `json:"used_bytes"`
	LimitBytes     uint64  `json:"limit_bytes"`
	UsedPercent    float64 `json:"used_percent"`
	CacheBytes     uint64  `json:"cache_bytes"`
	OOMEventsTotal uint64  `json:"oom_events_total"`
}

// ContainerStorageMetrics contains aggregate container block-I/O rates.
type ContainerStorageMetrics struct {
	ReadBytesPerSecond       float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond      float64 `json:"write_bytes_per_second"`
	ReadOperationsPerSecond  float64 `json:"read_operations_per_second"`
	WriteOperationsPerSecond float64 `json:"write_operations_per_second"`
}

// ContainerNetworkMetrics contains aggregate container network rates.
type ContainerNetworkMetrics struct {
	RXBytesPerSecond   float64 `json:"rx_bytes_per_second"`
	TXBytesPerSecond   float64 `json:"tx_bytes_per_second"`
	RXPacketsPerSecond float64 `json:"rx_packets_per_second"`
	TXPacketsPerSecond float64 `json:"tx_packets_per_second"`
}

// ContainerPIDMetrics contains the current process count and configured limit.
type ContainerPIDMetrics struct {
	Current uint64 `json:"current"`
	Limit   uint64 `json:"limit"`
}
