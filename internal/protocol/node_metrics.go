package protocol

import "time"

const (
	MetricsSchemaVersion = 1
	MetricsReportType    = "metrics.report"
	MetricsAcceptedType  = "metrics.accepted"
	MetricsRejectedType  = "metrics.rejected"
	MetricTypeNode       = "node"
	MetricTypeContainer  = "container"
)

// MetricsReport carries one typed metric series through the working connection.
type MetricsReport struct {
	Type          string       `json:"type"`
	SchemaVersion int          `json:"schema_version"`
	RequestID     string       `json:"request_id"`
	StreamID      string       `json:"stream_id"`
	Metric        MetricSeries `json:"metric"`
}

// MetricsAccepted acknowledges a committed metrics request.
type MetricsAccepted struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

// MetricSeries identifies the core collector or plugin that produced samples.
type MetricSeries struct {
	Type          string         `json:"type"`
	SchemaVersion int            `json:"schema_version,omitempty"`
	SourceID      string         `json:"source_id,omitempty"`
	Samples       []MetricSample `json:"samples"`
}

// MetricSample is one observation interval with exactly one typed payload.
type MetricSample struct {
	Sequence         uint64              `json:"sequence"`
	ObservedAt       time.Time           `json:"observed_at"`
	IntervalMS       uint64              `json:"interval_ms"`
	ObservationScope string              `json:"observation_scope"`
	Node             *NodeMetrics        `json:"node,omitempty"`
	Containers       *ContainerMetricSet `json:"containers,omitempty"`
	Plugin           *PluginMetricSet    `json:"plugin,omitempty"`
	CollectionIssues []CollectionIssue   `json:"collection_issues,omitempty"`
}

// ContainerMetricSet contains all containers observed through one runtime.
type ContainerMetricSet struct {
	Items []ContainerMetrics `json:"items"`
}

// PluginMetricSet is a bounded set of numeric measurements produced by an adapter.
type PluginMetricSet struct {
	Values map[string]float64 `json:"values"`
}

// NodeMetrics contains dynamic resource usage visible to the agent.
type NodeMetrics struct {
	CPU       CPUMetrics       `json:"cpu"`
	Memory    MemoryMetrics    `json:"memory"`
	Storage   StorageMetrics   `json:"storage"`
	Network   []NetworkMetrics `json:"network"`
	GPUs      []GPUMetrics     `json:"gpus"`
	Processes ProcessMetrics   `json:"processes"`
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
	UsedBytes                uint64   `json:"used_bytes"`
	AvailableBytes           uint64   `json:"available_bytes"`
	CachedBytes              uint64   `json:"cached_bytes"`
	BuffersBytes             uint64   `json:"buffers_bytes"`
	SwapUsedBytes            uint64   `json:"swap_used_bytes"`
	PageFaultsPerSecond      *float64 `json:"page_faults_per_second,omitempty"`
	MajorPageFaultsPerSecond *float64 `json:"major_page_faults_per_second,omitempty"`
}

// StorageMetrics contains block-device rates and filesystem gauges.
type StorageMetrics struct {
	Devices     []StorageDeviceMetrics `json:"devices"`
	Filesystems []FilesystemMetrics    `json:"filesystems"`
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
}

// FilesystemMetrics contains current capacity for one mounted filesystem.
type FilesystemMetrics struct {
	FilesystemID      string   `json:"filesystem_id"`
	Mountpoint        string   `json:"mountpoint"`
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
	StartedAt           time.Time `json:"started_at"`
	Name                string    `json:"name"`
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

// ContainerCPUMetrics follows the single-logical-core percentage convention.
type ContainerCPUMetrics struct {
	UsagePercent          float64 `json:"usage_percent"`
	ThrottledSecondsTotal float64 `json:"throttled_seconds_total"`
	ThrottledPeriodsTotal uint64  `json:"throttled_periods_total"`
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
