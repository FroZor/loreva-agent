package protocol

import "time"

// Container inventory message types.
const (
	ContainersListType         = "containers.list"
	ContainersListResultType   = "containers.list.result"
	ContainerInspectType       = "container.inspect"
	ContainerInspectResultType = "container.inspect.result"
	// MaxContainersListItems bounds one containers.list.result.
	MaxContainersListItems = 1024
)

// ContainersList asks for every container of the node's runtime, stopped
// ones included.
type ContainersList struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

// ContainersListResult answers containers.list. Truncated is set when the
// runtime has more containers than one answer carries.
type ContainersListResult struct {
	Type      string             `json:"type"`
	RequestID string             `json:"request_id"`
	Engine    ContainerEngine    `json:"engine"`
	Items     []ContainerSummary `json:"items"`
	Truncated bool               `json:"truncated"`
}

// ContainerEngine describes the container runtime of the node.
type ContainerEngine struct {
	Runtime           string   `json:"runtime"`
	Version           string   `json:"version"`
	OperatingSystem   string   `json:"operating_system,omitempty"`
	KernelVersion     string   `json:"kernel_version,omitempty"`
	Architecture      string   `json:"architecture,omitempty"`
	StorageDriver     string   `json:"storage_driver,omitempty"`
	LoggingDriver     string   `json:"logging_driver,omitempty"`
	CgroupDriver      string   `json:"cgroup_driver,omitempty"`
	CgroupVersion     string   `json:"cgroup_version,omitempty"`
	DefaultRuntime    string   `json:"default_runtime,omitempty"`
	RootDirectory     string   `json:"root_directory,omitempty"`
	SecurityOptions   []string `json:"security_options"`
	Containers        int      `json:"containers"`
	ContainersRunning int      `json:"containers_running"`
	ContainersPaused  int      `json:"containers_paused"`
	ContainersStopped int      `json:"containers_stopped"`
	Images            int      `json:"images"`
	Warnings          []string `json:"warnings"`
}

// ContainerSummary is one entry of containers.list.
type ContainerSummary struct {
	ContainerID    string          `json:"container_id"`
	Name           string          `json:"name"`
	Image          string          `json:"image"`
	ImageID        string          `json:"image_id"`
	State          string          `json:"state"`
	Status         string          `json:"status"`
	Health         string          `json:"health"`
	CreatedAt      time.Time       `json:"created_at"`
	Ports          []ContainerPort `json:"ports"`
	ComposeProject string          `json:"compose_project,omitempty"`
	ComposeService string          `json:"compose_service,omitempty"`
}

// ContainerPort is a container port and, when published, its host side.
type ContainerPort struct {
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
}

// ContainerInspect asks for the full description of one container. Size
// asks the runtime to measure the container's writable layer, which can
// take a while on large containers.
type ContainerInspect struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Size        bool   `json:"size"`
}

// ContainerInspectResult answers container.inspect.
type ContainerInspectResult struct {
	Type      string           `json:"type"`
	RequestID string           `json:"request_id"`
	Container ContainerDetails `json:"container"`
}

// ContainerDetails is what an administrator reads from docker inspect. Env
// is complete, secrets included; masking them is the client's job.
type ContainerDetails struct {
	ContainerID   string                 `json:"container_id"`
	Name          string                 `json:"name"`
	CreatedAt     time.Time              `json:"created_at"`
	Platform      string                 `json:"platform,omitempty"`
	Image         ContainerImage         `json:"image"`
	Command       ContainerCommand       `json:"command"`
	Env           []string               `json:"env"`
	Labels        map[string]string      `json:"labels"`
	State         ContainerStateDetails  `json:"state"`
	RestartPolicy ContainerRestartPolicy `json:"restart_policy"`
	AutoRemove    bool                   `json:"auto_remove"`
	Ports         []ContainerPort        `json:"ports"`
	Network       ContainerNetwork       `json:"network"`
	Mounts        []ContainerMount       `json:"mounts"`
	Limits        ContainerLimits        `json:"limits"`
	Security      ContainerSecurity      `json:"security"`
	Logging       ContainerLogging       `json:"logging"`
	Compose       *ContainerCompose      `json:"compose,omitempty"`
	SizeRWBytes   *int64                 `json:"size_rw_bytes,omitempty"`
	SizeRootBytes *int64                 `json:"size_root_fs_bytes,omitempty"`
}

// ContainerImage names the image a container was created from. Reference
// is what the container was created with; Digests are the registry digests
// of the image ID, empty for locally built images.
type ContainerImage struct {
	Reference string     `json:"reference"`
	ID        string     `json:"id"`
	Digests   []string   `json:"digests"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	SizeBytes *int64     `json:"size_bytes,omitempty"`
	Source    string     `json:"source,omitempty"`
	Revision  string     `json:"revision,omitempty"`
}

// ContainerCommand is how the container's main process is started.
type ContainerCommand struct {
	Path        string   `json:"path"`
	Args        []string `json:"args"`
	Entrypoint  []string `json:"entrypoint"`
	Cmd         []string `json:"cmd"`
	WorkingDir  string   `json:"working_dir,omitempty"`
	User        string   `json:"user,omitempty"`
	TTY         bool     `json:"tty"`
	OpenStdin   bool     `json:"open_stdin"`
	StopSignal  string   `json:"stop_signal,omitempty"`
	StopTimeout *int     `json:"stop_timeout_seconds,omitempty"`
}

// ContainerStateDetails is the runtime state of a container.
type ContainerStateDetails struct {
	Status       string           `json:"status"`
	Running      bool             `json:"running"`
	Paused       bool             `json:"paused"`
	Restarting   bool             `json:"restarting"`
	OOMKilled    bool             `json:"oom_killed"`
	Dead         bool             `json:"dead"`
	PID          int              `json:"pid"`
	ExitCode     int              `json:"exit_code"`
	Error        string           `json:"error,omitempty"`
	StartedAt    *time.Time       `json:"started_at,omitempty"`
	FinishedAt   *time.Time       `json:"finished_at,omitempty"`
	RestartCount int              `json:"restart_count"`
	Health       *ContainerHealth `json:"health,omitempty"`
}

// ContainerHealth is the state of the container's health check.
type ContainerHealth struct {
	Status        string `json:"status"`
	FailingStreak int    `json:"failing_streak"`
	LastExitCode  *int   `json:"last_exit_code,omitempty"`
	LastOutput    string `json:"last_output,omitempty"`
}

// ContainerRestartPolicy is Docker's restart policy.
type ContainerRestartPolicy struct {
	Name              string `json:"name"`
	MaximumRetryCount int    `json:"maximum_retry_count"`
}

// ContainerNetwork is how the container is attached to networks.
type ContainerNetwork struct {
	Mode       string                       `json:"mode"`
	Hostname   string                       `json:"hostname,omitempty"`
	DNS        []string                     `json:"dns"`
	ExtraHosts []string                     `json:"extra_hosts"`
	Networks   []ContainerNetworkAttachment `json:"networks"`
}

// ContainerNetworkAttachment is one network the container is attached to.
type ContainerNetworkAttachment struct {
	Name        string   `json:"name"`
	NetworkID   string   `json:"network_id"`
	IPv4Address string   `json:"ipv4_address,omitempty"`
	IPv4Prefix  int      `json:"ipv4_prefix_length,omitempty"`
	IPv4Gateway string   `json:"ipv4_gateway,omitempty"`
	IPv6Address string   `json:"ipv6_address,omitempty"`
	IPv6Prefix  int      `json:"ipv6_prefix_length,omitempty"`
	IPv6Gateway string   `json:"ipv6_gateway,omitempty"`
	MACAddress  string   `json:"mac_address,omitempty"`
	Aliases     []string `json:"aliases"`
}

// ContainerMount is one bind mount, volume, or tmpfs of the container.
type ContainerMount struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	Driver      string `json:"driver,omitempty"`
	Mode        string `json:"mode,omitempty"`
	ReadWrite   bool   `json:"read_write"`
	Propagation string `json:"propagation,omitempty"`
}

// ContainerLimits are the resource limits of the container; zero means no
// limit was set.
type ContainerLimits struct {
	MemoryBytes            int64  `json:"memory_bytes"`
	MemoryReservationBytes int64  `json:"memory_reservation_bytes"`
	MemorySwapBytes        int64  `json:"memory_swap_bytes"`
	NanoCPUs               int64  `json:"nano_cpus"`
	CPUShares              int64  `json:"cpu_shares"`
	CPUQuota               int64  `json:"cpu_quota"`
	CPUPeriod              int64  `json:"cpu_period"`
	CpusetCPUs             string `json:"cpuset_cpus,omitempty"`
	PIDsLimit              *int64 `json:"pids_limit,omitempty"`
	ShmSizeBytes           int64  `json:"shm_size_bytes"`
}

// ContainerSecurity lists the settings that widen or narrow the container's
// isolation.
type ContainerSecurity struct {
	Privileged      bool     `json:"privileged"`
	ReadOnlyRootFS  bool     `json:"read_only_root_fs"`
	CapAdd          []string `json:"cap_add"`
	CapDrop         []string `json:"cap_drop"`
	SecurityOptions []string `json:"security_options"`
	PIDMode         string   `json:"pid_mode,omitempty"`
	IPCMode         string   `json:"ipc_mode,omitempty"`
	UTSMode         string   `json:"uts_mode,omitempty"`
	UsernsMode      string   `json:"userns_mode,omitempty"`
	Devices         []string `json:"devices"`
	AppArmorProfile string   `json:"apparmor_profile,omitempty"`
}

// ContainerLogging is the container's log driver.
type ContainerLogging struct {
	Driver  string            `json:"driver"`
	Options map[string]string `json:"options"`
}

// ContainerCompose is set for containers created by Docker Compose.
type ContainerCompose struct {
	Project     string   `json:"project"`
	Service     string   `json:"service,omitempty"`
	WorkingDir  string   `json:"working_dir,omitempty"`
	ConfigFiles []string `json:"config_files"`
}
