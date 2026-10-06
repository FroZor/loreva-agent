// Package containerinfo lists the node's containers and describes one
// container the way docker inspect does, through the Docker Engine API.
package containerinfo

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	// maxText bounds one string taken from Docker, maxItems one list.
	maxText  = 32 * 1024
	maxItems = 4096
	// maxHealthOutput bounds the last health check output.
	maxHealthOutput = 4096
)

// Compose and OCI labels the agent reads.
const (
	labelComposeProject     = "com.docker.compose.project"
	labelComposeService     = "com.docker.compose.service"
	labelComposeWorkingDir  = "com.docker.compose.project.working_dir"
	labelComposeConfigFiles = "com.docker.compose.project.config_files"
	labelImageSource        = "org.opencontainers.image.source"
	labelImageRevision      = "org.opencontainers.image.revision"
)

var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Engine is the part of the Docker client the service uses.
type Engine interface {
	Info(ctx context.Context, options client.InfoOptions) (client.SystemInfoResult, error)
	ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error)
	ContainerInspect(ctx context.Context, containerID string, options client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	ImageInspect(ctx context.Context, imageID string, options ...client.ImageInspectOption) (client.ImageInspectResult, error)
}

// Service answers containers.list and container.inspect.
type Service struct {
	engine Engine
}

// New returns a service that talks to Docker through engine.
func New(engine Engine) *Service {
	return &Service{engine: engine}
}

// List returns the runtime and every container, stopped ones included.
func (s *Service) List(ctx context.Context) (protocol.ContainersListResult, error) {
	info, err := s.engine.Info(ctx, client.InfoOptions{})
	if err != nil {
		return protocol.ContainersListResult{}, fmt.Errorf("read Docker info: %w", err)
	}
	listed, err := s.engine.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return protocol.ContainersListResult{}, fmt.Errorf("list containers: %w", err)
	}

	containers := listed.Items
	slices.SortFunc(containers, func(a, b container.Summary) int {
		return strings.Compare(containerName(a.Names), containerName(b.Names))
	})
	result := protocol.ContainersListResult{
		Engine: engine(info),
		Items:  make([]protocol.ContainerSummary, 0, min(len(containers), protocol.MaxContainersListItems)),
	}
	if len(containers) > protocol.MaxContainersListItems {
		containers = containers[:protocol.MaxContainersListItems]
		result.Truncated = true
	}

	for _, item := range containers {
		result.Items = append(result.Items, summary(item))
	}

	return result, nil
}

// Inspect describes one container. Size asks Docker to measure its layers.
func (s *Service) Inspect(ctx context.Context, containerID string, size bool) (protocol.ContainerDetails, error) {
	if !containerIDPattern.MatchString(containerID) {
		return protocol.ContainerDetails{}, containerio.ErrInvalidContainerID
	}

	inspected, err := s.engine.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{Size: size})
	if errdefs.IsNotFound(err) {
		return protocol.ContainerDetails{}, containerio.ErrNotFound
	}
	if err != nil {
		return protocol.ContainerDetails{}, fmt.Errorf("inspect container: %w", err)
	}
	response := inspected.Container
	if response.Config == nil || response.State == nil || response.HostConfig == nil {
		return protocol.ContainerDetails{}, errors.New("Docker returned an incomplete container description")
	}

	details := describe(response)
	// The image may have been removed or retagged since; the container's
	// own references still stand then.
	if image, err := s.engine.ImageInspect(ctx, response.Image); err == nil {
		describeImage(&details.Image, image)
	}

	return details, nil
}

func engine(result client.SystemInfoResult) protocol.ContainerEngine {
	info := result.Info

	return protocol.ContainerEngine{
		Runtime:           "docker",
		Version:           text(info.ServerVersion),
		OperatingSystem:   text(info.OperatingSystem),
		KernelVersion:     text(info.KernelVersion),
		Architecture:      text(info.Architecture),
		StorageDriver:     text(info.Driver),
		LoggingDriver:     text(info.LoggingDriver),
		CgroupDriver:      text(info.CgroupDriver),
		CgroupVersion:     text(info.CgroupVersion),
		DefaultRuntime:    text(info.DefaultRuntime),
		RootDirectory:     text(info.DockerRootDir),
		SecurityOptions:   texts(info.SecurityOptions),
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		Warnings:          texts(info.Warnings),
	}
}

func summary(item container.Summary) protocol.ContainerSummary {
	result := protocol.ContainerSummary{
		ContainerID:    item.ID,
		Name:           text(containerName(item.Names)),
		Image:          text(item.Image),
		ImageID:        text(item.ImageID),
		State:          text(string(item.State)),
		Status:         text(item.Status),
		Health:         string(container.NoHealthcheck),
		CreatedAt:      time.Unix(item.Created, 0).UTC(),
		Ports:          make([]protocol.ContainerPort, 0, len(item.Ports)),
		ComposeProject: text(item.Labels[labelComposeProject]),
		ComposeService: text(item.Labels[labelComposeService]),
	}
	if item.Health != nil && item.Health.Status != "" {
		result.Health = string(item.Health.Status)
	}
	for _, port := range item.Ports {
		published := protocol.ContainerPort{ContainerPort: port.PrivatePort, Protocol: port.Type, HostPort: port.PublicPort}
		if port.IP.IsValid() {
			published.HostIP = port.IP.String()
		}
		result.Ports = append(result.Ports, published)
	}
	sortPorts(result.Ports)

	return result
}

func describe(response container.InspectResponse) protocol.ContainerDetails {
	config, host, state := response.Config, response.HostConfig, response.State

	details := protocol.ContainerDetails{
		ContainerID: response.ID,
		Name:        text(strings.TrimPrefix(response.Name, "/")),
		CreatedAt:   parseTime(response.Created),
		Platform:    text(response.Platform),
		Image: protocol.ContainerImage{
			Reference: text(config.Image),
			ID:        text(response.Image),
			Digests:   []string{},
		},
		Command: protocol.ContainerCommand{
			Path:        text(response.Path),
			Args:        texts(response.Args),
			Entrypoint:  texts(config.Entrypoint),
			Cmd:         texts(config.Cmd),
			WorkingDir:  text(config.WorkingDir),
			User:        text(config.User),
			TTY:         config.Tty,
			OpenStdin:   config.OpenStdin,
			StopSignal:  text(config.StopSignal),
			StopTimeout: config.StopTimeout,
		},
		Env:    texts(config.Env),
		Labels: textMap(config.Labels),
		State: protocol.ContainerStateDetails{
			Status:       text(string(state.Status)),
			Running:      state.Running,
			Paused:       state.Paused,
			Restarting:   state.Restarting,
			OOMKilled:    state.OOMKilled,
			Dead:         state.Dead,
			PID:          state.Pid,
			ExitCode:     state.ExitCode,
			Error:        text(state.Error),
			StartedAt:    optionalTime(state.StartedAt),
			FinishedAt:   optionalTime(state.FinishedAt),
			RestartCount: response.RestartCount,
			Health:       health(state.Health),
		},
		RestartPolicy: protocol.ContainerRestartPolicy{
			Name:              text(string(host.RestartPolicy.Name)),
			MaximumRetryCount: host.RestartPolicy.MaximumRetryCount,
		},
		AutoRemove: host.AutoRemove,
		Ports:      ports(config.ExposedPorts, response.NetworkSettings, host.PortBindings),
		Network:    networkDetails(config, host, response.NetworkSettings),
		Mounts:     mounts(response.Mounts),
		Limits: protocol.ContainerLimits{
			MemoryBytes:            host.Memory,
			MemoryReservationBytes: host.MemoryReservation,
			MemorySwapBytes:        host.MemorySwap,
			NanoCPUs:               host.NanoCPUs,
			CPUShares:              host.CPUShares,
			CPUQuota:               host.CPUQuota,
			CPUPeriod:              host.CPUPeriod,
			CpusetCPUs:             text(host.CpusetCpus),
			PIDsLimit:              host.PidsLimit,
			ShmSizeBytes:           host.ShmSize,
		},
		Security: protocol.ContainerSecurity{
			Privileged:      host.Privileged,
			ReadOnlyRootFS:  host.ReadonlyRootfs,
			CapAdd:          texts(host.CapAdd),
			CapDrop:         texts(host.CapDrop),
			SecurityOptions: texts(host.SecurityOpt),
			PIDMode:         text(string(host.PidMode)),
			IPCMode:         text(string(host.IpcMode)),
			UTSMode:         text(string(host.UTSMode)),
			UsernsMode:      text(string(host.UsernsMode)),
			Devices:         devices(host.Devices),
			AppArmorProfile: text(response.AppArmorProfile),
		},
		Logging: protocol.ContainerLogging{
			Driver:  text(host.LogConfig.Type),
			Options: textMap(host.LogConfig.Config),
		},
		Compose:       compose(config.Labels),
		SizeRWBytes:   response.SizeRw,
		SizeRootBytes: response.SizeRootFs,
	}
	if details.Image.Reference == "" {
		details.Image.Reference = details.Image.ID
	}

	return details
}

func describeImage(target *protocol.ContainerImage, image client.ImageInspectResult) {
	target.Digests = texts(image.RepoDigests)
	if created := parseTime(image.Created); !created.IsZero() {
		target.CreatedAt = &created
	}
	size := image.Size
	target.SizeBytes = &size
	if image.Config != nil {
		target.Source = text(image.Config.Labels[labelImageSource])
		target.Revision = text(image.Config.Labels[labelImageRevision])
	}
}

func health(state *container.Health) *protocol.ContainerHealth {
	if state == nil || state.Status == "" {
		return nil
	}

	result := &protocol.ContainerHealth{Status: string(state.Status), FailingStreak: state.FailingStreak}
	if count := len(state.Log); count > 0 && state.Log[count-1] != nil {
		last := state.Log[count-1]
		exitCode := last.ExitCode
		result.LastExitCode = &exitCode
		result.LastOutput = truncate(last.Output, maxHealthOutput)
	}

	return result
}

// ports lists every exposed or published port; a port without a host
// binding has no host side.
func ports(exposed network.PortSet, settings *container.NetworkSettings, configured network.PortMap) []protocol.ContainerPort {
	bindings := configured
	if settings != nil && len(settings.Ports) > 0 {
		bindings = settings.Ports
	}

	result := make([]protocol.ContainerPort, 0, len(exposed)+len(bindings))
	seen := make(map[network.Port]bool, len(exposed)+len(bindings))
	for port, hosts := range bindings {
		seen[port] = true
		if len(hosts) == 0 {
			result = append(result, protocol.ContainerPort{ContainerPort: port.Num(), Protocol: string(port.Proto())})
		}
		for _, host := range hosts {
			published := protocol.ContainerPort{ContainerPort: port.Num(), Protocol: string(port.Proto())}
			if host.HostIP.IsValid() {
				published.HostIP = host.HostIP.String()
			}
			if number, err := parsePort(host.HostPort); err == nil {
				published.HostPort = number
			}
			result = append(result, published)
		}
	}
	for port := range exposed {
		if !seen[port] {
			result = append(result, protocol.ContainerPort{ContainerPort: port.Num(), Protocol: string(port.Proto())})
		}
	}
	sortPorts(result)

	return result
}

func networkDetails(config *container.Config, host *container.HostConfig, settings *container.NetworkSettings) protocol.ContainerNetwork {
	result := protocol.ContainerNetwork{
		Mode:       text(string(host.NetworkMode)),
		Hostname:   text(config.Hostname),
		DNS:        make([]string, 0, len(host.DNS)),
		ExtraHosts: texts(host.ExtraHosts),
		Networks:   []protocol.ContainerNetworkAttachment{},
	}
	for _, server := range host.DNS {
		result.DNS = append(result.DNS, server.String())
	}
	if settings == nil {
		return result
	}

	for name, endpoint := range settings.Networks {
		if endpoint == nil {
			continue
		}
		attachment := protocol.ContainerNetworkAttachment{
			Name:       text(name),
			NetworkID:  text(endpoint.NetworkID),
			IPv4Prefix: endpoint.IPPrefixLen,
			IPv6Prefix: endpoint.GlobalIPv6PrefixLen,
			MACAddress: text(endpoint.MacAddress.String()),
			Aliases:    texts(endpoint.Aliases),
		}
		attachment.IPv4Address = address(endpoint.IPAddress.IsValid(), endpoint.IPAddress.String())
		attachment.IPv4Gateway = address(endpoint.Gateway.IsValid(), endpoint.Gateway.String())
		attachment.IPv6Address = address(endpoint.GlobalIPv6Address.IsValid(), endpoint.GlobalIPv6Address.String())
		attachment.IPv6Gateway = address(endpoint.IPv6Gateway.IsValid(), endpoint.IPv6Gateway.String())
		result.Networks = append(result.Networks, attachment)
	}
	slices.SortFunc(result.Networks, func(a, b protocol.ContainerNetworkAttachment) int { return strings.Compare(a.Name, b.Name) })

	return result
}

func mounts(points []container.MountPoint) []protocol.ContainerMount {
	result := make([]protocol.ContainerMount, 0, min(len(points), maxItems))
	for _, point := range points[:min(len(points), maxItems)] {
		result = append(result, protocol.ContainerMount{
			Type:        text(string(point.Type)),
			Name:        text(point.Name),
			Source:      text(point.Source),
			Destination: text(point.Destination),
			Driver:      text(point.Driver),
			Mode:        text(point.Mode),
			ReadWrite:   point.RW,
			Propagation: text(string(point.Propagation)),
		})
	}
	slices.SortFunc(result, func(a, b protocol.ContainerMount) int { return strings.Compare(a.Destination, b.Destination) })

	return result
}

func devices(mappings []container.DeviceMapping) []string {
	result := make([]string, 0, min(len(mappings), maxItems))
	for _, mapping := range mappings[:min(len(mappings), maxItems)] {
		result = append(result, text(mapping.PathOnHost+":"+mapping.PathInContainer+":"+mapping.CgroupPermissions))
	}

	return result
}

func compose(labels map[string]string) *protocol.ContainerCompose {
	project := labels[labelComposeProject]
	if project == "" {
		return nil
	}

	result := &protocol.ContainerCompose{
		Project:     text(project),
		Service:     text(labels[labelComposeService]),
		WorkingDir:  text(labels[labelComposeWorkingDir]),
		ConfigFiles: []string{},
	}
	if files := labels[labelComposeConfigFiles]; files != "" {
		result.ConfigFiles = texts(strings.Split(files, ","))
	}

	return result
}

// containerName is the first name Docker lists, without its leading slash.
func containerName(names []string) string {
	if len(names) == 0 {
		return ""
	}

	return strings.TrimPrefix(names[0], "/")
}

func sortPorts(ports []protocol.ContainerPort) {
	slices.SortFunc(ports, func(a, b protocol.ContainerPort) int {
		if a.ContainerPort != b.ContainerPort {
			return int(a.ContainerPort) - int(b.ContainerPort)
		}
		if a.Protocol != b.Protocol {
			return strings.Compare(a.Protocol, b.Protocol)
		}
		return strings.Compare(a.HostIP, b.HostIP)
	})
}

func parsePort(value string) (uint16, error) {
	number, err := strconv.ParseUint(value, 10, 16)
	if err != nil || number == 0 {
		return 0, errors.New("not a port")
	}

	return uint16(number), nil
}

// parseTime reads Docker's RFC 3339 times; Docker reports the zero time
// as 0001-01-01T00:00:00Z.
func parseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Year() <= 1 {
		return time.Time{}
	}

	return parsed.UTC()
}

func optionalTime(value string) *time.Time {
	parsed := parseTime(value)
	if parsed.IsZero() {
		return nil
	}

	return &parsed
}

func address(valid bool, value string) string {
	if !valid {
		return ""
	}

	return value
}

func text(value string) string {
	return truncate(value, maxText)
}

func texts(values []string) []string {
	result := make([]string, 0, min(len(values), maxItems))
	for _, value := range values[:min(len(values), maxItems)] {
		result = append(result, text(value))
	}

	return result
}

func textMap(values map[string]string) map[string]string {
	result := make(map[string]string, min(len(values), maxItems))
	for key, value := range values {
		if len(result) == maxItems {
			break
		}
		result[text(key)] = text(value)
	}

	return result
}

// truncate cuts value to at most limit bytes without splitting a character
// and replaces invalid UTF-8, which JSON cannot carry faithfully.
func truncate(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}

	return value[:limit]
}
