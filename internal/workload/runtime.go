package workload

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	composetypes "github.com/compose-spec/compose-go/v2/types"
	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/dockerapi"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	managedLabel            = "dev.loreva.managed"
	workloadIDLabel         = "dev.loreva.workload_id"
	planDigestLabel         = "dev.loreva.plan_digest"
	workloadFormatLabel     = "dev.loreva.format"
	runtimeOperationTimeout = 15 * time.Minute
)

type dockerRuntime struct {
	client       *client.Client
	compose      *composeCLI
	composeError error
}

type activeWorkload struct {
	format     string
	planDigest string
	containers []string
}

func openDockerRuntime(ctx context.Context, stateRoot string) (*dockerRuntime, error) {
	engine, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("create Docker client: %w", err)
	}
	if err := dockerapi.ValidateEndpoint(engine.DaemonHost()); err != nil {
		_ = engine.Close()
		return nil, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = engine.Ping(probeCtx, client.PingOptions{})
	cancel()
	if err != nil {
		_ = engine.Close()
		return nil, fmt.Errorf("connect to Docker Engine: %w", err)
	}

	compose, composeErr := openComposeCLI(ctx, engine.DaemonHost(), stateRoot)

	return &dockerRuntime{client: engine, compose: compose, composeError: composeErr}, nil
}

func (runtime *dockerRuntime) close() error {
	if runtime == nil || runtime.client == nil {
		return nil
	}

	return runtime.client.Close()
}

func (runtime *dockerRuntime) execute(
	ctx context.Context,
	store planStore,
	plan *storedPlan,
	progress func(string),
) error {
	operationCtx, cancel := context.WithTimeout(ctx, runtimeOperationTimeout)
	defer cancel()

	if err := runtime.ensureSameController(operationCtx, store, plan); err != nil {
		return err
	}

	switch plan.Format {
	case protocol.WorkloadFormatOCI:
		return runtime.executeOCI(operationCtx, plan, progress)
	case protocol.WorkloadFormatCompose:
		return runtime.executeCompose(operationCtx, plan, progress)
	case protocol.WorkloadFormatDockerfile:
		return runtime.executeDockerfile(operationCtx, plan, progress)
	case protocol.WorkloadFormatPterodactylEgg:
		return runtime.executeEgg(operationCtx, plan, progress)
	default:
		return fmt.Errorf("unsupported stored workload format %q", plan.Format)
	}
}

func (runtime *dockerRuntime) executeOCI(
	ctx context.Context,
	plan *storedPlan,
	progress func(string),
) error {
	input := plan.Payload.OCI
	if input == nil {
		return errors.New("stored OCI plan is missing input")
	}

	if err := runtime.ensureContainerAbsent(ctx, plan.WorkloadID); err != nil {
		return err
	}

	progress("pull_image")
	pull, err := runtime.client.ImagePull(ctx, input.Image, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull workload image: %w", err)
	}
	if err := pull.Wait(ctx); err != nil {
		return fmt.Errorf("wait for workload image pull: %w", err)
	}

	return runtime.createWorkloadContainer(ctx, plan, *input, progress)
}

func (runtime *dockerRuntime) ensureContainerAbsent(ctx context.Context, workloadID string) error {
	name := workloadResourceName(workloadID)
	if _, err := runtime.client.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); err == nil {
		return errors.New("managed workload container already exists")
	} else if !errdefs.IsNotFound(err) {
		return fmt.Errorf("inspect workload container: %w", err)
	}

	return nil
}

func (runtime *dockerRuntime) createWorkloadContainer(
	ctx context.Context,
	plan *storedPlan,
	input protocol.OCIWorkloadInput,
	progress func(string),
) error {
	name := workloadResourceName(plan.WorkloadID)

	labels := workloadLabels(plan)
	mounts, err := runtime.prepareMounts(ctx, plan, input.Mounts)
	if err != nil {
		return err
	}
	exposedPorts, portBindings, err := dockerPorts(input.Ports)
	if err != nil {
		return err
	}

	environment := make([]string, 0, len(input.Environment))
	for key, value := range input.Environment {
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)
	pidsLimit := input.Resources.PIDsLimit
	initProcess := true

	progress("create_container")
	created, err := runtime.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image: input.Image, Env: environment, Cmd: input.Command,
			ExposedPorts: exposedPorts, Labels: labels,
		},
		HostConfig: &container.HostConfig{
			PortBindings:  portBindings,
			Mounts:        mounts,
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			Resources: container.Resources{
				NanoCPUs:  input.Resources.CPUMillicores * 1_000_000,
				Memory:    input.Resources.MemoryBytes,
				PidsLimit: &pidsLimit,
			},
			SecurityOpt: []string{"no-new-privileges:true"},
			Init:        &initProcess,
		},
	})
	if err != nil {
		return fmt.Errorf("create workload container: %w", err)
	}
	progress("start_container")
	if _, err := runtime.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start workload container: %w", err)
	}

	return nil
}

func (runtime *dockerRuntime) executeCompose(
	ctx context.Context,
	plan *storedPlan,
	progress func(string),
) error {
	if runtime.compose == nil {
		return fmt.Errorf("Docker Compose is unavailable: %w", runtime.composeError)
	}

	project, err := composeProjectFromPlan(ctx, plan)
	if err != nil {
		return err
	}
	if err := runtime.ensureComposeOwnership(ctx, project.Name); err != nil {
		return err
	}

	progress("compose_up")
	return runtime.compose.runProject(ctx, plan.ProjectDir, project,
		"up", "--detach", "--wait", "--wait-timeout", "300",
	)
}

func composeProjectFromPlan(ctx context.Context, plan *storedPlan) (*composetypes.Project, error) {
	input := plan.Payload.Compose
	if input == nil {
		return nil, errors.New("stored Compose plan is missing input")
	}
	project, err := loadComposeProject(ctx, plan.ProjectDir, plan.ProjectFile, plan.ProjectName, *input)
	if err != nil {
		return nil, err
	}

	labels := workloadLabels(plan)
	for name, service := range project.Services {
		if service.Labels == nil {
			service.Labels = composetypes.Labels{}
		}
		for key, value := range labels {
			if _, reserved := service.Labels[key]; reserved {
				return nil, fmt.Errorf("service %s defines reserved Loreva label %s", name, key)
			}
			service.Labels[key] = value
		}
		project.Services[name] = service
	}

	return project, nil
}

func (runtime *dockerRuntime) lifecycle(
	ctx context.Context,
	store planStore,
	portalID string,
	nodeID string,
	workloadID string,
	action string,
	timeoutSeconds int,
) error {
	operationCtx, cancel := context.WithTimeout(ctx, runtimeOperationTimeout)
	defer cancel()

	active, err := runtime.findActive(operationCtx, workloadID)
	if err != nil {
		return err
	}
	plan, err := store.loadPlan(active.planDigest)
	if err != nil {
		return fmt.Errorf("load active workload plan: %w", err)
	}
	if plan.PortalID != portalID || plan.NodeID != nodeID ||
		plan.WorkloadID != workloadID || plan.Format != active.format {
		return errors.New("active workload does not match its stored plan")
	}

	if plan.Format == protocol.WorkloadFormatPterodactylEgg {
		return runtime.lifecycleEgg(operationCtx, active.containers, plan, action, timeoutSeconds)
	}
	if plan.Format != protocol.WorkloadFormatCompose {
		return runtime.lifecycleContainers(operationCtx, active.containers, action, timeoutSeconds)
	}

	project, err := composeProjectFromPlan(operationCtx, plan)
	if err != nil {
		return err
	}
	if err := runtime.ensureComposeOwnership(operationCtx, project.Name); err != nil {
		return err
	}
	if runtime.compose == nil {
		return fmt.Errorf("Docker Compose is unavailable: %w", runtime.composeError)
	}

	timeout := strconv.Itoa(timeoutSeconds)
	switch action {
	case "stop":
		return runtime.compose.runProject(operationCtx, plan.ProjectDir, project, "stop", "--timeout", timeout)
	case "restart":
		return runtime.compose.runProject(operationCtx, plan.ProjectDir, project, "restart", "--timeout", timeout)
	case "delete":
		return runtime.compose.runProject(operationCtx, plan.ProjectDir, project, "down", "--timeout", timeout)
	default:
		return fmt.Errorf("unsupported Compose lifecycle action %q", action)
	}
}

func (runtime *dockerRuntime) lifecycleContainers(
	ctx context.Context,
	containerIDs []string,
	action string,
	timeoutSeconds int,
) error {
	seconds := timeoutSeconds
	for _, containerID := range containerIDs {
		switch action {
		case "stop":
			if _, err := runtime.client.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: &seconds}); err != nil {
				return fmt.Errorf("stop workload container: %w", err)
			}
		case "restart":
			if _, err := runtime.client.ContainerRestart(ctx, containerID, client.ContainerRestartOptions{Timeout: &seconds}); err != nil {
				return fmt.Errorf("restart workload container: %w", err)
			}
		case "delete":
			if _, err := runtime.client.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: &seconds}); err != nil && !errdefs.IsNotFound(err) {
				return fmt.Errorf("stop workload container before delete: %w", err)
			}
			if _, err := runtime.client.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{}); err != nil && !errdefs.IsNotFound(err) {
				return fmt.Errorf("delete workload container: %w", err)
			}
		default:
			return fmt.Errorf("unsupported workload lifecycle action %q", action)
		}
	}

	return nil
}

func (runtime *dockerRuntime) findActive(ctx context.Context, workloadID string) (*activeWorkload, error) {
	result, err := runtime.client.ContainerList(ctx, client.ContainerListOptions{
		All: true,
		Filters: make(client.Filters).Add(
			"label", managedLabel+"=true", workloadIDLabel+"="+workloadID,
		),
	})
	if err != nil {
		return nil, fmt.Errorf("list managed workload containers: %w", err)
	}
	if len(result.Items) == 0 {
		return nil, errors.New("managed workload does not exist")
	}

	active := &activeWorkload{containers: make([]string, 0, len(result.Items))}
	for _, summary := range result.Items {
		format := summary.Labels[workloadFormatLabel]
		planDigest := summary.Labels[planDigestLabel]
		if format == "" || planDigest == "" ||
			(active.format != "" && active.format != format) ||
			(active.planDigest != "" && active.planDigest != planDigest) {
			return nil, errors.New("managed workload resources have inconsistent ownership labels")
		}
		active.format = format
		active.planDigest = planDigest
		active.containers = append(active.containers, summary.ID)
	}

	return active, nil
}

func (runtime *dockerRuntime) ensureComposeOwnership(ctx context.Context, projectName string) error {
	result, err := runtime.client.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", "com.docker.compose.project="+projectName),
	})
	if err != nil {
		return fmt.Errorf("inspect existing Compose project: %w", err)
	}
	for _, summary := range result.Items {
		if summary.Labels[managedLabel] != "true" {
			return errors.New("Compose project name is already owned outside Loreva")
		}
	}

	return nil
}

func (runtime *dockerRuntime) prepareMounts(
	ctx context.Context,
	plan *storedPlan,
	inputs []protocol.WorkloadMount,
) ([]mount.Mount, error) {
	result := make([]mount.Mount, 0, len(inputs))
	labels := workloadLabels(plan)

	for index, input := range inputs {
		mountType := mount.Type(input.Type)
		source := input.Source
		if input.Type == "volume" && source == "" {
			source = workloadResourceName(plan.WorkloadID) + "-data-" + strconv.Itoa(index+1)
			if _, err := runtime.client.VolumeCreate(ctx, client.VolumeCreateOptions{
				Name: source, Labels: labels,
			}); err != nil {
				return nil, fmt.Errorf("create managed workload volume: %w", err)
			}
		}

		result = append(result, mount.Mount{
			Type: mountType, Source: source, Target: input.Target, ReadOnly: input.ReadOnly,
		})
	}

	return result, nil
}

func dockerPorts(inputs []protocol.WorkloadPort) (network.PortSet, network.PortMap, error) {
	exposed := network.PortSet{}
	bindings := network.PortMap{}

	for _, input := range inputs {
		port, ok := network.PortFrom(input.ContainerPort, network.IPProtocol(input.Protocol))
		if !ok {
			return nil, nil, errors.New("invalid container port")
		}
		hostIP := netip.Addr{}
		if input.HostIP != "" {
			var err error
			hostIP, err = netip.ParseAddr(input.HostIP)
			if err != nil {
				return nil, nil, err
			}
		}

		exposed[port] = struct{}{}
		bindings[port] = []network.PortBinding{{
			HostIP: hostIP, HostPort: strconv.FormatUint(uint64(input.HostPort), 10),
		}}
	}

	return exposed, bindings, nil
}

func workloadLabels(plan *storedPlan) map[string]string {
	return map[string]string{
		managedLabel: "true", workloadIDLabel: plan.WorkloadID,
		planDigestLabel: plan.PlanDigest, workloadFormatLabel: plan.Format,
	}
}

func workloadResourceName(workloadID string) string {
	return "loreva-" + strings.ReplaceAll(workloadID, "-", "")
}

// ensureSameController refuses to execute a plan when containers or volumes
// of its workload ID were created under another controller's plan. Resource
// names depend only on the workload ID, so without this check a paired device
// could recreate a portal workload, or mount its preserved volumes, by
// reusing the workload ID, and the other way round.
func (runtime *dockerRuntime) ensureSameController(ctx context.Context, store planStore, plan *storedPlan) error {
	filters := make(client.Filters).Add("label", managedLabel+"=true", workloadIDLabel+"="+plan.WorkloadID)

	containers, err := runtime.client.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return fmt.Errorf("list managed workload containers: %w", err)
	}
	volumes, err := runtime.client.VolumeList(ctx, client.VolumeListOptions{Filters: filters})
	if err != nil {
		return fmt.Errorf("list managed workload volumes: %w", err)
	}

	digests := make(map[string]struct{})
	for _, summary := range containers.Items {
		digests[summary.Labels[planDigestLabel]] = struct{}{}
	}
	for _, volume := range volumes.Items {
		digests[volume.Labels[planDigestLabel]] = struct{}{}
	}

	for digest := range digests {
		if digest == plan.PlanDigest {
			continue
		}

		owner, err := store.loadPlan(digest)
		if err != nil {
			return fmt.Errorf("workload %s has resources of an unknown plan: %w", plan.WorkloadID, err)
		}
		if owner.PortalID != plan.PortalID {
			return errors.New("workload ID belongs to another controller")
		}
	}

	return nil
}
