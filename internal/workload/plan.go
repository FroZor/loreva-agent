package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	composecli "github.com/compose-spec/compose-go/v2/cli"
	composeloader "github.com/compose-spec/compose-go/v2/loader"
	composetypes "github.com/compose-spec/compose-go/v2/types"
	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"go.yaml.in/yaml/v4"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	minimumMemoryBytes       = 64 << 20
	maximumMemoryBytes       = 1 << 50
	minimumPIDs              = 16
	maximumPIDs              = 1 << 20
	maxEnvironmentValueBytes = 32 << 10
	maxComposeFileBytes      = 4 << 20
)

type storedPlan struct {
	Version      int                          `json:"version"`
	PortalID     string                       `json:"portal_id"`
	NodeID       string                       `json:"node_id"`
	WorkloadID   string                       `json:"workload_id"`
	PlanDigest   string                       `json:"plan_digest"`
	Format       string                       `json:"format"`
	Payload      protocol.WorkloadPlanPayload `json:"payload"`
	ProjectDir   string                       `json:"project_dir,omitempty"`
	ProjectFile  string                       `json:"project_file,omitempty"`
	ProjectName  string                       `json:"project_name,omitempty"`
	ArtifactPath string                       `json:"artifact_path,omitempty"`
	Steps        []protocol.WorkloadPlanStep  `json:"steps"`
	Findings     []protocol.WorkloadFinding   `json:"findings"`
}

type planBuilder struct {
	stateRoot string
	artifacts artifactStore
}

func (builder planBuilder) build(ctx context.Context, command protocol.WorkloadCommand) (*storedPlan, error) {
	var payload protocol.WorkloadPlanPayload
	if err := protocol.DecodeStrict(command.Payload, &payload); err != nil {
		return nil, fmt.Errorf("decode workload plan payload: %w", err)
	}

	plan := &storedPlan{
		Version:    protocol.WorkloadSchemaVersion,
		PortalID:   command.PortalID,
		NodeID:     command.NodeID,
		WorkloadID: command.WorkloadID,
		Format:     payload.Format,
		Payload:    payload,
		Steps:      []protocol.WorkloadPlanStep{},
		Findings:   []protocol.WorkloadFinding{},
	}

	switch payload.Format {
	case protocol.WorkloadFormatOCI:
		if payload.OCI == nil || payload.Compose != nil || payload.Dockerfile != nil || payload.Egg != nil {
			return nil, errors.New("oci plan must contain exactly one oci input")
		}
		if err := builder.planOCI(plan, *payload.OCI); err != nil {
			return nil, err
		}
	case protocol.WorkloadFormatCompose:
		if payload.Compose == nil || payload.OCI != nil || payload.Dockerfile != nil || payload.Egg != nil {
			return nil, errors.New("compose plan must contain exactly one compose input")
		}
		if err := builder.planCompose(ctx, plan, *payload.Compose); err != nil {
			return nil, err
		}
	case protocol.WorkloadFormatDockerfile:
		if payload.Dockerfile == nil || payload.OCI != nil || payload.Compose != nil || payload.Egg != nil {
			return nil, errors.New("dockerfile plan must contain exactly one dockerfile input")
		}
		if err := builder.planDockerfile(ctx, plan, *payload.Dockerfile); err != nil {
			return nil, err
		}
	case protocol.WorkloadFormatPterodactylEgg:
		if payload.Egg == nil || payload.OCI != nil || payload.Compose != nil || payload.Dockerfile != nil {
			return nil, errors.New("pterodactyl Egg plan must contain exactly one pterodactyl_egg input")
		}
		if err := builder.planEgg(ctx, plan, *payload.Egg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported workload format %q", payload.Format)
	}

	plan.PlanDigest = planDigest(plan)

	return plan, nil
}

func (builder planBuilder) planOCI(plan *storedPlan, input protocol.OCIWorkloadInput) error {
	if err := validatePinnedImage(input.Image); err != nil {
		return err
	}
	if err := validateResources(input.Resources); err != nil {
		return err
	}
	if err := validatePorts(input.Ports); err != nil {
		return err
	}
	if err := validateEnvironment(input.Environment); err != nil {
		return err
	}
	if err := validateCommandArguments(input.Command); err != nil {
		return fmt.Errorf("validate OCI command: %w", err)
	}

	findings, err := inspectMounts(input.Mounts, builder.stateRoot, "container")
	if err != nil {
		return err
	}
	plan.Findings = append(plan.Findings, findings...)
	plan.Steps = []protocol.WorkloadPlanStep{
		{Sequence: 1, Action: "pull", Resource: input.Image},
		{Sequence: 2, Action: "create", Resource: "container"},
		{Sequence: 3, Action: "start", Resource: "container"},
	}

	return nil
}

func validateCommandArguments(arguments []string) error {
	if len(arguments) > 256 {
		return errors.New("command exceeds 256 arguments")
	}
	for _, argument := range arguments {
		if len(argument) > 8192 || strings.ContainsRune(argument, '\x00') {
			return errors.New("command contains an oversized argument or NUL")
		}
	}

	return nil
}

func validateEnvironment(environment map[string]string) error {
	if len(environment) > 1024 {
		return errors.New("workload environment exceeds 1024 entries")
	}
	for key, value := range environment {
		if !validEnvironmentName(key) || len(value) > maxEnvironmentValueBytes || strings.ContainsRune(value, '\x00') {
			return errors.New("workload environment contains an invalid key or value")
		}
	}

	return nil
}

func validEnvironmentName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		if index == 0 {
			if !letter && character != '_' {
				return false
			}
			continue
		}
		if !letter && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}

	return true
}

func (builder planBuilder) planCompose(
	ctx context.Context,
	plan *storedPlan,
	input protocol.ComposeWorkloadInput,
) error {
	if err := validateRelativeFile(input.File); err != nil {
		return fmt.Errorf("validate Compose file: %w", err)
	}
	if err := validateEnvironment(input.Environment); err != nil {
		return fmt.Errorf("validate Compose environment: %w", err)
	}
	if err := validateProfiles(input.Profiles); err != nil {
		return err
	}

	artifactPath, err := builder.artifacts.acquire(ctx, input.Artifact)
	if err != nil {
		return err
	}
	digestHex := strings.TrimPrefix(input.Artifact.SHA256, "sha256:")
	projectDir := filepath.Join(builder.stateRoot, "workloads", "projects", digestHex)
	if err := extractTarGzip(artifactPath, projectDir); err != nil {
		if !errors.Is(err, errExtractionExists) {
			return err
		}
	}

	projectFile := filepath.Join(projectDir, filepath.FromSlash(input.File))
	if err := ensureRegularWithin(projectDir, projectFile); err != nil {
		return err
	}

	projectName := composeProjectName(plan.WorkloadID)
	project, err := loadComposeProject(ctx, projectDir, projectFile, projectName, input)
	if err != nil {
		return fmt.Errorf("load Compose project: %w", err)
	}
	if len(project.Services) == 0 {
		return errors.New("Compose project contains no enabled services")
	}
	if len(project.Services) > 512 {
		return errors.New("Compose project exceeds 512 enabled services")
	}

	plan.ProjectDir = projectDir
	plan.ProjectFile = projectFile
	plan.ProjectName = projectName
	plan.Steps = []protocol.WorkloadPlanStep{
		{Sequence: 1, Action: "load", Resource: input.File},
		{Sequence: 2, Action: "pull", Resource: "compose.images"},
		{Sequence: 3, Action: "up", Resource: projectName},
	}

	findings, err := inspectComposeProject(project, builder.stateRoot, projectDir)
	if err != nil {
		return err
	}
	plan.Findings = append(plan.Findings, findings...)

	return nil
}

func validateProfiles(profiles []string) error {
	if len(profiles) > 64 {
		return errors.New("Compose profiles exceed 64 entries")
	}
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if len(profile) == 0 || len(profile) > 128 || strings.ContainsRune(profile, '\x00') {
			return errors.New("Compose profiles contain an invalid value")
		}
		if _, duplicate := seen[profile]; duplicate {
			return errors.New("Compose profiles contain a duplicate")
		}
		seen[profile] = struct{}{}
	}

	return nil
}

func loadComposeProject(
	ctx context.Context,
	workingDir string,
	configPath string,
	projectName string,
	input protocol.ComposeWorkloadInput,
) (*composetypes.Project, error) {
	environment := make([]string, 0, len(input.Environment))
	for key, value := range input.Environment {
		if !validEnvironmentName(key) || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("Compose environment contains an invalid key or value")
		}
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)

	if err := rejectComposeIncludes(configPath); err != nil {
		return nil, err
	}

	preflightOptions, err := composecli.NewProjectOptions(
		[]string{configPath},
		composecli.WithWorkingDirectory(workingDir),
		composecli.WithName(projectName),
		composecli.WithEnv(environment),
		composecli.WithProfiles(input.Profiles),
		composecli.WithLoadOptions(func(options *composeloader.Options) {
			options.SkipResolveEnvironment = true
			options.SkipResolveLabels = true
			options.SkipInclude = true
			options.SkipExtends = true
		}),
	)
	if err != nil {
		return nil, err
	}
	preflight, err := preflightOptions.LoadProject(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateComposePreflight(preflight, workingDir); err != nil {
		return nil, err
	}

	options, err := composecli.NewProjectOptions(
		[]string{configPath},
		composecli.WithWorkingDirectory(workingDir),
		composecli.WithName(projectName),
		composecli.WithEnv(environment),
		composecli.WithProfiles(input.Profiles),
	)
	if err != nil {
		return nil, err
	}

	return options.LoadProject(ctx)
}

func rejectComposeIncludes(configPath string) (resultErr error) {
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("open Compose file for preflight: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxComposeFileBytes+1))
	if err != nil {
		return fmt.Errorf("read Compose file for preflight: %w", err)
	}
	if len(data) == 0 || len(data) > maxComposeFileBytes {
		return fmt.Errorf("Compose file must be between 1 byte and %d bytes", maxComposeFileBytes)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode Compose file for preflight: %w", err)
	}
	if len(document.Content) == 0 || len(document.Content[0].Content) == 0 {
		return errors.New("Compose file is empty")
	}

	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return errors.New("Compose document must be a mapping")
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value == "include" {
			return errors.New("Compose include is unsupported; package all services in one signed project")
		}
	}

	return nil
}

func validateComposePreflight(project *composetypes.Project, projectDir string) error {
	if _, err := inspectComposeFileObjects(project, projectDir); err != nil {
		return err
	}

	for _, serviceName := range project.ServiceNames() {
		service := project.Services[serviceName]
		if err := validateComposeServiceFiles(service, projectDir); err != nil {
			return fmt.Errorf("validate service %s files: %w", serviceName, err)
		}
		if service.Build != nil {
			if err := validateComposeBuild(*service.Build, projectDir); err != nil {
				return fmt.Errorf("validate service %s build: %w", serviceName, err)
			}
		}
		if service.Extends != nil {
			return fmt.Errorf(
				"service %s uses unsupported extends; package the resolved service in the signed project",
				serviceName,
			)
		}
	}

	return nil
}

func inspectComposeProject(
	project *composetypes.Project,
	stateRoot string,
	projectDir string,
) ([]protocol.WorkloadFinding, error) {
	findings := []protocol.WorkloadFinding{}

	resourceFindings, err := inspectComposeFileObjects(project, projectDir)
	if err != nil {
		return nil, err
	}
	findings = append(findings, resourceFindings...)

	instances, err := composeInstanceCount(project)
	if err != nil {
		return nil, err
	}
	if instances > 64 {
		findings = append(findings, finding(
			"large_compose_project", "high", "Compose project starts more than 64 containers", true,
		))
	}
	for name, volume := range project.Volumes {
		if bool(volume.External) {
			findings = append(findings, finding(
				"external_volume", "medium", "Compose project uses existing volume "+name, true,
			))
		}
		if (volume.Driver != "" && volume.Driver != "local") || len(volume.DriverOpts) > 0 {
			findings = append(findings, finding(
				"volume_driver", "high", "Compose volume "+name+" uses custom driver settings", true,
			))
		}
	}
	for name, network := range project.Networks {
		if bool(network.External) {
			findings = append(findings, finding(
				"external_network", "medium", "Compose project joins existing network "+name, true,
			))
		}
	}

	for _, serviceName := range project.ServiceNames() {
		service := project.Services[serviceName]
		if len(service.Ports) > 256 || len(service.Volumes) > 256 || len(service.Environment) > 1024 {
			return nil, fmt.Errorf("service %s exceeds port, volume, or environment limits", serviceName)
		}
		for label := range service.Labels {
			if reservedWorkloadLabel(label) {
				return nil, fmt.Errorf("service %s defines reserved Loreva label %s", serviceName, label)
			}
		}
		if service.Build != nil {
			if err := validateComposeBuild(*service.Build, projectDir); err != nil {
				return nil, fmt.Errorf("validate service %s build: %w", serviceName, err)
			}
			findings = append(findings, finding(
				"compose_build", "high", "service "+serviceName+" builds executable content on the node", true,
			))
		}
		if err := validateComposeServiceFiles(service, projectDir); err != nil {
			return nil, fmt.Errorf("validate service %s files: %w", serviceName, err)
		}
		if service.Provider != nil {
			return nil, fmt.Errorf("service %s uses an unsupported external provider", serviceName)
		}
		if service.Privileged {
			findings = append(findings, finding(
				"privileged_container", "critical", "service "+serviceName+" requests privileged mode", true,
			))
		}
		if service.UseAPISocket {
			findings = append(findings, finding(
				"docker_socket", "critical", "service "+serviceName+" requests the Docker API socket", true,
			))
		}
		if service.NetworkMode == "host" || strings.HasPrefix(service.NetworkMode, "container:") ||
			service.Pid == "host" || strings.HasPrefix(service.Pid, "container:") ||
			service.Ipc == "host" || strings.HasPrefix(service.Ipc, "container:") ||
			service.Cgroup == "host" || service.UserNSMode == "host" || service.Uts == "host" {
			findings = append(findings, finding(
				"host_namespace", "critical", "service "+serviceName+" joins a host namespace", true,
			))
		}
		if len(service.Devices) > 0 || len(service.DeviceCgroupRules) > 0 || composeDeploysDevices(service) {
			findings = append(findings, finding(
				"host_device", "high", "service "+serviceName+" requests host devices", true,
			))
		}
		if len(service.CapAdd) > 0 {
			findings = append(findings, finding(
				"added_capabilities", "critical", "service "+serviceName+" adds Linux capabilities", true,
			))
		}
		if unsafeSecurityOptions(service.SecurityOpt) {
			findings = append(findings, finding(
				"security_profile_override", "critical", "service "+serviceName+" overrides container security profiles", true,
			))
		}
		if len(service.VolumesFrom) > 0 {
			findings = append(findings, finding(
				"volumes_from", "high", "service "+serviceName+" inherits volumes from another container", true,
			))
		}
		if len(service.ExternalLinks) > 0 {
			findings = append(findings, finding(
				"external_links", "high", "service "+serviceName+" links to containers outside the project", true,
			))
		}
		if service.CredentialSpec != nil {
			findings = append(findings, finding(
				"credential_spec", "critical", "service "+serviceName+" requests a host credential specification", true,
			))
		}
		findings = append(findings, inspectComposeHooks(serviceName, service)...)
		if service.CgroupParent != "" || len(service.Sysctls) > 0 || len(service.GroupAdd) > 0 {
			findings = append(findings, finding(
				"host_runtime_tuning", "high", "service "+serviceName+" requests host-coupled runtime settings", true,
			))
		}
		if !composeResourcesBounded(service) {
			findings = append(findings, finding(
				"unbounded_resources", "high", "service "+serviceName+" does not define CPU, memory, and PID limits", true,
			))
		}
		if service.Image != "" {
			if err := validatePinnedImage(service.Image); err != nil {
				findings = append(findings, finding(
					"unpinned_image", "high", "service "+serviceName+" image is not pinned by sha256 digest", true,
				))
			}
		}

		mounts := make([]protocol.WorkloadMount, 0, len(service.Volumes))
		for _, volume := range service.Volumes {
			source := volume.Source
			if volume.Type == "volume" {
				if definition, exists := project.Volumes[volume.Source]; exists && !bool(definition.External) {
					source = ""
				}
			}
			mounts = append(mounts, protocol.WorkloadMount{
				Type: volume.Type, Source: source, Target: volume.Target, ReadOnly: volume.ReadOnly,
			})
		}
		mountFindings, err := inspectMounts(mounts, stateRoot, "service "+serviceName)
		if err != nil {
			return nil, err
		}
		findings = append(findings, mountFindings...)
	}

	return deduplicateFindings(findings), nil
}

func inspectComposeFileObjects(
	project *composetypes.Project,
	projectDir string,
) ([]protocol.WorkloadFinding, error) {
	findings := []protocol.WorkloadFinding{}

	for name, config := range project.Configs {
		if config.File != "" {
			if err := ensureProjectFile(projectDir, config.File, false); err != nil {
				return nil, fmt.Errorf("config %s: %w", name, err)
			}
		}
		if bool(config.External) || config.Driver != "" || len(config.DriverOpts) > 0 {
			findings = append(findings, finding(
				"external_config", "high", "Compose config "+name+" uses a Docker-managed external source", true,
			))
		}
	}

	for name, secret := range project.Secrets {
		if secret.File != "" {
			if err := ensureProjectFile(projectDir, secret.File, false); err != nil {
				return nil, fmt.Errorf("secret %s: %w", name, err)
			}
		}
		if bool(secret.External) || secret.Driver != "" || len(secret.DriverOpts) > 0 {
			findings = append(findings, finding(
				"external_secret", "critical", "Compose secret "+name+" uses a Docker-managed external source", true,
			))
		}
	}

	return findings, nil
}

func validateComposeServiceFiles(service composetypes.ServiceConfig, projectDir string) error {
	for _, environmentFile := range service.EnvFiles {
		if err := ensureProjectFile(projectDir, environmentFile.Path, !bool(environmentFile.Required)); err != nil {
			return fmt.Errorf("env_file: %w", err)
		}
	}
	for _, labelFile := range service.LabelFiles {
		if err := ensureProjectFile(projectDir, labelFile, false); err != nil {
			return fmt.Errorf("label_file: %w", err)
		}
	}
	if service.CredentialSpec != nil && service.CredentialSpec.File != "" {
		if err := ensureProjectFile(projectDir, service.CredentialSpec.File, false); err != nil {
			return fmt.Errorf("credential_spec.file: %w", err)
		}
	}

	return nil
}

func validateComposeBuild(build composetypes.BuildConfig, projectDir string) error {
	contextPath, err := ensureProjectDirectory(projectDir, build.Context)
	if err != nil {
		return fmt.Errorf("context: %w", err)
	}
	if build.Dockerfile != "" && build.DockerfileInline == "" {
		dockerfile := build.Dockerfile
		if !filepath.IsAbs(dockerfile) {
			dockerfile = filepath.Join(contextPath, dockerfile)
		}
		if err := ensureProjectFile(projectDir, dockerfile, false); err != nil {
			return fmt.Errorf("dockerfile: %w", err)
		}
	}
	if len(build.AdditionalContexts) > 0 {
		return errors.New("additional_contexts are unsupported because they bypass the signed build context")
	}
	if len(build.SSH) > 0 {
		return errors.New("SSH forwarding is unsupported for isolated builds")
	}
	if len(build.CacheFrom) > 0 || len(build.CacheTo) > 0 {
		return errors.New("external build caches are unsupported for isolated builds")
	}

	return nil
}

func inspectComposeHooks(
	serviceName string,
	service composetypes.ServiceConfig,
) []protocol.WorkloadFinding {
	findings := []protocol.WorkloadFinding{}
	hooks := append([]composetypes.ServiceHook{}, service.PreStart...)
	hooks = append(hooks, service.PostStart...)
	hooks = append(hooks, service.PreStop...)

	for _, hook := range hooks {
		if hook.Privileged {
			findings = append(findings, finding(
				"privileged_hook", "critical", "service "+serviceName+" defines a privileged lifecycle hook", true,
			))
		}
		if hook.Image != "" {
			if err := validatePinnedImage(hook.Image); err != nil {
				findings = append(findings, finding(
					"unpinned_hook_image", "high", "service "+serviceName+" uses an unpinned lifecycle hook image", true,
				))
			}
		}
	}

	return findings
}

func composeInstanceCount(project *composetypes.Project) (int, error) {
	total := 0
	for _, service := range project.Services {
		replicas := 1
		if service.Scale != nil {
			replicas = *service.Scale
		} else if service.Deploy != nil && service.Deploy.Replicas != nil {
			replicas = *service.Deploy.Replicas
		}
		if replicas < 0 || replicas > 512 || total > 512-replicas {
			return 0, errors.New("Compose project exceeds 512 container instances")
		}
		total += replicas
	}

	return total, nil
}

func composeDeploysDevices(service composetypes.ServiceConfig) bool {
	return service.Deploy != nil && service.Deploy.Resources.Limits != nil &&
		len(service.Deploy.Resources.Limits.Devices) > 0
}

func unsafeSecurityOptions(options []string) bool {
	for _, option := range options {
		normalized := strings.ToLower(strings.ReplaceAll(option, "=", ":"))
		if normalized != "no-new-privileges:true" {
			return true
		}
	}

	return false
}

func composeResourcesBounded(service composetypes.ServiceConfig) bool {
	cpu := service.CPUS > 0
	memory := service.MemLimit > 0
	pids := service.PidsLimit > 0
	if service.Deploy != nil && service.Deploy.Resources.Limits != nil {
		limits := service.Deploy.Resources.Limits
		cpu = cpu || limits.NanoCPUs > 0
		memory = memory || limits.MemoryBytes > 0
		pids = pids || limits.Pids > 0
	}

	return cpu && memory && pids
}

func reservedWorkloadLabel(value string) bool {
	switch value {
	case managedLabel, workloadIDLabel, planDigestLabel, workloadFormatLabel:
		return true
	default:
		return false
	}
}

func validatePinnedImage(value string) error {
	named, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return fmt.Errorf("parse OCI image reference: %w", err)
	}
	digested, ok := named.(reference.Digested)
	if !ok || digested.Digest().Algorithm() != digest.SHA256 || digested.Digest().Validate() != nil {
		return errors.New("OCI image must be pinned by a sha256 digest")
	}

	return nil
}

func validateResources(resources protocol.WorkloadResources) error {
	if resources.CPUMillicores <= 0 || resources.CPUMillicores > 1_000_000 {
		return errors.New("cpu_millicores must be between 1 and 1000000")
	}
	if resources.MemoryBytes < minimumMemoryBytes || resources.MemoryBytes > maximumMemoryBytes {
		return fmt.Errorf("memory_bytes must be between %d and %d", minimumMemoryBytes, maximumMemoryBytes)
	}
	if resources.PIDsLimit < minimumPIDs || resources.PIDsLimit > maximumPIDs {
		return fmt.Errorf("pids_limit must be between %d and %d", minimumPIDs, maximumPIDs)
	}

	return nil
}

func validatePorts(ports []protocol.WorkloadPort) error {
	if len(ports) > 256 {
		return errors.New("workload ports exceed 256 entries")
	}
	seen := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		if port.HostPort == 0 || port.ContainerPort == 0 {
			return errors.New("workload ports must use non-zero host and container ports")
		}
		if port.Protocol != "tcp" && port.Protocol != "udp" {
			return errors.New("workload port protocol must be tcp or udp")
		}
		if port.HostIP != "" {
			address, err := netip.ParseAddr(port.HostIP)
			if err != nil || address.IsMulticast() || address.IsUnspecified() {
				return errors.New("workload host_ip must be a concrete unicast address or empty")
			}
		}

		key := fmt.Sprintf("%s|%d|%s", port.HostIP, port.HostPort, port.Protocol)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("workload contains duplicate host port bindings")
		}
		seen[key] = struct{}{}
	}

	return nil
}

func inspectMounts(
	mounts []protocol.WorkloadMount,
	stateRoot string,
	owner string,
) ([]protocol.WorkloadFinding, error) {
	if len(mounts) > 256 {
		return nil, errors.New("workload mounts exceed 256 entries")
	}
	findings := []protocol.WorkloadFinding{}
	seenTargets := make(map[string]struct{}, len(mounts))

	for _, mount := range mounts {
		if !strings.HasPrefix(mount.Target, "/") || filepath.Clean(filepath.FromSlash(mount.Target)) == string(filepath.Separator) {
			return nil, errors.New("container mount target must be an absolute non-root path")
		}
		if _, duplicate := seenTargets[mount.Target]; duplicate {
			return nil, errors.New("workload contains duplicate mount targets")
		}
		seenTargets[mount.Target] = struct{}{}

		switch mount.Type {
		case "volume":
			if mount.Source != "" {
				findings = append(findings, finding(
					"external_volume", "medium", owner+" uses existing volume "+mount.Source, true,
				))
			}
		case "tmpfs":
			if mount.Source != "" {
				return nil, errors.New("tmpfs mount must not define source")
			}
		case "bind", "npipe":
			if mount.Source == "" {
				return nil, errors.New("bind and npipe mounts require source")
			}
			if dockerSocket(mount.Source) {
				findings = append(findings, finding(
					"docker_socket", "critical", owner+" can control the Docker daemon through "+mount.Source, true,
				))
				continue
			}
			if mount.Type == "bind" {
				if err := validateHostBind(mount.Source, stateRoot); err != nil {
					return nil, err
				}
			}
			findings = append(findings, finding(
				"host_bind", "high", owner+" can access host path "+mount.Source, true,
			))
		default:
			return nil, fmt.Errorf("unsupported mount type %q", mount.Type)
		}
	}

	return deduplicateFindings(findings), nil
}

func validateHostBind(source, stateRoot string) error {
	if !filepath.IsAbs(source) {
		return errors.New("host bind source must be absolute")
	}

	clean := filepath.Clean(source)
	volume := filepath.VolumeName(clean)
	if clean == string(filepath.Separator) || (volume != "" && clean == volume+string(filepath.Separator)) {
		return errors.New("binding the host filesystem root is forbidden")
	}

	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(stateRoot, clean)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("binding the Loreva agent state directory is forbidden")
	}

	return nil
}

func dockerSocket(source string) bool {
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(source)))

	return normalized == "/var/run/docker.sock" || normalized == "/run/docker.sock" ||
		normalized == "//./pipe/docker_engine"
}

func validateRelativeFile(value string) error {
	clean := filepath.Clean(filepath.FromSlash(value))
	if value == "" || clean == "." || filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" ||
		clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("file must be a safe relative path")
	}

	return nil
}

func ensureRegularWithin(root, path string) error {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("Compose file escapes the extracted project")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Compose file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Compose file must be a regular file")
	}

	return nil
}

func ensureProjectFile(root, path string, allowMissing bool) error {
	resolved, err := projectPath(root, path)
	if err != nil {
		return err
	}

	info, err := os.Lstat(resolved)
	if allowMissing && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect project file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("project file must be a regular file")
	}

	return nil
}

func ensureProjectDirectory(root, path string) (string, error) {
	if path == "" {
		path = "."
	}
	resolved, err := projectPath(root, path)
	if err != nil {
		return "", err
	}

	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect project directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("build context must be a directory")
	}

	return resolved, nil
}

func projectPath(root, path string) (string, error) {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return "", errors.New("project path is empty or contains NUL")
	}

	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(root, filepath.FromSlash(resolved))
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}

	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("project path escapes the signed artifact")
	}

	return resolved, nil
}

func composeProjectName(workloadID string) string {
	return "loreva-" + strings.ReplaceAll(workloadID, "-", "")
}

func planDigest(plan *storedPlan) string {
	canonical, _ := json.Marshal(struct {
		Version    int                          `json:"version"`
		WorkloadID string                       `json:"workload_id"`
		Payload    protocol.WorkloadPlanPayload `json:"payload"`
		Steps      []protocol.WorkloadPlanStep  `json:"steps"`
		Findings   []protocol.WorkloadFinding   `json:"findings"`
	}{plan.Version, plan.WorkloadID, plan.Payload, plan.Steps, plan.Findings})
	hash := sha256.Sum256(canonical)

	return "sha256:" + hex.EncodeToString(hash[:])
}

func finding(code, severity, message string, approval bool) protocol.WorkloadFinding {
	digestInput, _ := json.Marshal([]any{code, severity, message, approval})
	hash := sha256.Sum256(digestInput)

	return protocol.WorkloadFinding{
		Code: code, Severity: severity, Message: message,
		FindingDigest: "sha256:" + hex.EncodeToString(hash[:]), RequiresApproval: approval,
	}
}

func deduplicateFindings(values []protocol.WorkloadFinding) []protocol.WorkloadFinding {
	seen := make(map[string]protocol.WorkloadFinding, len(values))
	for _, value := range values {
		seen[value.FindingDigest] = value
	}

	result := make([]protocol.WorkloadFinding, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Severity != result[right].Severity {
			return result[left].Severity < result[right].Severity
		}
		return result[left].FindingDigest < result[right].FindingDigest
	})

	return result
}
