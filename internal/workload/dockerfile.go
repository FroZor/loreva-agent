package workload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const maxBuildResponseBytes = 64 << 20

type dockerBuildMessage struct {
	Error       string `json:"error"`
	ErrorDetail struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

func (builder planBuilder) planDockerfile(
	ctx context.Context,
	plan *storedPlan,
	input protocol.DockerfileWorkloadInput,
) error {
	if err := validateRelativeFile(input.File); err != nil {
		return fmt.Errorf("validate Dockerfile path: %w", err)
	}
	if err := validateBuildTarget(input.Target); err != nil {
		return err
	}
	if err := validateEnvironment(input.BuildArgs); err != nil {
		return fmt.Errorf("validate Dockerfile build_args: %w", err)
	}
	if err := validateEnvironment(input.Environment); err != nil {
		return err
	}
	if err := validateResources(input.Resources); err != nil {
		return err
	}
	if err := validatePorts(input.Ports); err != nil {
		return err
	}
	if err := validateCommandArguments(input.Command); err != nil {
		return fmt.Errorf("validate Dockerfile workload command: %w", err)
	}

	artifactPath, err := builder.artifacts.acquire(ctx, input.Artifact)
	if err != nil {
		return err
	}
	digestHex := strings.TrimPrefix(input.Artifact.SHA256, "sha256:")
	projectDir := filepath.Join(builder.stateRoot, "workloads", "projects", digestHex)
	if err := extractTarGzip(artifactPath, projectDir); err != nil && !errors.Is(err, errExtractionExists) {
		return err
	}
	projectFile := filepath.Join(projectDir, filepath.FromSlash(input.File))
	if err := ensureRegularWithin(projectDir, projectFile); err != nil {
		return err
	}

	findings, err := inspectMounts(input.Mounts, builder.stateRoot, "Dockerfile workload")
	if err != nil {
		return err
	}
	plan.ArtifactPath = artifactPath
	plan.ProjectDir = projectDir
	plan.ProjectFile = projectFile
	plan.Findings = append(findings, finding(
		"dockerfile_build",
		"critical",
		"Dockerfile build executes author-supplied build steps with network access",
		true,
	))
	plan.Findings = deduplicateFindings(plan.Findings)
	plan.Steps = []protocol.WorkloadPlanStep{
		{Sequence: 1, Action: "load", Resource: input.File},
		{Sequence: 2, Action: "build", Resource: "signed_context"},
		{Sequence: 3, Action: "create", Resource: "container"},
		{Sequence: 4, Action: "start", Resource: "container"},
	}

	return nil
}

func validateBuildTarget(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 128 {
		return errors.New("Dockerfile target exceeds 128 bytes")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' && character != '-' {
			return errors.New("Dockerfile target contains unsupported characters")
		}
	}

	return nil
}

func (runtime *dockerRuntime) executeDockerfile(
	ctx context.Context,
	plan *storedPlan,
	progress func(string),
) error {
	input := plan.Payload.Dockerfile
	if input == nil {
		return errors.New("stored Dockerfile plan is missing input")
	}
	if err := runtime.ensureContainerAbsent(ctx, plan.WorkloadID); err != nil {
		return err
	}

	image := builtImageName(plan)
	progress("build_image")
	if err := runtime.buildDockerfile(ctx, plan, *input, image); err != nil {
		return err
	}

	return runtime.createWorkloadContainer(ctx, plan, protocol.OCIWorkloadInput{
		Image:       image,
		Environment: input.Environment,
		Command:     input.Command,
		Resources:   input.Resources,
		Ports:       input.Ports,
		Mounts:      input.Mounts,
	}, progress)
}

func (runtime *dockerRuntime) buildDockerfile(
	ctx context.Context,
	plan *storedPlan,
	input protocol.DockerfileWorkloadInput,
	image string,
) (resultErr error) {
	contextFile, err := os.Open(plan.ArtifactPath)
	if err != nil {
		return fmt.Errorf("open Dockerfile build context: %w", err)
	}
	defer func() {
		if closeErr := contextFile.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	buildArgs := make(map[string]*string, len(input.BuildArgs))
	for key, value := range input.BuildArgs {
		value := value
		buildArgs[key] = &value
	}
	result, err := runtime.client.ImageBuild(ctx, contextFile, client.ImageBuildOptions{
		Tags:        []string{image},
		Dockerfile:  filepath.ToSlash(input.File),
		Target:      input.Target,
		BuildArgs:   buildArgs,
		Labels:      workloadLabels(plan),
		PullParent:  true,
		Remove:      true,
		ForceRemove: true,
		Memory:      input.Resources.MemoryBytes,
		CPUPeriod:   100_000,
		CPUQuota:    input.Resources.CPUMillicores * 100,
		NetworkMode: "default",
		Version:     build.BuilderBuildKit,
	})
	if err != nil {
		return fmt.Errorf("start Dockerfile build: %w", err)
	}
	defer func() {
		if closeErr := result.Body.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	limited := &io.LimitedReader{R: result.Body, N: maxBuildResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	for {
		var message dockerBuildMessage
		if err := decoder.Decode(&message); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("decode Dockerfile build result: %w", err)
		}
		if message.ErrorDetail.Message != "" {
			return errors.New(sanitizeRuntimeMessage(message.ErrorDetail.Message))
		}
		if message.Error != "" {
			return errors.New(sanitizeRuntimeMessage(message.Error))
		}
	}
	if limited.N <= 0 {
		return errors.New("Dockerfile build response exceeded 64 MiB")
	}

	return nil
}

func builtImageName(plan *storedPlan) string {
	digest := strings.TrimPrefix(plan.PlanDigest, "sha256:")

	return "loreva/workload-" + strings.ReplaceAll(plan.WorkloadID, "-", "") + ":" + digest[:12]
}
