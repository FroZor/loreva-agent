package workload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxInstallerLogBytes = 16 << 10
	eggRuntimeUser       = "1000:1000"
)

func (runtime *dockerRuntime) executeEgg(
	ctx context.Context,
	plan *storedPlan,
	progress func(string),
) error {
	input := plan.Payload.Egg
	if input == nil {
		return errors.New("stored Pterodactyl Egg plan is missing input")
	}
	egg, err := loadEgg(plan.ArtifactPath)
	if err != nil {
		return err
	}
	if err := validateEggInput(egg, *input); err != nil {
		return err
	}

	name := workloadResourceName(plan.WorkloadID)
	if _, err := runtime.client.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); err == nil {
		return errors.New("managed workload container already exists")
	} else if !errdefs.IsNotFound(err) {
		return fmt.Errorf("inspect workload container: %w", err)
	}
	progress("pull_installer_image")
	if err := runtime.pullImage(ctx, input.InstallerImage); err != nil {
		return err
	}
	progress("pull_runtime_image")
	if err := runtime.pullImage(ctx, input.DockerImage); err != nil {
		return err
	}

	volumeName := name + "-data-1"
	progress("create_volume")
	if _, err := runtime.client.VolumeCreate(ctx, client.VolumeCreateOptions{
		Name: volumeName, Labels: workloadLabels(plan),
	}); err != nil {
		return fmt.Errorf("create Pterodactyl Egg data volume: %w", err)
	}

	environment, err := eggRuntimeEnvironment(egg, *input, plan.WorkloadID)
	if err != nil {
		return err
	}
	if installer := egg.Scripts.Installation; strings.TrimSpace(installer.Script) != "" {
		progress("run_installer")
		if err := runtime.runEggTask(
			ctx,
			name+"-install",
			input.InstallerImage,
			installer.Entrypoint,
			installer.Script,
			environment,
			volumeName,
			plan,
			nil,
		); err != nil {
			return fmt.Errorf("run Pterodactyl Egg installer: %w", err)
		}
	}
	if containsString(egg.Features, "eula") {
		progress("record_eula")
		if err := runtime.runEggTask(
			ctx,
			name+"-eula",
			input.InstallerImage,
			egg.Scripts.Installation.Entrypoint,
			"printf 'eula=true\\n' > /mnt/server/eula.txt",
			environment,
			volumeName,
			plan,
			nil,
		); err != nil {
			return fmt.Errorf("record Minecraft EULA agreement: %w", err)
		}
	}
	progress("set_volume_ownership")
	if err := runtime.runEggTask(
		ctx,
		name+"-permissions",
		input.InstallerImage,
		egg.Scripts.Installation.Entrypoint,
		"chown -R "+eggRuntimeUser+" /mnt/server",
		environment,
		volumeName,
		plan,
		[]string{"CHOWN"},
	); err != nil {
		return fmt.Errorf("secure Pterodactyl Egg volume ownership: %w", err)
	}

	exposedPorts, portBindings, err := dockerPorts(input.Ports)
	if err != nil {
		return err
	}
	pidsLimit := input.Resources.PIDsLimit
	initProcess := true

	progress("create_container")
	created, err := runtime.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:        input.DockerImage,
			User:         eggRuntimeUser,
			Env:          environment,
			WorkingDir:   "/home/container",
			ExposedPorts: exposedPorts,
			Labels:       workloadLabels(plan),
			Tty:          true,
			OpenStdin:    true,
		},
		HostConfig: &container.HostConfig{
			PortBindings:  portBindings,
			Mounts:        []mount.Mount{{Type: mount.TypeVolume, Source: volumeName, Target: "/home/container"}},
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			Resources: container.Resources{
				NanoCPUs:  input.Resources.CPUMillicores * 1_000_000,
				Memory:    input.Resources.MemoryBytes,
				PidsLimit: &pidsLimit,
			},
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Init:        &initProcess,
		},
	})
	if err != nil {
		return fmt.Errorf("create Pterodactyl Egg runtime container: %w", err)
	}
	progress("start_container")
	if _, err := runtime.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start Pterodactyl Egg runtime container: %w", err)
	}

	return nil
}

func eggRuntimeEnvironment(
	egg pterodactylEgg,
	input protocol.PterodactylEggInput,
	workloadID string,
) ([]string, error) {
	environment, err := eggEnvironment(egg, input.Variables)
	if err != nil {
		return nil, err
	}

	serverPort := uint16(0)
	if len(input.Ports) > 0 {
		serverPort = input.Ports[0].ContainerPort
	}
	environment = append(environment,
		"STARTUP="+egg.Startup,
		"SERVER_MEMORY="+strconv.FormatInt(input.Resources.MemoryBytes/(1<<20), 10),
		"SERVER_IP=0.0.0.0",
		"SERVER_PORT="+strconv.FormatUint(uint64(serverPort), 10),
		"P_SERVER_UUID="+workloadID,
		"TZ=UTC",
	)
	if containsString(egg.Features, "eula") {
		environment = append(environment, "EULA=TRUE")
	}

	return environment, nil
}

func (runtime *dockerRuntime) pullImage(ctx context.Context, image string) error {
	pull, err := runtime.client.ImagePull(ctx, image, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull workload image: %w", err)
	}
	if err := pull.Wait(ctx); err != nil {
		return fmt.Errorf("wait for workload image pull: %w", err)
	}

	return nil
}

func (runtime *dockerRuntime) runEggTask(
	ctx context.Context,
	name string,
	image string,
	entrypoint string,
	script string,
	environment []string,
	volumeName string,
	plan *storedPlan,
	capabilities []string,
) error {
	if image == "" || entrypoint == "" {
		return errors.New("Pterodactyl Egg task image and entrypoint are required")
	}

	pidsLimit := int64(512)
	created, err := runtime.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:      image,
			Entrypoint: []string{entrypoint},
			Cmd:        []string{"-c", script},
			Env:        environment,
			WorkingDir: "/mnt/server",
			Labels:     workloadLabels(plan),
			Tty:        true,
		},
		HostConfig: &container.HostConfig{
			Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: volumeName, Target: "/mnt/server"}},
			Resources: container.Resources{
				NanoCPUs:  2_000_000_000,
				Memory:    2 << 30,
				PidsLimit: &pidsLimit,
			},
			CapDrop:     []string{"ALL"},
			CapAdd:      capabilities,
			SecurityOpt: []string{"no-new-privileges:true"},
		},
	})
	if err != nil {
		return fmt.Errorf("create Egg task container: %w", err)
	}
	defer func() {
		removeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = runtime.client.ContainerRemove(removeCtx, created.ID, client.ContainerRemoveOptions{Force: true})
		cancel()
	}()

	wait := runtime.client.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})
	if _, err := runtime.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start Egg task container: %w", err)
	}

	select {
	case err := <-wait.Error:
		return err
	case response := <-wait.Result:
		if response.Error != nil || response.StatusCode != 0 {
			logs := runtime.containerLogs(ctx, created.ID)
			return fmt.Errorf("Egg task exited with status %d: %s", response.StatusCode, logs)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (runtime *dockerRuntime) containerLogs(ctx context.Context, containerID string) string {
	result, err := runtime.client.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: true, Tail: "200",
	})
	if err != nil {
		return "logs unavailable"
	}
	defer func() {
		_ = result.Close()
	}()

	var buffer bytes.Buffer
	_, _ = io.Copy(&buffer, io.LimitReader(result, maxInstallerLogBytes))

	return sanitizeRuntimeMessage(buffer.String())
}

func sanitizeRuntimeMessage(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || character >= 0x20 {
			return character
		}
		return -1
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > maxInstallerLogBytes {
		value = value[:maxInstallerLogBytes]
	}

	return value
}
