package workload

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const eggStopFallbackSeconds = 10

func (runtime *dockerRuntime) lifecycleEgg(
	ctx context.Context,
	containerIDs []string,
	plan *storedPlan,
	action string,
	timeoutSeconds int,
) error {
	if len(containerIDs) != 1 {
		return errors.New("Pterodactyl Egg workload must own exactly one runtime container")
	}

	egg, err := loadEgg(plan.ArtifactPath)
	if err != nil {
		return err
	}
	containerID := containerIDs[0]
	if err := runtime.stopEggContainer(ctx, containerID, strings.TrimSpace(egg.Config.Stop), timeoutSeconds); err != nil {
		return err
	}

	switch action {
	case "stop":
		return nil
	case "restart":
		if _, err := runtime.client.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
			return fmt.Errorf("start Pterodactyl Egg container: %w", err)
		}

		return nil
	case "delete":
		if _, err := runtime.client.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{}); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("delete Pterodactyl Egg container: %w", err)
		}

		return nil
	default:
		return fmt.Errorf("unsupported Pterodactyl Egg lifecycle action %q", action)
	}
}

func (runtime *dockerRuntime) stopEggContainer(
	ctx context.Context,
	containerID string,
	stopCommand string,
	timeoutSeconds int,
) error {
	inspection, err := runtime.client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil
		}

		return fmt.Errorf("inspect Pterodactyl Egg container: %w", err)
	}
	if !inspection.Container.State.Running {
		return nil
	}

	attached, err := runtime.client.ContainerAttach(ctx, containerID, client.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
	})
	if err != nil {
		return runtime.stopEggFallback(ctx, containerID)
	}
	defer attached.HijackedResponse.Close()

	wait := runtime.client.ContainerWait(ctx, containerID, client.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})
	if _, err := attached.HijackedResponse.Conn.Write([]byte(stopCommand + "\n")); err != nil {
		return runtime.stopEggFallback(ctx, containerID)
	}
	if err := attached.HijackedResponse.CloseWrite(); err != nil {
		return runtime.stopEggFallback(ctx, containerID)
	}

	timer := time.NewTimer(time.Duration(timeoutSeconds) * time.Second)
	defer timer.Stop()

	select {
	case err := <-wait.Error:
		if err != nil {
			return fmt.Errorf("wait for Pterodactyl Egg stop command: %w", err)
		}

		return nil
	case <-wait.Result:
		return nil
	case <-timer.C:
		return runtime.stopEggFallback(ctx, containerID)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *dockerRuntime) stopEggFallback(ctx context.Context, containerID string) error {
	timeout := eggStopFallbackSeconds
	if _, err := runtime.client.ContainerStop(ctx, containerID, client.ContainerStopOptions{Timeout: &timeout}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("stop Pterodactyl Egg container: %w", err)
	}

	return nil
}
