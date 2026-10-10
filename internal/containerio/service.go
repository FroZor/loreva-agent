// Package containerio streams container logs and delivers console commands
// to containers through the Docker Engine API.
package containerio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

var (
	// ErrNotFound means Docker has no container with the requested ID.
	ErrNotFound = errors.New("container not found")
	// ErrNotRunning means the operation needs a running container.
	ErrNotRunning = errors.New("container is not running")
	// ErrInvalidContainerID means the ID is not a full Docker container ID.
	ErrInvalidContainerID = errors.New("container_id must be a 64-character lowercase hex Docker ID")
)

var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const dialTimeout = 5 * time.Second

// Engine is the part of the Docker client the service uses.
type Engine interface {
	ContainerInspect(ctx context.Context, containerID string, options client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	ContainerLogs(ctx context.Context, containerID string, options client.ContainerLogsOptions) (client.ContainerLogsResult, error)
	ContainerAttach(ctx context.Context, containerID string, options client.ContainerAttachOptions) (client.ContainerAttachResult, error)
}

// Dialer opens TCP connections to a container's RCON or telnet port.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Service reads container logs and sends console commands.
type Service struct {
	engine Engine
	dialer Dialer
}

// New returns a service that talks to Docker through engine.
func New(engine Engine) *Service {
	return &Service{engine: engine, dialer: &net.Dialer{Timeout: dialTimeout}}
}

func (s *Service) inspect(ctx context.Context, containerID string) (client.ContainerInspectResult, error) {
	if !containerIDPattern.MatchString(containerID) {
		return client.ContainerInspectResult{}, ErrInvalidContainerID
	}

	result, err := s.engine.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			return client.ContainerInspectResult{}, ErrNotFound
		}

		return client.ContainerInspectResult{}, fmt.Errorf("inspect container: %w", err)
	}
	if result.Container.Config == nil || result.Container.State == nil {
		return client.ContainerInspectResult{}, errors.New("Docker returned an incomplete container description")
	}

	return result, nil
}
