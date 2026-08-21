// Package observation identifies whether collected data describes a host or a constrained runtime.
package observation

import (
	"context"
	"strings"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// Environment contains the detected observation scope and virtualization details.
type Environment struct {
	Scope  string
	System string
	Role   string
	Error  error
}

// Detect returns one consistent observation scope for all node collectors.
func Detect(ctx context.Context) Environment {
	system, role, err := host.VirtualizationWithContext(ctx)
	environment := Environment{
		Scope:  protocol.ObservationScopeHost,
		System: system,
		Role:   role,
		Error:  err,
	}
	if err != nil {
		environment.Scope = fallbackScope()
	}
	if isContainer(system) {
		environment.Scope = protocol.ObservationScopeRuntime
	}

	return environment
}

func isContainer(provider string) bool {
	switch strings.ToLower(provider) {
	case "containerd", "docker", "lxc", "lxc-libvirt", "openvz", "podman", "rkt":
		return true
	default:
		return false
	}
}
