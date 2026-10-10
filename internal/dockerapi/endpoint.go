// Package dockerapi opens Docker Engine clients only for endpoints the agent trusts.
package dockerapi

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/moby/moby/client"
)

// ValidateEndpoint accepts a local socket, SSH, or a TLS endpoint that is verified.
func ValidateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}

	switch strings.ToLower(parsed.Scheme) {
	case "unix", "npipe", "ssh", "https":
		return nil
	case "tcp":
		if os.Getenv(client.EnvTLSVerify) != "" {
			return nil
		}
	}

	return errors.New("Docker endpoint must use a local socket, SSH, or verified TLS")
}

// Connect returns a client for the environment's Docker endpoint after checking it.
func Connect() (*client.Client, error) {
	engine, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("create Docker client: %w", err)
	}
	if err := ValidateEndpoint(engine.DaemonHost()); err != nil {
		closeErr := engine.Close()
		return nil, errors.Join(err, closeErr)
	}

	return engine, nil
}
