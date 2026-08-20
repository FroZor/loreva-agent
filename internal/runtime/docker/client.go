// Package docker provides a narrow local Docker Engine boundary.
package docker

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	mobyclient "github.com/moby/moby/client"
)

// ErrUnsupportedEndpoint rejects remote or unknown Docker transports.
var ErrUnsupportedEndpoint = errors.New("only local unix and npipe Docker endpoints are supported")

// Client exposes the deliberately narrow Docker operations allowed to the agent.
type Client struct {
	api *mobyclient.Client
}

// Open creates a Docker client for a validated local socket endpoint.
func Open(endpoint string) (*Client, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}

	api, err := mobyclient.New(mobyclient.WithHost(endpoint))
	if err != nil {
		return nil, fmt.Errorf("create Docker client: %w", err)
	}

	return &Client{api: api}, nil
}

// Ping verifies access to the local Docker Engine.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.api.Ping(ctx, mobyclient.PingOptions{NegotiateAPIVersion: true})
	if err != nil {
		return fmt.Errorf("ping Docker Engine: %w", err)
	}

	return nil
}

// Close releases resources owned by the Docker client.
func (c *Client) Close() error {
	return c.api.Close()
}

func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse Docker endpoint: %w", err)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "unix", "npipe":
		return nil
	default:
		return ErrUnsupportedEndpoint
	}
}
