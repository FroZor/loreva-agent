package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentapi"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const (
	probeTimeout      = 5 * time.Second
	keepaliveInterval = 25
	maxResponseSize   = 4 * 1024 * 1024
)

// Session is an open tunnel to one node with an HTTP client for its API.
type Session struct {
	tunnel   *tunnel.Tunnel
	http     *http.Client
	baseURL  string
	endpoint netip.AddrPort
}

// endpointConfig is the local side of a tunnel to a node.
type endpointConfig struct {
	privateKey    tunnel.Key
	presharedKey  tunnel.Key
	address       netip.Addr
	nodePublicKey tunnel.Key
	nodeAddress   netip.Addr
	endpoints     []netip.AddrPort
}

// Connect opens a session with the credentials saved by Pair.
func Connect(ctx context.Context, credentials *Credentials) (*Session, error) {
	config, err := credentials.endpointConfig()
	if err != nil {
		return nil, err
	}

	return open(ctx, config)
}

// open tries each endpoint until a TCP connection to the API succeeds, which
// proves the WireGuard handshake with the node's key completed.
func open(ctx context.Context, config endpointConfig) (*Session, error) {
	var failures []error

	for _, endpoint := range config.endpoints {
		session, err := openEndpoint(ctx, config, endpoint)
		if err == nil {
			return session, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		failures = append(failures, fmt.Errorf("%s: %w", endpoint, err))
	}

	return nil, fmt.Errorf("could not reach the node: %w", errors.Join(failures...))
}

func openEndpoint(ctx context.Context, config endpointConfig, endpoint netip.AddrPort) (*Session, error) {
	tun, err := tunnel.Start(tunnel.Config{PrivateKey: config.privateKey, Address: config.address}, []tunnel.Peer{{
		PublicKey:           config.nodePublicKey,
		PresharedKey:        config.presharedKey,
		Address:             config.nodeAddress,
		Endpoint:            endpoint,
		PersistentKeepalive: keepaliveInterval,
	}})
	if err != nil {
		return nil, err
	}

	apiAddress := netip.AddrPortFrom(config.nodeAddress, agentapi.Port).String()

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	probe, err := tun.DialContext(probeCtx, "tcp", apiAddress)
	if err != nil {
		tun.Close()
		return nil, err
	}
	_ = probe.Close()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return tun.DialContext(ctx, "tcp", apiAddress)
		},
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
	}

	return &Session{
		tunnel:   tun,
		http:     &http.Client{Transport: transport},
		baseURL:  "http://" + apiAddress,
		endpoint: endpoint,
	}, nil
}

// Close shuts the tunnel down.
func (s *Session) Close() {
	s.http.CloseIdleConnections()
	s.tunnel.Close()
}

// Do sends one API request with an optional JSON body and returns the
// response body. A non-2xx response is returned as an *APIError.
func (s *Session) Do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}

		reader = bytes.NewReader(data)
	}

	request, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := s.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxResponseSize {
		return nil, errors.New("response exceeds 4 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, parseAPIError(response.StatusCode, data)
	}

	return data, nil
}

func (s *Session) doJSON(ctx context.Context, method, path string, body, target any) error {
	data, err := s.Do(ctx, method, path, body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}

	return nil
}

// APIError is a non-2xx response from the agent.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return "agent API " + strconv.Itoa(e.Status) + " " + e.Code + ": " + e.Message
}

func parseAPIError(status int, data []byte) error {
	var body agentapi.Error
	if err := json.Unmarshal(data, &body); err != nil || body.Error.Code == "" {
		return &APIError{Status: status, Code: "unknown", Message: http.StatusText(status)}
	}

	return &APIError{Status: status, Code: body.Error.Code, Message: body.Error.Message}
}

func (c *Credentials) endpointConfig() (endpointConfig, error) {
	var config endpointConfig
	var err error

	if config.privateKey, err = tunnel.ParseKey(c.PrivateKey); err != nil {
		return config, fmt.Errorf("credentials private_key: %w", err)
	}
	if config.presharedKey, err = tunnel.ParseKey(c.PresharedKey); err != nil {
		return config, fmt.Errorf("credentials preshared_key: %w", err)
	}
	if config.nodePublicKey, err = tunnel.ParseKey(c.NodePublicKey); err != nil {
		return config, fmt.Errorf("credentials node_public_key: %w", err)
	}
	if config.address, err = netip.ParseAddr(c.Address); err != nil {
		return config, fmt.Errorf("credentials address: %w", err)
	}
	if config.nodeAddress, err = netip.ParseAddr(c.NodeAddress); err != nil {
		return config, fmt.Errorf("credentials node_address: %w", err)
	}

	for _, value := range c.Endpoints {
		endpoint, err := pairing.ParseEndpoint(value)
		if err != nil {
			return config, fmt.Errorf("credentials endpoint: %w", err)
		}

		config.endpoints = append(config.endpoints, endpoint)
	}
	if len(config.endpoints) == 0 {
		return config, errors.New("credentials have no endpoints")
	}

	return config, nil
}
