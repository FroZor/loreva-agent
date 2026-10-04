// Package connectivity establishes policy-constrained portal connections.
package connectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/coder/websocket"
)

const defaultReadLimit int64 = 64 * 1024

var (
	// ErrInsecureTransport rejects non-loopback plaintext WebSocket endpoints.
	ErrInsecureTransport = errors.New("plain WS is allowed only for loopback development endpoints")
	// ErrUnsupportedScheme rejects endpoint URL schemes outside wss and ws.
	ErrUnsupportedScheme = errors.New("endpoint scheme must be wss or ws")
	// ErrTLSPolicy indicates that the negotiated TLS profile is not PQ-hybrid.
	ErrTLSPolicy = errors.New("connection does not satisfy pqc-hybrid-v1 TLS policy")
	// ErrSubprotocol indicates that the portal did not select the required protocol.
	ErrSubprotocol = errors.New("portal did not negotiate the required WebSocket subprotocol")
)

// Config defines trust, identity, and frame limits for portal connections.
type Config struct {
	PortalCAPEM        string
	ClientCertificate  *tls.Certificate
	AllowDevelopmentWS bool
	ReadLimit          int64
}

// DialOptions defines request-specific headers and WebSocket subprotocols.
type DialOptions struct {
	Header       http.Header
	Subprotocols []string
}

// Dialer establishes WebSocket connections that satisfy the agent TLS policy.
type Dialer struct {
	httpClient         *http.Client
	allowDevelopmentWS bool
	readLimit          int64
}

// NewDialer validates config and creates a portal connection dialer.
func NewDialer(config Config) (*Dialer, error) {
	httpClient, err := NewHTTPClient(config)
	if err != nil {
		return nil, err
	}
	if config.ReadLimit <= 0 {
		config.ReadLimit = defaultReadLimit
	}

	return &Dialer{
		httpClient:         httpClient,
		allowDevelopmentWS: config.AllowDevelopmentWS,
		readLimit:          config.ReadLimit,
	}, nil
}

// NewHTTPClient creates an HTTP client with the same trust and TLS policy as
// portal WebSocket connections. It is used for immutable portal artifacts;
// callers must still constrain destination paths and verify signed digests.
func NewHTTPClient(config Config) (*http.Client, error) {
	return secureHTTPClient(config.PortalCAPEM, config.ClientCertificate)
}

// Dial opens a WebSocket and verifies its negotiated transport policy.
func (d *Dialer) Dial(ctx context.Context, endpoint string, options DialOptions) (*websocket.Conn, *http.Response, error) {
	if err := validateEndpoint(endpoint, d.allowDevelopmentWS); err != nil {
		return nil, nil, err
	}

	conn, response, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient:      d.httpClient,
		HTTPHeader:      options.Header,
		Subprotocols:    options.Subprotocols,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, response, fmt.Errorf("dial portal websocket: %w", err)
	}

	conn.SetReadLimit(d.readLimit)
	if strings.HasPrefix(strings.ToLower(endpoint), "wss://") {
		if response == nil || response.TLS == nil ||
			response.TLS.Version != tls.VersionTLS13 ||
			response.TLS.CurveID != tls.X25519MLKEM768 {
			_ = conn.Close(websocket.StatusPolicyViolation, "tls_policy_violation")
			return nil, response, ErrTLSPolicy
		}
	}
	if len(options.Subprotocols) > 0 && conn.Subprotocol() != options.Subprotocols[0] {
		_ = conn.Close(websocket.StatusProtocolError, "subprotocol required")
		return nil, response, ErrSubprotocol
	}

	return conn, response, nil
}

// Endpoint resolves and validates a fixed protocol path under a portal URL.
func Endpoint(portalURL, endpointPath string) (string, error) {
	parsed, err := url.Parse(portalURL)
	if err != nil {
		return "", fmt.Errorf("parse portal URL: %w", err)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("portal URL must not contain a path")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("portal URL must not contain a query or fragment")
	}
	parsed.Path = path.Clean("/" + strings.TrimPrefix(endpointPath, "/"))
	if err := validateEndpoint(parsed.String(), true); err != nil {
		return "", err
	}

	return parsed.String(), nil
}

// HTTPEndpoint resolves a fixed HTTPS path under a portal WebSocket URL.
// Plain HTTP is accepted only for explicitly enabled loopback development.
func HTTPEndpoint(portalURL, endpointPath string, allowDevelopmentHTTP bool) (string, error) {
	parsed, err := url.Parse(portalURL)
	if err != nil {
		return "", fmt.Errorf("parse portal URL: %w", err)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("portal URL must not contain a path")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", errors.New("portal URL must not contain user information, a query, or a fragment")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "wss":
		parsed.Scheme = "https"
	case "ws":
		if !allowDevelopmentHTTP || !isLoopbackHost(parsed.Hostname()) {
			return "", ErrInsecureTransport
		}
		parsed.Scheme = "http"
	default:
		return "", ErrUnsupportedScheme
	}

	parsed.Path = path.Clean("/" + strings.TrimPrefix(endpointPath, "/"))

	return parsed.String(), nil
}

func validateEndpoint(endpoint string, allowDevelopmentWS bool) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse portal endpoint: %w", err)
	}
	if parsed.Hostname() == "" {
		return errors.New("portal endpoint must include a host")
	}
	if parsed.User != nil {
		return errors.New("portal endpoint must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("portal endpoint must not contain a query or fragment")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "wss":
		return nil
	case "ws":
		if !allowDevelopmentWS || !isLoopbackHost(parsed.Hostname()) {
			return ErrInsecureTransport
		}
		return nil
	default:
		return ErrUnsupportedScheme
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RetryableHTTPStatus reports whether an HTTP status represents a transient failure.
func RetryableHTTPStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
}
