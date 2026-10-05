package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	connectTimeout = 10 * time.Second
	// maxFrameBytes bounds a frame from the node. Node reports are bounded
	// to 512 KiB by the protocol.
	maxFrameBytes = 1024 * 1024
)

// Session is an open direct session with one node over TLS.
type Session struct {
	// Hello is the node's first frame.
	Hello protocol.SessionHello

	conn     *websocket.Conn
	tls      tls.ConnectionState
	endpoint netip.AddrPort
}

// endpointConfig is what the device needs to reach a node.
type endpointConfig struct {
	nodeID      string
	nodePin     string
	certificate tls.Certificate
	endpoints   []netip.AddrPort
}

// Connect opens a device session with the credentials saved by Pair.
func Connect(ctx context.Context, credentials *Credentials) (*Session, error) {
	config, err := credentials.endpointConfig()
	if err != nil {
		return nil, err
	}

	session, err := open(ctx, config)
	if err != nil {
		return nil, err
	}
	if session.Hello.Peer != protocol.SessionPeerDevice || session.Hello.DeviceID != credentials.DeviceID {
		session.Close()
		return nil, errors.New("the node does not recognize this device; it may have been revoked")
	}

	return session, nil
}

// open tries each endpoint until the session handshake succeeds.
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
	tlsConfig := certpin.ClientConfig(config.certificate, config.nodePin)

	var state tls.ConnectionState
	httpClient := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
			if err != nil {
				return nil, err
			}

			conn := tls.Client(raw, tlsConfig)
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			state = conn.ConnectionState()

			return conn, nil
		},
	}}

	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	conn, _, err := websocket.Dial(dialCtx, "wss://"+endpoint.String()+protocol.DirectSessionPath, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{protocol.DirectSessionSubprotocol},
	})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(maxFrameBytes)

	session := &Session{conn: conn, tls: state, endpoint: endpoint}
	if err := session.readHello(dialCtx, config.nodeID); err != nil {
		session.Close()
		return nil, err
	}

	return session, nil
}

func (s *Session) readHello(ctx context.Context, nodeID string) error {
	if s.conn.Subprotocol() != protocol.DirectSessionSubprotocol {
		return errors.New("node did not accept the " + protocol.DirectSessionSubprotocol + " subprotocol")
	}
	if err := wsframe.ReadJSON(ctx, s.conn, &s.Hello); err != nil {
		return fmt.Errorf("read session hello: %w", err)
	}
	if s.Hello.Type != protocol.SessionHelloType || s.Hello.Protocol != protocol.DirectSessionSubprotocol {
		return errors.New("node sent an invalid session hello")
	}
	if s.Hello.NodeID != nodeID {
		return errors.New("node ID in the session hello does not match")
	}

	return nil
}

// Read returns the next frame from the node as raw JSON.
func (s *Session) Read(ctx context.Context) ([]byte, error) {
	return wsframe.ReadRawJSON(ctx, s.conn)
}

// ReadFrame returns the next frame. A binary frame carries stream data:
// a channel byte, the big-endian stream ID, then the data.
func (s *Session) ReadFrame(ctx context.Context) (isBinary bool, data []byte, err error) {
	messageType, data, err := s.conn.Read(ctx)
	if err != nil {
		return false, nil, err
	}

	return messageType == websocket.MessageBinary, data, nil
}

// Write sends one JSON frame to the node. The node validates it strictly.
func (s *Session) Write(ctx context.Context, frame []byte) error {
	if !json.Valid(frame) {
		return errors.New("frame is not valid JSON")
	}

	return s.conn.Write(ctx, websocket.MessageText, frame)
}

// WriteJSON encodes value and sends it as one frame.
func (s *Session) WriteJSON(ctx context.Context, value any) error {
	return wsframe.WriteJSON(ctx, s.conn, value)
}

// Close ends the session.
func (s *Session) Close() {
	_ = s.conn.Close(websocket.StatusNormalClosure, "")
}

// exporter returns this connection's TLS exporter value for pairing.
func (s *Session) exporter() ([]byte, error) {
	return s.tls.ExportKeyingMaterial(pairing.ExporterLabel, nil, pairing.ExporterSize)
}

// RemoteError is an error frame from the node.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	return "node refused the request: " + e.Code + ": " + e.Message
}

func (c *Credentials) endpointConfig() (endpointConfig, error) {
	if err := certpin.Validate(c.NodePin); err != nil {
		return endpointConfig{}, fmt.Errorf("credentials node_pin: %w", err)
	}

	certificate, err := certpin.Identity{PrivateKey: c.PrivateKey, Certificate: c.Certificate}.TLSCertificate()
	if err != nil {
		return endpointConfig{}, fmt.Errorf("credentials TLS identity: %w", err)
	}

	config := endpointConfig{nodeID: c.NodeID, nodePin: c.NodePin, certificate: certificate}
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
