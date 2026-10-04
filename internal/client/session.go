package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/tunnel"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	probeTimeout      = 5 * time.Second
	keepaliveInterval = 25
	// maxFrameBytes bounds a frame from the node. Node reports are bounded
	// to 512 KiB by the protocol.
	maxFrameBytes = 1024 * 1024
)

// Session is an open direct session with one node: a userspace WireGuard
// tunnel and the node protocol WebSocket inside it.
type Session struct {
	// Hello is the node's first frame.
	Hello protocol.SessionHello

	tunnel   *tunnel.Tunnel
	conn     *websocket.Conn
	endpoint netip.AddrPort
}

// endpointConfig is the local side of a tunnel to a node.
type endpointConfig struct {
	privateKey    tunnel.Key
	presharedKey  tunnel.Key
	address       netip.Addr
	nodeID        string
	nodePublicKey tunnel.Key
	nodeAddress   netip.Addr
	endpoints     []netip.AddrPort
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

// open tries each endpoint until the session handshake succeeds, which
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

	address := netip.AddrPortFrom(config.nodeAddress, protocol.DirectSessionPort).String()
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return tun.DialContext(ctx, "tcp", address)
		},
	}}

	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	conn, _, err := websocket.Dial(dialCtx, "ws://"+address+protocol.DirectSessionPath, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{protocol.DirectSessionSubprotocol},
	})
	if err != nil {
		tun.Close()
		return nil, err
	}
	conn.SetReadLimit(maxFrameBytes)

	session := &Session{tunnel: tun, conn: conn, endpoint: endpoint}
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

// Close ends the session and shuts the tunnel down.
func (s *Session) Close() {
	_ = s.conn.Close(websocket.StatusNormalClosure, "")
	s.tunnel.Close()
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
	var config endpointConfig
	var err error

	config.nodeID = c.NodeID
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
