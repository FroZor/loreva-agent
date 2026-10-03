package direct

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/control"
)

// controlServer handles local CLI connections. An invite lives only as long
// as the connection that created it, so invite secrets never touch disk.
type controlServer struct {
	pairings *pairings
	api      *api
	logger   *slog.Logger

	mu       sync.Mutex
	conns    map[*control.Conn]struct{}
	closed   bool
	handlers sync.WaitGroup
}

func (c *controlServer) serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("control socket stopped: %w", err)
		}

		if err := control.AuthorizePeer(conn); err != nil {
			c.logger.Warn("control connection refused", "error", err)
			_ = conn.Close()
			continue
		}

		if !c.start(control.NewConn(conn)) {
			_ = conn.Close()
			return nil
		}
	}
}

// start tracks and handles a connection unless the server is closing.
func (c *controlServer) start(conn *control.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}
	if c.conns == nil {
		c.conns = make(map[*control.Conn]struct{})
	}
	c.conns[conn] = struct{}{}
	c.handlers.Go(func() { c.handle(conn) })

	return true
}

func (c *controlServer) untrack(conn *control.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.conns, conn)
}

// closeConnections disconnects every CLI client and waits for its handler.
func (c *controlServer) closeConnections() {
	c.mu.Lock()
	c.closed = true
	for conn := range c.conns {
		_ = conn.Close()
	}
	c.mu.Unlock()

	c.handlers.Wait()
}

func (c *controlServer) handle(conn *control.Conn) {
	var session *inviteSession
	defer func() {
		if session != nil {
			c.pairings.cancel(session)
		}
		c.untrack(conn)
		_ = conn.Close()
	}()

	for {
		message, err := conn.Receive()
		if err != nil {
			return
		}

		response, err := c.dispatch(conn, &session, message)
		if err != nil {
			response = control.Message{Type: control.TypeError, Error: err.Error()}
		}
		if response.Type == "" {
			continue
		}
		if err := conn.Send(response); err != nil {
			return
		}
	}
}

func (c *controlServer) dispatch(conn *control.Conn, session **inviteSession, message control.Message) (control.Message, error) {
	switch message.Type {
	case control.TypeInviteCreate:
		if *session != nil {
			return control.Message{}, errors.New("this connection already has an invite")
		}

		created, encoded, err := c.pairings.createInvite(time.Duration(message.TTLSeconds)*time.Second, message.Endpoints, message.NoConfirm)
		if err != nil {
			return control.Message{}, err
		}

		*session = created
		if err := conn.Send(control.Message{Type: control.TypeInviteCreated, Invite: encoded, ExpiresAt: created.invite.ExpiresAt}); err != nil {
			return control.Message{}, err
		}
		go forwardEvents(conn, created.events)

		return control.Message{}, nil

	case control.TypePairingDecision:
		if *session == nil {
			return control.Message{}, errors.New("this connection has no invite")
		}

		return control.Message{}, c.pairings.decide(*session, message.PairingID, message.Approve)

	case control.TypeDevicesList:
		devices := []control.Device{}
		for _, device := range c.api.registry.list() {
			devices = append(devices, control.Device{
				ID:                 device.ID,
				Name:               device.Name,
				WireGuardPublicKey: device.WireGuardPublicKey,
				TunnelAddress:      device.TunnelAddress,
				PairedAt:           device.PairedAt,
			})
		}

		return control.Message{Type: control.TypeDevices, Devices: devices}, nil

	case control.TypeDeviceRemove:
		if err := c.api.revoke(message.DeviceID); err != nil {
			return control.Message{}, err
		}

		return control.Message{Type: control.TypeDeviceRemoved, DeviceID: message.DeviceID}, nil

	default:
		return control.Message{}, fmt.Errorf("unknown control message type %q", message.Type)
	}
}

// forwardEvents relays invite events until the invite ends. Send errors are
// ignored: a closed CLI simply misses them.
func forwardEvents(conn *control.Conn, events <-chan control.Message) {
	for message := range events {
		_ = conn.Send(message)
	}
}
