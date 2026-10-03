// Package control defines the local control socket protocol between the
// running agent and root-only CLI commands such as invite and devices.
//
// Messages are newline-delimited JSON objects. The socket lives in the state
// directory, is mode 0600, and the agent additionally checks the peer's
// credentials, so only root and the agent's own user can use it.
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/strictjson"
)

// SocketName is the control socket file name inside the state directory.
const SocketName = "control.sock"

const maxMessageSize = 64 * 1024

// Message types. The CLI sends invite.create, pairing.decision, devices.list,
// and device.remove; the agent sends the rest.
const (
	TypeInviteCreate     = "invite.create"
	TypePairingDecision  = "pairing.decision"
	TypeDevicesList      = "devices.list"
	TypeDeviceRemove     = "device.remove"
	TypeInviteCreated    = "invite.created"
	TypePairingRequested = "pairing.requested"
	TypePairingCompleted = "pairing.completed"
	TypePairingRejected  = "pairing.rejected"
	TypeInviteExpired    = "invite.expired"
	TypeDevices          = "devices"
	TypeDeviceRemoved    = "device.removed"
	TypeError            = "error"
)

// Message is one control protocol message. Each type uses a subset of the
// fields; the rest stay empty.
type Message struct {
	Type string `json:"type"`

	// invite.create
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	Endpoints  []string `json:"endpoints,omitempty"`
	NoConfirm  bool     `json:"no_confirm,omitempty"`

	// invite.created
	Invite    string    `json:"invite,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`

	// pairing.requested, pairing.decision, pairing.completed
	PairingID   string `json:"pairing_id,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	SAS         string `json:"sas,omitempty"`
	Approve     bool   `json:"approve,omitempty"`

	// pairing.completed, device.remove, device.removed
	DeviceID string `json:"device_id,omitempty"`

	// devices
	Devices []Device `json:"devices,omitempty"`

	// error
	Error string `json:"error,omitempty"`
}

// Device is a paired device as the control socket reports it.
type Device struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	WireGuardPublicKey string    `json:"wireguard_public_key"`
	TunnelAddress      string    `json:"tunnel_address"`
	PairedAt           time.Time `json:"paired_at"`
}

// SocketPath returns the control socket path for a state directory.
func SocketPath(stateDir string) string {
	return filepath.Join(stateDir, SocketName)
}

// maxSocketPath is the usable length of sockaddr_un.sun_path on Linux.
const maxSocketPath = 107

func checkSocketPath(path string) error {
	if len(path) > maxSocketPath {
		return fmt.Errorf("control socket path %s is longer than %d bytes; use a shorter --state-dir", path, maxSocketPath)
	}

	return nil
}

// Conn exchanges control messages over a stream connection.
type Conn struct {
	conn    net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
}

// NewConn wraps an established connection.
func NewConn(conn net.Conn) *Conn {
	return &Conn{conn: conn, reader: bufio.NewReaderSize(conn, 4096)}
}

// Dial connects to the agent's control socket.
func Dial(stateDir string) (*Conn, error) {
	path := SocketPath(stateDir)
	if err := checkSocketPath(path); err != nil {
		return nil, err
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect to the running agent (is the service started?): %w", err)
	}

	return NewConn(conn), nil
}

// Send writes one message.
func (c *Conn) Send(message Message) error {
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode control message: %w", err)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write control message: %w", err)
	}

	return nil
}

// Receive reads one message. It rejects lines over 64 KiB.
func (c *Conn) Receive() (Message, error) {
	var line []byte
	for {
		chunk, isPrefix, err := c.reader.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return Message{}, io.ErrUnexpectedEOF
			}

			return Message{}, err
		}

		line = append(line, chunk...)
		if len(line) > maxMessageSize {
			return Message{}, errors.New("control message exceeds 64 KiB")
		}
		if !isPrefix {
			break
		}
	}

	var message Message
	if err := strictjson.Decode(line, &message); err != nil {
		return Message{}, fmt.Errorf("decode control message: %w", err)
	}
	if message.Type == "" {
		return Message{}, errors.New("control message type is required")
	}

	return message, nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}
