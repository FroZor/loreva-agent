package direct

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	maxFrameBytes = 64 * 1024
	// pairingRequestTimeout bounds how long an unpaired key may stay
	// connected without asking to pair, so strangers cannot hold the few
	// pairing slots.
	pairingRequestTimeout = 10 * time.Second
	pairingPending        = "pending"
	maxSessionsPerDevice  = 4
	maxSessions           = 64
	// maxPairingSessions bounds connections that hold no paired key yet.
	maxPairingSessions  = 4
	sessionResultBuffer = 64
	// selfRevokeDelay lets the answer to a revoke request reach a device
	// that revoked itself before its session closes.
	selfRevokeDelay = time.Second
	// sessionCloseTimeout bounds how long a revocation waits for the
	// device's sessions to close.
	sessionCloseTimeout = 3 * time.Second
)

var (
	errForbidden   = newSessionError("forbidden", "this peer may not do this")
	errUnavailable = newSessionError("unavailable", "the node is busy or shutting down; retry later")
)

// sessionError is a refusal with a stable code that the device receives as is.
type sessionError struct {
	code    string
	message string
}

func newSessionError(code, message string) *sessionError {
	return &sessionError{code: code, message: message}
}

func (e *sessionError) Error() string { return e.message }

// sessions accepts direct sessions over TLS. The caller is identified by the
// pin of the client certificate it presented in the handshake, which proves
// it holds the key. A paired key gets the node protocol; any other key
// reaches this point only while an invite is active, and may only pair.
type sessions struct {
	node     *localNode
	options  Options
	pairings *pairings
	registry *registry
	logger   *slog.Logger

	mu      sync.Mutex
	active  map[string]map[*deviceConn]struct{}
	count   int
	pairing map[string]struct{}
}

// deviceConn is one open device session. done closes when it has ended.
type deviceConn struct {
	cancel  context.CancelFunc
	results chan any
	done    chan struct{}
}

func newSessions(node *localNode, options Options, pending *pairings, devices *registry) *sessions {
	return &sessions{
		node:     node,
		options:  options,
		pairings: pending,
		registry: devices,
		logger:   options.Logger,
		active:   make(map[string]map[*deviceConn]struct{}),
		pairing:  make(map[string]struct{}),
	}
}

func (s *sessions) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.DirectSessionPath, s.accept)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	return mux
}

func (s *sessions) accept(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	pin := certpin.Of(r.TLS.PeerCertificates[0])
	device, paired := s.registry.byPin(pin)
	if !paired && !s.pairings.active() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{protocol.DirectSessionSubprotocol},
	})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()

	if conn.Subprotocol() != protocol.DirectSessionSubprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "subprotocol "+protocol.DirectSessionSubprotocol+" is required")
		return
	}
	conn.SetReadLimit(maxFrameBytes)

	if !paired {
		exporter, err := r.TLS.ExportKeyingMaterial(pairing.ExporterLabel, nil, pairing.ExporterSize)
		if err != nil {
			return
		}
		if !s.trackPairing(pin) {
			_ = conn.Close(websocket.StatusTryAgainLater, "too many pairing sessions")
			return
		}
		defer s.untrackPairing(pin)

		s.servePairing(r.Context(), conn, pin, exporter)
		return
	}

	s.serveDevice(r.Context(), conn, device)
}

func (s *sessions) hello(peer, deviceID string) protocol.SessionHello {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	return protocol.SessionHello{
		Type:           protocol.SessionHelloType,
		Protocol:       protocol.DirectSessionSubprotocol,
		Peer:           peer,
		DeviceID:       deviceID,
		NodeID:         s.node.id,
		AgentVersion:   s.options.Version,
		Hostname:       hostname,
		OS:             runtime.GOOS,
		Architecture:   runtime.GOARCH,
		PortalEnrolled: s.options.PortalEnrolled,
		Time:           time.Now().UTC(),
	}
}

// servePairing runs the pairing exchange for a device key that is not paired.
func (s *sessions) servePairing(ctx context.Context, conn *websocket.Conn, pin string, exporter []byte) {
	if err := writeFrame(ctx, conn, s.hello(protocol.SessionPeerInvite, "")); err != nil {
		return
	}

	started, err := s.readPairingRequest(ctx, conn, pin, exporter)
	if err != nil {
		s.logger.Debug("pairing session ended", "error", err)
		return
	}

	// The device sends nothing more; CloseRead still answers pings and
	// notices when the device goes away.
	waitCtx := conn.CloseRead(ctx)
	for {
		status, deviceID, err := s.pairings.status(waitCtx, started.PairingID)
		if err != nil {
			s.pairings.abandon(started.PairingID)
			return
		}
		if status == pairingPending {
			continue
		}

		result := protocol.PairingResult{
			Type:      protocol.PairingResultType,
			PairingID: started.PairingID,
			Status:    status,
			DeviceID:  deviceID,
		}
		if err := writeFrame(ctx, conn, result); err != nil {
			return
		}

		_ = conn.Close(websocket.StatusNormalClosure, "pairing "+status)

		return
	}
}

// readPairingRequest reads requests until one starts pairing. Requests that
// fail validation are answered and do not use up the invite.
func (s *sessions) readPairingRequest(ctx context.Context, conn *websocket.Conn, pin string, exporter []byte) (protocol.PairingStarted, error) {
	readCtx, cancel := context.WithTimeout(ctx, pairingRequestTimeout)
	defer cancel()

	for {
		data, err := wsframe.ReadRawJSON(readCtx, conn)
		if err != nil {
			return protocol.PairingStarted{}, err
		}

		var request protocol.PairingRequest
		if err := protocol.DecodeStrict(data, &request); err != nil || request.Type != protocol.PairingRequestType {
			if err := writeError(ctx, conn, "", newSessionError("invalid_message", "send pairing.request")); err != nil {
				return protocol.PairingStarted{}, err
			}
			continue
		}

		started, err := s.pairings.start(request, pin, exporter)
		if err == nil {
			return started, writeFrame(ctx, conn, started)
		}

		if writeErr := writeError(ctx, conn, "", err); writeErr != nil {
			return protocol.PairingStarted{}, writeErr
		}
		if refusal, ok := errors.AsType[*sessionError](err); !ok || refusal.code == "invite_used" || refusal == errForbidden {
			return protocol.PairingStarted{}, err
		}
	}
}

func (s *sessions) serveDevice(ctx context.Context, conn *websocket.Conn, device state.Device) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tracked := &deviceConn{cancel: cancel, results: make(chan any, sessionResultBuffer), done: make(chan struct{})}
	defer close(tracked.done)
	if !s.track(device.ID, tracked) {
		_ = conn.Close(websocket.StatusTryAgainLater, "too many sessions")
		return
	}
	defer s.untrack(device.ID, tracked)

	err := session.ServeDevice(sessionCtx, conn, session.DeviceConfig{
		Hello:           s.hello(protocol.SessionPeerDevice, device.ID),
		NodeID:          s.node.id,
		Collectors:      s.options.Collectors.session(),
		Workloads:       s.options.Workloads,
		WorkloadResults: tracked.results,
		Devices:         directory{sessions: s},
		Containers:      s.options.Containers,
		Logger:          s.logger.With("device_id", device.ID),
	})
	if err != nil && sessionCtx.Err() == nil {
		s.logger.Debug("device session ended", "device_id", device.ID, "error", err)
	}
}

func (s *sessions) track(deviceID string, conn *deviceConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Checking the registry under s.mu orders this against revoke, which
	// removes the device before it closes the device's tracked sessions.
	if s.count >= maxSessions || len(s.active[deviceID]) >= maxSessionsPerDevice || !s.registry.has(deviceID) {
		return false
	}
	if s.active[deviceID] == nil {
		s.active[deviceID] = make(map[*deviceConn]struct{})
	}

	s.active[deviceID][conn] = struct{}{}
	s.count++

	return true
}

// trackPairing allows one pairing session per device key and a few in total.
func (s *sessions) trackPairing(pin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, busy := s.pairing[pin]; busy || len(s.pairing) >= maxPairingSessions {
		return false
	}
	s.pairing[pin] = struct{}{}

	return true
}

func (s *sessions) untrackPairing(pin string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.pairing, pin)
}

func (s *sessions) untrack(deviceID string, conn *deviceConn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.active[deviceID][conn]; !found {
		return
	}

	delete(s.active[deviceID], conn)
	if len(s.active[deviceID]) == 0 {
		delete(s.active, deviceID)
	}
	s.count--
}

// fanOut copies workload responses to every open device session: all of a
// node's devices share one controller scope.
func (s *sessions) fanOut(ctx context.Context, results <-chan any) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-results:
			s.mu.Lock()
			for _, conns := range s.active {
				for conn := range conns {
					select {
					case conn.results <- result:
					default:
						s.logger.Warn("device session is not reading workload responses")
					}
				}
			}
			s.mu.Unlock()
		}
	}
}

// revoke deletes a device and ends its open sessions. The TLS listener stops
// accepting its key at once. A device that revokes itself keeps its session
// for selfRevokeDelay so it can read the answer; other sessions end now.
func (s *sessions) revoke(deviceID, callerID string) error {
	removed, err := s.registry.remove(deviceID)
	if errors.Is(err, errDeviceNotFound) {
		return session.ErrDeviceNotFound
	}
	if err != nil {
		return err
	}

	if removed.ID == callerID {
		time.AfterFunc(selfRevokeDelay, func() { s.closeDevice(removed.ID) })
	} else {
		go s.closeDevice(removed.ID)
	}
	if metrics := s.options.Collectors.Metrics; metrics != nil {
		metrics.RemoveCursor("device:" + removed.ID)
	}
	s.logger.Info("device revoked", "device_id", removed.ID, "device_name", removed.Name)

	return nil
}

// closeDevice ends the device's sessions and waits, briefly, until they
// have closed.
func (s *sessions) closeDevice(deviceID string) {
	s.mu.Lock()
	conns := make([]*deviceConn, 0, len(s.active[deviceID]))
	for conn := range s.active[deviceID] {
		conn.cancel()
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	timeout := time.NewTimer(sessionCloseTimeout)
	defer timeout.Stop()

	for _, conn := range conns {
		select {
		case <-conn.done:
		case <-timeout.C:
			return
		}
	}
}

// directory gives device sessions the paired-device operations.
type directory struct{ sessions *sessions }

func (d directory) List(currentID string) []protocol.Device {
	devices := []protocol.Device{}
	for _, device := range d.sessions.registry.list() {
		devices = append(devices, protocol.Device{
			ID:             device.ID,
			Name:           device.Name,
			CertificatePin: device.CertificatePin,
			PairedAt:       device.PairedAt,
			Current:        device.ID == currentID,
		})
	}

	return devices
}

func (d directory) Remove(currentID, deviceID string) error {
	if !agentcrypto.ValidUUID(deviceID) {
		return session.ErrDeviceNotFound
	}

	return d.sessions.revoke(deviceID, currentID)
}

func writeFrame(ctx context.Context, conn *websocket.Conn, frame any) error {
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return wsframe.WriteJSON(writeCtx, conn, frame)
}

func writeError(ctx context.Context, conn *websocket.Conn, requestID string, err error) error {
	refusal, ok := errors.AsType[*sessionError](err)
	if !ok {
		refusal = newSessionError("internal", "internal error")
	}

	return writeFrame(ctx, conn, protocol.Error{
		Type:      protocol.ErrorType,
		RequestID: requestID,
		Code:      refusal.code,
		Message:   refusal.message,
	})
}
