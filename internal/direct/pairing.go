package direct

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
)

const (
	defaultInviteTTL = 15 * time.Minute
	minInviteTTL     = time.Minute
	maxInviteTTL     = time.Hour
	// decisionGrace keeps a decided invite around so the device can read
	// the final status before the node forgets it.
	decisionGrace     = 30 * time.Second
	statusWait        = 25 * time.Second
	maxActiveInvites  = 16
	inviteEventBuffer = 4
)

// inviteSession is one invite created through the control socket. Its token
// exists only in memory and dies with the CLI connection that created it.
type inviteSession struct {
	invite    *pairing.Invite
	noConfirm bool
	events    chan control.Message
	timer     *time.Timer
	pairing   *pairingSession
	// graceUntil is when the invite may go after a decision.
	graceUntil time.Time
	done       bool
}

type pairingSession struct {
	id      string
	status  string
	sas     string
	device  state.Device
	changed chan struct{}
}

// pairings owns invite sessions. Each invite starts at most one pairing.
type pairings struct {
	node     *localNode
	registry *registry
	logger   *slog.Logger

	mu      sync.Mutex
	invites map[string]*inviteSession
}

func newPairings(node *localNode, devices *registry, logger *slog.Logger) *pairings {
	return &pairings{
		node:     node,
		registry: devices,
		logger:   logger,
		invites:  make(map[string]*inviteSession),
	}
}

func (p *pairings) createInvite(ttl time.Duration, endpoints []string, noConfirm bool) (*inviteSession, string, error) {
	if ttl == 0 {
		ttl = defaultInviteTTL
	}
	if ttl < minInviteTTL || ttl > maxInviteTTL {
		return nil, "", fmt.Errorf("invite lifetime must be between %s and %s", minInviteTTL, maxInviteTTL)
	}

	advertised, err := inviteEndpoints(endpoints, p.node.endpoints, p.node.listenPort)
	if err != nil {
		return nil, "", err
	}

	inviteID, err := agentcrypto.NewUUID()
	if err != nil {
		return nil, "", err
	}
	token, err := pairing.NewToken()
	if err != nil {
		return nil, "", err
	}

	invite := &pairing.Invite{
		InviteID:  inviteID,
		NodeID:    p.node.id,
		NodePin:   p.node.pin,
		Endpoints: advertised,
		Token:     token,
		ExpiresAt: time.Now().Add(ttl).UTC().Truncate(time.Second),
	}
	encoded, err := invite.Encode()
	if err != nil {
		return nil, "", err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.invites) >= maxActiveInvites {
		return nil, "", errors.New("too many active invites")
	}

	session := &inviteSession{
		invite:    invite,
		noConfirm: noConfirm,
		events:    make(chan control.Message, inviteEventBuffer),
	}
	session.timer = time.AfterFunc(ttl, func() { p.expire(session) })
	p.invites[inviteID] = session

	return session, encoded, nil
}

// active reports whether any invite can still start a pairing. Without one,
// the TLS listener refuses every client certificate it does not know.
func (p *pairings) active() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, session := range p.invites {
		if !session.done && session.pairing == nil {
			return true
		}
	}

	return false
}

// start handles pairing.request. devicePin is the pin of the client
// certificate the device presented on this TLS connection, which proves it
// holds the key; exporter is this connection's TLS exporter value.
func (p *pairings) start(request protocol.PairingRequest, devicePin string, exporter []byte) (protocol.PairingStarted, error) {
	token, err := pairing.DecodeToken(request.InviteToken)
	if err != nil {
		return protocol.PairingStarted{}, errForbidden
	}
	if err := pairing.ValidateDeviceName(request.DeviceName); err != nil {
		return protocol.PairingStarted{}, newSessionError("invalid_device_name", err.Error())
	}
	if _, paired := p.registry.byPin(devicePin); paired {
		return protocol.PairingStarted{}, newSessionError("already_paired", "this device key is already paired")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, other := range p.invites {
		if other.pairing != nil && other.pairing.status == pairingPending && other.pairing.device.CertificatePin == devicePin {
			return protocol.PairingStarted{}, newSessionError("pairing_pending", "this device key already has a pending pairing")
		}
	}

	session := p.sessionByTokenLocked(token)
	if session == nil {
		return protocol.PairingStarted{}, errForbidden
	}
	if session.pairing != nil {
		return protocol.PairingStarted{}, newSessionError("invite_used", "this invite has already been used")
	}

	pairingID, err := agentcrypto.NewUUID()
	if err != nil {
		return protocol.PairingStarted{}, err
	}
	deviceID, err := agentcrypto.NewUUID()
	if err != nil {
		return protocol.PairingStarted{}, err
	}
	nonce, err := pairing.NewNonce()
	if err != nil {
		return protocol.PairingStarted{}, err
	}

	transcript := pairing.Transcript{
		InviteID:   session.invite.InviteID,
		NodeID:     p.node.id,
		NodePin:    p.node.pin,
		DevicePin:  devicePin,
		DeviceName: request.DeviceName,
		NodeNonce:  nonce,
		Exporter:   exporter,
	}
	session.pairing = &pairingSession{
		id:     pairingID,
		status: pairingPending,
		sas:    transcript.SAS(),
		device: state.Device{
			ID:             deviceID,
			Name:           request.DeviceName,
			CertificatePin: devicePin,
		},
		changed: make(chan struct{}),
	}
	p.notifyLocked(session, control.Message{
		Type:        control.TypePairingRequested,
		PairingID:   pairingID,
		DeviceName:  request.DeviceName,
		Fingerprint: devicePin,
		SAS:         session.pairing.sas,
	})

	if session.noConfirm {
		if err := p.decideLocked(session, true); err != nil {
			return protocol.PairingStarted{}, err
		}
	}

	return protocol.PairingStarted{
		Type:      protocol.PairingStartedType,
		PairingID: pairingID,
		NodeNonce: base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// sessionByTokenLocked compares the token with every live invite in
// constant time, so timing reveals neither a match nor its position.
func (p *pairings) sessionByTokenLocked(token []byte) *inviteSession {
	var found *inviteSession
	for _, session := range p.invites {
		if pairing.TokenEqual(session.invite.Token, token) && !session.done {
			found = session
		}
	}

	return found
}

// status reports the pairing status and, once approved, the device ID. While
// the pairing is pending it waits up to statusWait for a decision.
func (p *pairings) status(ctx context.Context, pairingID string) (string, string, error) {
	p.mu.Lock()
	var current *pairingSession
	for _, session := range p.invites {
		if session.pairing != nil && session.pairing.id == pairingID {
			current = session.pairing
		}
	}
	if current == nil {
		p.mu.Unlock()
		return "", "", newSessionError("not_found", "pairing not found")
	}
	changed := current.changed
	pending := current.status == pairingPending
	p.mu.Unlock()

	if pending {
		wait := time.NewTimer(statusWait)
		defer wait.Stop()

		select {
		case <-changed:
		case <-wait.C:
		case <-ctx.Done():
			return "", "", errUnavailable
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if current.status == protocol.PairingApproved {
		return current.status, current.device.ID, nil
	}

	return current.status, "", nil
}

// decide applies the operator's answer from the control socket.
func (p *pairings) decide(session *inviteSession, pairingID string, approve bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if session.done || session.pairing == nil || session.pairing.id != pairingID ||
		session.pairing.status != pairingPending {
		return errors.New("no pending pairing with this ID")
	}

	return p.decideLocked(session, approve)
}

func (p *pairings) decideLocked(session *inviteSession, approve bool) error {
	current := session.pairing

	if approve {
		current.device.PairedAt = time.Now().UTC()
		if err := p.registry.add(current.device); err != nil {
			p.finishLocked(session, protocol.PairingRejected)
			return err
		}

		p.finishLocked(session, protocol.PairingApproved)
		p.logger.Info("device paired", "device_id", current.device.ID, "device_name", current.device.Name)

		return nil
	}

	p.finishLocked(session, protocol.PairingRejected)

	return nil
}

// finishLocked records a terminal status, tells the CLI, and keeps the invite
// for decisionGrace so the device can read the status.
func (p *pairings) finishLocked(session *inviteSession, status string) {
	current := session.pairing
	current.status = status
	close(current.changed)

	switch status {
	case protocol.PairingApproved:
		p.notifyLocked(session, control.Message{
			Type:       control.TypePairingCompleted,
			PairingID:  current.id,
			DeviceID:   current.device.ID,
			DeviceName: current.device.Name,
		})
	case protocol.PairingRejected:
		p.notifyLocked(session, control.Message{Type: control.TypePairingRejected, PairingID: current.id})
	case protocol.PairingExpired:
		p.notifyLocked(session, control.Message{Type: control.TypeInviteExpired})
	}

	session.graceUntil = time.Now().Add(decisionGrace)
	session.timer.Reset(decisionGrace)
}

// expire ends an invite when its lifetime or grace period runs out. A
// pending pairing first becomes expired and keeps the invite for the grace
// period, so the device learns the result instead of timing out.
func (p *pairings) expire(session *inviteSession) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if session.done {
		return
	}

	switch {
	case session.pairing == nil:
		p.notifyLocked(session, control.Message{Type: control.TypeInviteExpired})
		p.removeLocked(session)
	case session.pairing.status == pairingPending:
		p.finishLocked(session, protocol.PairingExpired)
	case time.Now().Before(session.graceUntil):
		// A decision re-armed the timer while this call waited for the lock.
	default:
		p.removeLocked(session)
	}
}

// cancel ends an invite whose CLI connection closed. A decided pairing keeps
// its grace period so the device still learns the result.
func (p *pairings) cancel(session *inviteSession) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if session.done {
		return
	}

	switch {
	case session.pairing == nil:
		p.removeLocked(session)
	case session.pairing.status == pairingPending:
		p.finishLocked(session, protocol.PairingExpired)
	}
}

// closeAll ends every invite when the server stops.
func (p *pairings) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, session := range p.invites {
		p.removeLocked(session)
	}
}

func (p *pairings) removeLocked(session *inviteSession) {
	session.done = true
	session.timer.Stop()
	delete(p.invites, session.invite.InviteID)
	close(session.events)
}

func (p *pairings) notifyLocked(session *inviteSession, message control.Message) {
	if session.done {
		return
	}

	select {
	case session.events <- message:
	default:
		p.logger.Warn("control client is not reading invite events", "type", message.Type)
	}
}

// abandon expires a pending pairing whose device disconnected, so the
// operator cannot approve a device that is gone.
func (p *pairings) abandon(pairingID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, session := range p.invites {
		if session.pairing != nil && session.pairing.id == pairingID && session.pairing.status == pairingPending && !session.done {
			p.finishLocked(session, protocol.PairingExpired)
		}
	}
}
