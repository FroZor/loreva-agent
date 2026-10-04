package direct

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentapi"
	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const (
	defaultInviteTTL = 15 * time.Minute
	minInviteTTL     = time.Minute
	maxInviteTTL     = time.Hour
	// decisionGrace keeps the temporary peer after a decision so the device
	// can read the final status before the node drops it.
	decisionGrace     = 30 * time.Second
	statusWait        = 25 * time.Second
	maxActiveInvites  = 16
	addressAttempts   = 8
	inviteEventBuffer = 4
)

// inviteSession is one invite created through the control socket. Its
// secrets exist only in memory and its temporary peer is removed when the
// session ends.
type inviteSession struct {
	invite    *pairing.Invite
	peerKey   tunnel.Key
	noConfirm bool
	events    chan control.Message
	timer     *time.Timer
	pairing   *pairingSession
	// graceUntil is when the temporary peer may go after a decision.
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

// pairings owns invite sessions. The temporary invite peer may reach only
// the pairing endpoints, and each invite starts at most one pairing.
type pairings struct {
	node     *localNode
	tunnel   *tunnel.Tunnel
	registry *registry
	logger   *slog.Logger

	mu      sync.Mutex
	invites map[netip.Addr]*inviteSession
}

func newPairings(node *localNode, tun *tunnel.Tunnel, devices *registry, logger *slog.Logger) *pairings {
	return &pairings{
		node:     node,
		tunnel:   tun,
		registry: devices,
		logger:   logger,
		invites:  make(map[netip.Addr]*inviteSession),
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

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.invites) >= maxActiveInvites {
		return nil, "", errors.New("too many active invites")
	}

	invite, err := p.newInviteLocked(advertised, ttl)
	if err != nil {
		return nil, "", err
	}
	encoded, err := invite.Encode()
	if err != nil {
		return nil, "", err
	}
	peerKey, err := invite.PrivateKey.PublicKey()
	if err != nil {
		return nil, "", err
	}

	err = p.tunnel.AddPeer(tunnel.Peer{PublicKey: peerKey, PresharedKey: invite.PresharedKey, Address: invite.Address})
	if err != nil {
		return nil, "", err
	}

	session := &inviteSession{
		invite:    invite,
		peerKey:   peerKey,
		noConfirm: noConfirm,
		events:    make(chan control.Message, inviteEventBuffer),
	}
	session.timer = time.AfterFunc(ttl, func() { p.expire(session) })
	p.invites[invite.Address] = session

	return session, encoded, nil
}

func (p *pairings) newInviteLocked(endpoints []netip.AddrPort, ttl time.Duration) (*pairing.Invite, error) {
	inviteID, err := agentcrypto.NewUUID()
	if err != nil {
		return nil, err
	}
	privateKey, err := tunnel.GenerateKey()
	if err != nil {
		return nil, err
	}
	presharedKey, err := tunnel.GenerateKey()
	if err != nil {
		return nil, err
	}
	address, err := p.freeAddressLocked()
	if err != nil {
		return nil, err
	}

	return &pairing.Invite{
		InviteID:      inviteID,
		NodeID:        p.node.id,
		NodePublicKey: p.node.publicKey,
		NodeAddress:   p.node.address,
		Endpoints:     endpoints,
		PrivateKey:    privateKey,
		PresharedKey:  presharedKey,
		Address:       address,
		ExpiresAt:     time.Now().Add(ttl).UTC().Truncate(time.Second),
	}, nil
}

// freeAddressLocked returns a tunnel address no device or invite uses.
func (p *pairings) freeAddressLocked() (netip.Addr, error) {
	for range addressAttempts {
		address, err := tunnel.RandomAddress(p.node.prefix)
		if err != nil {
			continue
		}

		if _, used := p.invites[address]; !used && !p.hasDevice(address) {
			return address, nil
		}
	}

	return netip.Addr{}, errors.New("could not allocate a tunnel address")
}

func (p *pairings) hasDevice(address netip.Addr) bool {
	_, found := p.registry.byAddress(address)

	return found
}

// isInvite reports whether address belongs to an active invite peer.
func (p *pairings) isInvite(address netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, found := p.invites[address]

	return found
}

// start handles POST /v1/pairing from an invite peer.
func (p *pairings) start(from netip.Addr, request agentapi.PairingRequest) (agentapi.PairingStarted, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := p.invites[from]
	if session == nil {
		return agentapi.PairingStarted{}, errForbidden
	}
	if session.pairing != nil {
		return agentapi.PairingStarted{}, newAPIError(http.StatusConflict, "invite_used", "this invite has already been used")
	}

	transcript, sharedSecret, err := p.transcriptLocked(session, request)
	if err != nil {
		return agentapi.PairingStarted{}, err
	}

	pairingID, err := agentcrypto.NewUUID()
	if err != nil {
		return agentapi.PairingStarted{}, err
	}
	deviceID, err := agentcrypto.NewUUID()
	if err != nil {
		return agentapi.PairingStarted{}, err
	}
	presharedKey, err := transcript.PresharedKey(sharedSecret, session.invite.PresharedKey)
	if err != nil {
		return agentapi.PairingStarted{}, err
	}

	session.pairing = &pairingSession{
		id:     pairingID,
		status: agentapi.PairingPending,
		sas:    transcript.SAS(),
		device: state.Device{
			ID:                 deviceID,
			Name:               transcript.DeviceName,
			WireGuardPublicKey: transcript.DevicePublicKey.String(),
			PresharedKey:       presharedKey.String(),
			TunnelAddress:      transcript.DeviceAddress.String(),
		},
		changed: make(chan struct{}),
	}
	p.notifyLocked(session, control.Message{
		Type:        control.TypePairingRequested,
		PairingID:   pairingID,
		DeviceName:  transcript.DeviceName,
		Fingerprint: transcript.DevicePublicKey.String(),
		SAS:         session.pairing.sas,
	})

	if session.noConfirm {
		if err := p.decideLocked(session, true); err != nil {
			return agentapi.PairingStarted{}, err
		}
	}

	return agentapi.PairingStarted{
		PairingID:       pairingID,
		NodeNonce:       base64.StdEncoding.EncodeToString(transcript.NodeNonce),
		MLKEMCiphertext: base64.StdEncoding.EncodeToString(transcript.Ciphertext),
		DeviceAddress:   transcript.DeviceAddress.String(),
	}, nil
}

// transcriptLocked validates the device's commitment and completes the node
// side of the key agreement.
func (p *pairings) transcriptLocked(session *inviteSession, request agentapi.PairingRequest) (*pairing.Transcript, []byte, error) {
	if err := pairing.ValidateDeviceName(request.DeviceName); err != nil {
		return nil, nil, newAPIError(http.StatusBadRequest, "invalid_device_name", err.Error())
	}

	devicePublicKey, err := tunnel.ParseKey(request.WireGuardPublicKey)
	if err != nil || devicePublicKey.IsZero() || devicePublicKey == p.node.publicKey ||
		devicePublicKey == session.peerKey || p.registry.hasPublicKey(devicePublicKey) {
		return nil, nil, newAPIError(http.StatusBadRequest, "invalid_public_key", "wireguard_public_key must be a new 32-byte key")
	}

	encapsulationKey, err := base64.StdEncoding.Strict().DecodeString(request.MLKEMEncapsulationKey)
	if err != nil {
		return nil, nil, newAPIError(http.StatusBadRequest, "invalid_mlkem_key", "mlkem_encapsulation_key must be standard Base64")
	}
	sharedSecret, ciphertext, err := pairing.Encapsulate(encapsulationKey)
	if err != nil {
		return nil, nil, newAPIError(http.StatusBadRequest, "invalid_mlkem_key", "mlkem_encapsulation_key is not a valid ML-KEM-768 key")
	}

	deviceAddress, err := p.freeAddressLocked()
	if err != nil {
		return nil, nil, err
	}
	nonce, err := pairing.NewNonce()
	if err != nil {
		return nil, nil, err
	}

	transcript := &pairing.Transcript{
		InviteID:         session.invite.InviteID,
		NodeID:           p.node.id,
		NodePublicKey:    p.node.publicKey,
		DevicePublicKey:  devicePublicKey,
		DeviceName:       request.DeviceName,
		DeviceAddress:    deviceAddress,
		EncapsulationKey: encapsulationKey,
		Ciphertext:       ciphertext,
		NodeNonce:        nonce,
	}

	return transcript, sharedSecret, nil
}

// status handles GET /v1/pairing/{id}. While the pairing is pending it waits
// up to statusWait for a decision.
func (p *pairings) status(ctx context.Context, from netip.Addr, pairingID string) (agentapi.PairingStatus, error) {
	p.mu.Lock()
	session := p.invites[from]
	if session == nil || session.pairing == nil || session.pairing.id != pairingID {
		p.mu.Unlock()
		return agentapi.PairingStatus{}, newAPIError(http.StatusNotFound, "not_found", "pairing not found")
	}
	current := session.pairing
	changed := current.changed
	pending := current.status == agentapi.PairingPending
	p.mu.Unlock()

	if pending {
		wait := time.NewTimer(statusWait)
		defer wait.Stop()

		select {
		case <-changed:
		case <-wait.C:
		case <-ctx.Done():
			return agentapi.PairingStatus{}, errUnavailable
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	result := agentapi.PairingStatus{Status: current.status}
	if current.status == agentapi.PairingApproved {
		result.DeviceID = current.device.ID
	}

	return result, nil
}

// decide applies the operator's answer from the control socket.
func (p *pairings) decide(session *inviteSession, pairingID string, approve bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if session.done || session.pairing == nil || session.pairing.id != pairingID ||
		session.pairing.status != agentapi.PairingPending {
		return errors.New("no pending pairing with this ID")
	}

	return p.decideLocked(session, approve)
}

func (p *pairings) decideLocked(session *inviteSession, approve bool) error {
	current := session.pairing

	if approve {
		current.device.PairedAt = time.Now().UTC()
		if err := p.addDevice(current.device); err != nil {
			p.finishLocked(session, agentapi.PairingRejected)
			return err
		}

		p.finishLocked(session, agentapi.PairingApproved)
		p.logger.Info("device paired", "device_id", current.device.ID, "device_name", current.device.Name)

		return nil
	}

	p.finishLocked(session, agentapi.PairingRejected)

	return nil
}

func (p *pairings) addDevice(device state.Device) error {
	peer, err := devicePeer(device)
	if err != nil {
		return err
	}
	if err := p.registry.add(device); err != nil {
		return err
	}
	if err := p.tunnel.AddPeer(peer); err != nil {
		if _, removeErr := p.registry.remove(device.ID); removeErr != nil {
			return errors.Join(err, removeErr)
		}

		return err
	}

	return nil
}

// finishLocked records a terminal status, tells the CLI, and keeps the
// temporary peer for decisionGrace so the device can read the status.
func (p *pairings) finishLocked(session *inviteSession, status string) {
	current := session.pairing
	current.status = status
	close(current.changed)

	switch status {
	case agentapi.PairingApproved:
		p.notifyLocked(session, control.Message{
			Type:       control.TypePairingCompleted,
			PairingID:  current.id,
			DeviceID:   current.device.ID,
			DeviceName: current.device.Name,
		})
	case agentapi.PairingRejected:
		p.notifyLocked(session, control.Message{Type: control.TypePairingRejected, PairingID: current.id})
	case agentapi.PairingExpired:
		p.notifyLocked(session, control.Message{Type: control.TypeInviteExpired})
	}

	session.graceUntil = time.Now().Add(decisionGrace)
	session.timer.Reset(decisionGrace)
}

// expire ends an invite when its lifetime or grace period runs out. A
// pending pairing first becomes expired and keeps the peer for the grace
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
	case session.pairing.status == agentapi.PairingPending:
		p.finishLocked(session, agentapi.PairingExpired)
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
	case session.pairing.status == agentapi.PairingPending:
		p.finishLocked(session, agentapi.PairingExpired)
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
	delete(p.invites, session.invite.Address)
	close(session.events)

	if err := p.tunnel.RemovePeer(session.peerKey); err != nil {
		p.logger.Warn("remove invite peer", "error", err)
	}
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
