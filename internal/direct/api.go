package direct

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentapi"
	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/strictjson"
	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const (
	maxRequestBody   = 64 * 1024
	collectorTimeout = 45 * time.Second
	// peerRemovalDelay lets the response to a revoke request reach a device
	// that revoked itself before its peer disappears.
	peerRemovalDelay = time.Second
)

var errForbidden = newAPIError(http.StatusForbidden, "forbidden", "this peer may not call this endpoint")

// apiError is an error with a stable code that the API returns as is.
type apiError struct {
	status  int
	code    string
	message string
}

func newAPIError(status int, code, message string) *apiError {
	return &apiError{status: status, code: code, message: message}
}

func (e *apiError) Error() string { return e.message }

type deviceContextKey struct{}

// api serves paired devices and invite peers inside the tunnel. The caller
// is identified by its tunnel source address: WireGuard accepts a packet
// only from the peer that owns that address, so the address authenticates
// the device.
type api struct {
	node     *localNode
	options  Options
	pairings *pairings
	registry *registry
	tunnel   *tunnel.Tunnel
	logger   *slog.Logger
}

func (a *api) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+agentapi.PairingPath, a.invitePeer(a.startPairing))
	mux.Handle("GET "+agentapi.PairingPath+"/{id}", a.invitePeer(a.pairingStatus))
	mux.Handle("GET "+agentapi.NodePath, a.pairedDevice(a.getNode))
	mux.Handle("GET "+agentapi.SpecificationsPath, a.pairedDevice(a.getSpecifications))
	mux.Handle("GET "+agentapi.NetworkPath, a.pairedDevice(a.getNetwork))
	mux.Handle("GET "+agentapi.DevicesPath, a.pairedDevice(a.listDevices))
	mux.Handle("DELETE "+agentapi.DevicesPath+"/{id}", a.pairedDevice(a.removeDevice))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, newAPIError(http.StatusNotFound, "not_found", "no such endpoint"))
	})

	return mux
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (a *api) invitePeer(next handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := remoteAddress(r)
		if !ok || !a.pairings.isInvite(address) {
			writeError(w, errForbidden)
			return
		}

		a.serve(w, r, next)
	})
}

func (a *api) pairedDevice(next handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := remoteAddress(r)
		if !ok {
			writeError(w, errForbidden)
			return
		}

		device, found := a.registry.byAddress(address)
		if !found {
			writeError(w, errForbidden)
			return
		}

		a.serve(w, r.WithContext(context.WithValue(r.Context(), deviceContextKey{}, device)), next)
	})
}

func (a *api) serve(w http.ResponseWriter, r *http.Request, next handlerFunc) {
	err := next(w, r)
	if err == nil {
		return
	}

	var known *apiError
	if errors.As(err, &known) {
		writeError(w, known)
		return
	}

	a.logger.Error("direct API request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, newAPIError(http.StatusInternalServerError, "internal", "internal error"))
}

func (a *api) startPairing(w http.ResponseWriter, r *http.Request) error {
	var request agentapi.PairingRequest
	if err := decodeBody(w, r, &request); err != nil {
		return err
	}

	address, _ := remoteAddress(r)
	started, err := a.pairings.start(address, request)
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusCreated, started)
}

func (a *api) pairingStatus(w http.ResponseWriter, r *http.Request) error {
	pairingID := r.PathValue("id")
	if !agentcrypto.ValidUUID(pairingID) {
		return newAPIError(http.StatusNotFound, "not_found", "pairing not found")
	}

	address, _ := remoteAddress(r)
	status, err := a.pairings.status(r.Context(), address, pairingID)
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, status)
}

func (a *api) getNode(w http.ResponseWriter, _ *http.Request) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	return writeJSON(w, http.StatusOK, agentapi.Node{
		NodeID:             a.node.id,
		AgentVersion:       a.options.Version,
		Hostname:           hostname,
		OS:                 runtime.GOOS,
		Architecture:       runtime.GOARCH,
		WireGuardPublicKey: a.node.publicKey.String(),
		TunnelAddress:      a.node.address.String(),
		ListenPort:         a.node.listenPort,
		PortalEnrolled:     a.options.PortalEnrolled,
		Time:               time.Now().UTC(),
	})
}

func (a *api) getSpecifications(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()

	snapshot, err := a.options.Collectors.Specifications(ctx)
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, agentapi.Specifications{
		ObservedAt:       time.Now().UTC(),
		ObservationScope: snapshot.ObservationScope,
		Specifications:   snapshot.Specifications,
	})
}

func (a *api) getNetwork(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()

	snapshot, err := a.options.Collectors.Network(ctx)
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, agentapi.Network{
		ObservedAt:       time.Now().UTC(),
		ObservationScope: snapshot.ObservationScope,
		Network:          snapshot.Network,
	})
}

func (a *api) listDevices(w http.ResponseWriter, r *http.Request) error {
	current, _ := r.Context().Value(deviceContextKey{}).(state.Device)

	list := agentapi.DeviceList{Devices: []agentapi.Device{}}
	for _, device := range a.registry.list() {
		list.Devices = append(list.Devices, agentapi.Device{
			ID:                 device.ID,
			Name:               device.Name,
			WireGuardPublicKey: device.WireGuardPublicKey,
			TunnelAddress:      device.TunnelAddress,
			PairedAt:           device.PairedAt,
			Current:            device.ID == current.ID,
		})
	}

	return writeJSON(w, http.StatusOK, list)
}

func (a *api) removeDevice(w http.ResponseWriter, r *http.Request) error {
	deviceID := r.PathValue("id")
	if !agentcrypto.ValidUUID(deviceID) {
		return newAPIError(http.StatusNotFound, "not_found", "device not found")
	}

	if err := a.revoke(deviceID); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)

	return nil
}

// revoke deletes a device and removes its peer shortly afterwards. The
// device loses API access at once because requests are authorized against
// the registry.
func (a *api) revoke(deviceID string) error {
	removed, err := a.registry.remove(deviceID)
	if errors.Is(err, errDeviceNotFound) {
		return newAPIError(http.StatusNotFound, "not_found", "device not found")
	}
	if err != nil {
		return err
	}

	peer, err := devicePeer(removed)
	if err != nil {
		return err
	}

	time.AfterFunc(peerRemovalDelay, func() {
		if err := a.tunnel.RemovePeer(peer.PublicKey); err != nil {
			a.logger.Warn("remove revoked device peer", "device_id", removed.ID, "error", err)
		}
	})
	a.logger.Info("device revoked", "device_id", removed.ID, "device_name", removed.Name)

	return nil
}

func remoteAddress(r *http.Request) (netip.Addr, bool) {
	address, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}

	return address.Addr(), true
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		return newAPIError(http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds 64 KiB")
	}

	if err := strictjson.Decode(data, target); err != nil {
		return newAPIError(http.StatusBadRequest, "invalid_json", "request body is not valid JSON for this endpoint")
	}

	return nil
}

// writeJSON fails only when value cannot be encoded, before anything is sent.
func writeJSON(w http.ResponseWriter, status int, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	// A failed write means the peer went away; there is no one to tell.
	_, _ = w.Write(append(data, '\n'))

	return nil
}

func writeError(w http.ResponseWriter, err *apiError) {
	body := agentapi.Error{Error: agentapi.ErrorDetail{Code: err.code, Message: err.message}}
	_ = writeJSON(w, err.status, body)
}
