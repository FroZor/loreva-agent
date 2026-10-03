package direct

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const maxDevices = 256

var errDeviceNotFound = errors.New("device not found")

// registry is the persisted list of paired devices. Every change is written
// to devices.json before it becomes visible in memory.
type registry struct {
	store *state.Store

	mu      sync.RWMutex
	devices []state.Device
	saved   bool
}

func loadRegistry(store *state.Store) (*registry, error) {
	devices, err := store.LoadDevices()
	if errors.Is(err, state.ErrNotFound) {
		return &registry{store: store}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load paired devices: %w", err)
	}

	for _, device := range devices.Items {
		if _, err := devicePeer(device); err != nil {
			return nil, fmt.Errorf("paired device %s: %w", device.ID, err)
		}
	}

	return &registry{store: store, devices: devices.Items, saved: true}, nil
}

func (r *registry) list() []state.Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return slices.Clone(r.devices)
}

func (r *registry) byAddress(address netip.Addr) (state.Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, device := range r.devices {
		if device.TunnelAddress == address.String() {
			return device, true
		}
	}

	return state.Device{}, false
}

// hasPublicKey reports whether a paired device already uses publicKey.
func (r *registry) hasPublicKey(publicKey tunnel.Key) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return slices.ContainsFunc(r.devices, func(device state.Device) bool {
		return device.WireGuardPublicKey == publicKey.String()
	})
}

func (r *registry) add(device state.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.devices) >= maxDevices {
		return fmt.Errorf("at most %d devices can be paired", maxDevices)
	}

	return r.persist(append(slices.Clone(r.devices), device))
}

func (r *registry) remove(id string) (state.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	index := slices.IndexFunc(r.devices, func(device state.Device) bool { return device.ID == id })
	if index < 0 {
		return state.Device{}, errDeviceNotFound
	}

	removed := r.devices[index]
	if err := r.persist(slices.Delete(slices.Clone(r.devices), index, index+1)); err != nil {
		return state.Device{}, err
	}

	return removed, nil
}

// persist must be called with mu held.
func (r *registry) persist(devices []state.Device) error {
	document := &state.Devices{Items: devices}
	if document.Items == nil {
		document.Items = []state.Device{}
	}

	save := r.store.SaveDevices
	if r.saved {
		save = r.store.ReplaceDevices
	}
	if err := save(document); err != nil {
		return fmt.Errorf("save paired devices: %w", err)
	}

	r.devices = devices
	r.saved = true

	return nil
}

func devicePeer(device state.Device) (tunnel.Peer, error) {
	publicKey, err := tunnel.ParseKey(device.WireGuardPublicKey)
	if err != nil {
		return tunnel.Peer{}, fmt.Errorf("public key: %w", err)
	}
	presharedKey, err := tunnel.ParseKey(device.PresharedKey)
	if err != nil {
		return tunnel.Peer{}, fmt.Errorf("preshared key: %w", err)
	}
	address, err := netip.ParseAddr(device.TunnelAddress)
	if err != nil {
		return tunnel.Peer{}, fmt.Errorf("tunnel address: %w", err)
	}

	return tunnel.Peer{PublicKey: publicKey, PresharedKey: presharedKey, Address: address}, nil
}
