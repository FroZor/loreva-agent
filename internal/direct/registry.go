package direct

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/state"
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

// loadRegistry loads devices.json. Devices paired over WireGuard cannot
// connect any more, so their registry starts empty and is replaced on the
// next pairing; legacy reports that case.
func loadRegistry(store *state.Store) (devices *registry, legacy bool, err error) {
	document, err := store.LoadDevices()
	if errors.Is(err, state.ErrNotFound) {
		return &registry{store: store}, false, nil
	}
	if errors.Is(err, state.ErrLegacyDirect) {
		// Replace the old registry at once, so WireGuard keys and PSKs of
		// devices that can no longer connect do not stay on disk.
		devices := &registry{store: store, saved: true}
		if err := devices.persist(nil); err != nil {
			return nil, false, err
		}

		return devices, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load paired devices: %w", err)
	}

	for _, device := range document.Items {
		if err := certpin.Validate(device.CertificatePin); err != nil {
			return nil, false, fmt.Errorf("paired device %s: %w", device.ID, err)
		}
	}

	return &registry{store: store, devices: document.Items, saved: true}, false, nil
}

func (r *registry) list() []state.Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return slices.Clone(r.devices)
}

func (r *registry) byPin(pin string) (state.Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, device := range r.devices {
		if device.CertificatePin == pin {
			return device, true
		}
	}

	return state.Device{}, false
}

func (r *registry) add(device state.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.devices) >= maxDevices {
		return fmt.Errorf("at most %d devices can be paired", maxDevices)
	}
	if slices.ContainsFunc(r.devices, func(existing state.Device) bool { return existing.CertificatePin == device.CertificatePin }) {
		return errors.New("this device key is already paired")
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

func (r *registry) has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return slices.ContainsFunc(r.devices, func(device state.Device) bool { return device.ID == id })
}
