package state

import (
	"errors"
	"fmt"
)

const connectionPreferenceName = "connection.json"

// ConnectionMode is the operator-visible lifecycle state of portal connectivity.
type ConnectionMode string

const (
	// ConnectionModeEnabled allows the agent supervisor to maintain a portal session.
	ConnectionModeEnabled ConnectionMode = "enabled"
	// ConnectionModeDisconnected pauses portal connectivity until an explicit connect.
	ConnectionModeDisconnected ConnectionMode = "disconnected"
	// ConnectionModeRequiresConfiguration pauses a rejected identity until configure succeeds.
	ConnectionModeRequiresConfiguration ConnectionMode = "requires_configuration"
)

type connectionPreference struct {
	Version int            `json:"version"`
	Mode    ConnectionMode `json:"mode"`
}

// ConnectionMode reports the persisted connection preference. A missing
// preference enables connections for backward compatibility.
func (s *Store) ConnectionMode() (ConnectionMode, error) {
	var preference connectionPreference
	if err := s.load(connectionPreferenceName, &preference); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ConnectionModeEnabled, nil
		}

		return "", fmt.Errorf("load connection preference: %w", err)
	}
	if preference.Version != currentVersion {
		return "", fmt.Errorf("unsupported connection preference version %d", preference.Version)
	}
	if !validConnectionMode(preference.Mode) {
		return "", fmt.Errorf("unsupported connection mode %q", preference.Mode)
	}

	return preference.Mode, nil
}

// ConnectionEnabled reports whether the supervisor may maintain a portal session.
func (s *Store) ConnectionEnabled() (bool, error) {
	mode, err := s.ConnectionMode()
	if err != nil {
		return false, err
	}

	return mode == ConnectionModeEnabled, nil
}

// SetConnectionEnabled atomically persists whether the agent may connect.
func (s *Store) SetConnectionEnabled(enabled bool) error {
	mode := ConnectionModeDisconnected
	if enabled {
		mode = ConnectionModeEnabled
	}

	return s.SetConnectionMode(mode)
}

// RequireConfiguration pauses connectivity until a new identity is configured.
func (s *Store) RequireConfiguration() error {
	return s.SetConnectionMode(ConnectionModeRequiresConfiguration)
}

// CompleteConfiguration enables connectivity unless the operator explicitly
// disconnected the agent before replacing its identity.
func (s *Store) CompleteConfiguration() error {
	mode, err := s.ConnectionMode()
	if err != nil {
		return err
	}
	if mode == ConnectionModeDisconnected {
		return nil
	}

	return s.SetConnectionMode(ConnectionModeEnabled)
}

// SetConnectionMode atomically persists the connection lifecycle state.
func (s *Store) SetConnectionMode(mode ConnectionMode) error {
	if !validConnectionMode(mode) {
		return fmt.Errorf("unsupported connection mode %q", mode)
	}

	preference := &connectionPreference{
		Version: currentVersion,
		Mode:    mode,
	}

	var existing connectionPreference
	err := s.load(connectionPreferenceName, &existing)
	switch {
	case err == nil:
		if existing.Version != currentVersion {
			return fmt.Errorf("unsupported connection preference version %d", existing.Version)
		}

		return s.replaceExisting(connectionPreferenceName, preference)
	case errors.Is(err, ErrNotFound):
		return s.saveNew(connectionPreferenceName, preference)
	default:
		return fmt.Errorf("load connection preference: %w", err)
	}
}

func validConnectionMode(mode ConnectionMode) bool {
	switch mode {
	case ConnectionModeEnabled, ConnectionModeDisconnected, ConnectionModeRequiresConfiguration:
		return true
	default:
		return false
	}
}
