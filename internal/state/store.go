// Package state persists crash-safe agent identity transactions.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const (
	currentVersion = 1
	maxStateSize   = 1024 * 1024
	identityName   = "identity.json"
	pendingName    = "enrollment-pending.json"
	renewalName    = "renewal-pending.json"
)

// ErrNotFound indicates that the requested state document does not exist.
var ErrNotFound = errors.New("agent state not found")

// Store persists security-sensitive agent state in one protected directory.
type Store struct {
	dir string
}

// DefaultDir resolves the configured or platform-default state directory.
func DefaultDir() (string, error) {
	if configured := os.Getenv("LOREVA_STATE_DIR"); configured != "" {
		return filepath.Abs(configured)
	}

	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}

	return filepath.Join(base, "loreva-agent"), nil
}

// New creates a state store descriptor without writing to disk.
func New(dir string) (*Store, error) {
	if dir == "" {
		var err error
		dir, err = DefaultDir()
		if err != nil {
			return nil, err
		}
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}

	return &Store{dir: abs}, nil
}

// Dir returns the absolute state directory.
func (s *Store) Dir() string { return s.dir }

// LoadPending loads an incomplete enrollment transaction.
func (s *Store) LoadPending() (*PendingEnrollment, error) {
	var pending PendingEnrollment
	if err := s.load(pendingName, &pending); err != nil {
		return nil, err
	}

	if pending.Version != currentVersion {
		return nil, fmt.Errorf("unsupported pending state version %d", pending.Version)
	}

	return &pending, nil
}

// SavePending creates enrollment state without replacing an existing transaction.
func (s *Store) SavePending(pending *PendingEnrollment) error {
	pending.Version = currentVersion
	return s.saveNew(pendingName, pending)
}

// LoadRenewal loads an incomplete identity renewal transaction.
func (s *Store) LoadRenewal() (*PendingRenewal, error) {
	var pending PendingRenewal
	if err := s.load(renewalName, &pending); err != nil {
		return nil, err
	}

	if pending.Version != currentVersion {
		return nil, fmt.Errorf("unsupported renewal state version %d", pending.Version)
	}

	return &pending, nil
}

// SaveRenewal creates renewal state without replacing an existing transaction.
func (s *Store) SaveRenewal(pending *PendingRenewal) error {
	pending.Version = currentVersion
	return s.saveNew(renewalName, pending)
}

// LoadIdentity loads the enrolled agent identity.
func (s *Store) LoadIdentity() (*Identity, error) {
	var identity Identity
	if err := s.load(identityName, &identity); err != nil {
		return nil, err
	}

	if identity.Version != currentVersion {
		return nil, fmt.Errorf("unsupported identity state version %d", identity.Version)
	}

	return &identity, nil
}

// SaveIdentity creates the first enrolled identity without overwriting one.
func (s *Store) SaveIdentity(identity *Identity) error {
	identity.Version = currentVersion
	return s.saveNew(identityName, identity)
}

// ReplaceIdentity atomically replaces an existing, secure identity file. The
// caller must completely validate the replacement certificate and credential
// before invoking this method.
func (s *Store) ReplaceIdentity(identity *Identity) error {
	identity.Version = currentVersion
	return s.replaceExisting(identityName, identity)
}

// ClearPending removes a completed enrollment transaction.
func (s *Store) ClearPending() error {
	return s.clear(pendingName, "completed enrollment")
}

// ClearRenewal removes a completed renewal transaction.
func (s *Store) ClearRenewal() error {
	return s.clear(renewalName, "completed renewal")
}

func (s *Store) clear(name, description string) error {
	err := os.Remove(filepath.Join(s.dir, name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s state: %w", description, err)
	}

	if err == nil {
		if syncErr := syncDirectory(s.dir); syncErr != nil {
			return syncErr
		}
	}

	return nil
}

func (s *Store) load(name string, target any) (resultErr error) {
	path := filepath.Join(s.dir, name)

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("inspect state file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("state path must be a regular file, not a link")
	}
	if err := ensureSecureFile(path, info); err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close state file: %w", err))
		}
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxStateSize+1))
	if err != nil {
		return fmt.Errorf("read state file: %w", err)
	}
	if len(data) > maxStateSize {
		return errors.New("state file exceeds 1 MiB limit")
	}

	if err := strictjson.Decode(data, target); err != nil {
		return fmt.Errorf("decode state file: %w", err)
	}

	return nil
}

func (s *Store) saveNew(name string, value any) error {
	return s.save(name, value, false)
}

func (s *Store) replaceExisting(name string, value any) error {
	return s.save(name, value, true)
}

func (s *Store) save(name string, value any, replace bool) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := secureDirectory(s.dir); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}

	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if replace {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inspect state destination: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("state destination must be a regular file, not a link")
		}
		if err := ensureSecureFile(path, info); err != nil {
			return err
		}
	} else {
		if err == nil {
			return fmt.Errorf("state file already exists: %s", path)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect state destination: %w", err)
		}
	}

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxStateSize {
		return errors.New("encoded state exceeds 1 MiB limit")
	}

	temp, err := os.CreateTemp(s.dir, ".loreva-state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempName)
		}
	}()

	if err := secureFile(tempName); err != nil {
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}

	commit := commitState
	if replace {
		commit = replaceState
	}
	if err := commit(tempName, path); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}

	committed = true
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("sync state directory after commit: %w", err)
	}

	return nil
}
