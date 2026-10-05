// Package client is the reference device side of direct access: it pairs with
// a node from a connection key and opens the node protocol session over TLS
// with mutual key pinning. The loreva-agent device commands and the
// end-to-end tests use it; Loreva App implements the same protocol.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const (
	credentialsVersion = 2
	maxCredentialsSize = 64 * 1024
)

// Credentials are everything a device needs to reach one node after
// pairing. They contain the device's private key, so they are stored with
// mode 0600.
type Credentials struct {
	Version    int      `json:"version"`
	NodeID     string   `json:"node_id"`
	NodePin    string   `json:"node_pin"`
	Endpoints  []string `json:"endpoints"`
	DeviceID   string   `json:"device_id"`
	DeviceName string   `json:"device_name"`
	// PrivateKey and Certificate are the device's TLS identity, standard
	// Base64 PKCS#8 and DER.
	PrivateKey  string `json:"private_key"`
	Certificate string `json:"certificate"`
}

// CredentialsFile is a new credentials file, created before pairing so a
// path problem is found before the node registers the device.
type CredentialsFile struct {
	file *os.File
}

// CreateCredentials creates path with mode 0600. It never overwrites a file.
func CreateCredentials(path string) (*CredentialsFile, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create credentials file: %w", err)
	}

	return &CredentialsFile{file: file}, nil
}

// Write stores credentials, syncs, and closes the file.
func (f *CredentialsFile) Write(credentials *Credentials) error {
	data, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return errors.Join(fmt.Errorf("encode credentials: %w", err), f.file.Close())
	}

	if _, err := f.file.Write(append(data, '\n')); err != nil {
		return errors.Join(fmt.Errorf("write credentials file: %w", err), f.file.Close())
	}
	if err := f.file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync credentials file: %w", err), f.file.Close())
	}

	return f.file.Close()
}

// Discard closes and removes a file that was never written.
func (f *CredentialsFile) Discard() error {
	return errors.Join(f.file.Close(), os.Remove(f.file.Name()))
}

// LoadCredentials reads a credentials file and refuses one that other users
// can read.
func LoadCredentials(path string) (result *Credentials, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credentials file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close credentials file: %w", err))
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect credentials file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credentials file must be a regular file with mode 0600")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxCredentialsSize+1))
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	if len(data) > maxCredentialsSize {
		return nil, errors.New("credentials file is too large")
	}

	return ParseCredentials(data)
}

// ParseCredentials decodes credentials, for example from an app keychain.
func ParseCredentials(data []byte) (*Credentials, error) {
	if len(data) > maxCredentialsSize {
		return nil, errors.New("credentials are too large")
	}

	var credentials Credentials
	if err := strictjson.Decode(data, &credentials); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	if credentials.Version != credentialsVersion {
		return nil, fmt.Errorf("unsupported credentials version %d", credentials.Version)
	}

	return &credentials, nil
}
