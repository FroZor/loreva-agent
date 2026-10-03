// Package client is the device side of direct access: it pairs with a node
// from an invite and calls the agent API through userspace WireGuard. The
// loreva-agent device commands and the end-to-end tests use it, and it is
// the reference for other clients such as loreva-app.
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
	credentialsVersion = 1
	maxCredentialsSize = 64 * 1024
)

// Credentials are everything a device needs to reach one node after
// pairing. They contain the device's private key and PSK, so they are
// stored with mode 0600.
type Credentials struct {
	Version       int      `json:"version"`
	NodeID        string   `json:"node_id"`
	NodePublicKey string   `json:"node_public_key"`
	NodeAddress   string   `json:"node_address"`
	Endpoints     []string `json:"endpoints"`
	DeviceID      string   `json:"device_id"`
	DeviceName    string   `json:"device_name"`
	PrivateKey    string   `json:"private_key"`
	PresharedKey  string   `json:"preshared_key"`
	Address       string   `json:"address"`
}

// SaveCredentials writes a new credentials file. It never overwrites one.
func SaveCredentials(path string, credentials *Credentials) (resultErr error) {
	data, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create credentials file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close credentials file: %w", err))
		}
	}()

	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}

	return file.Sync()
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

	var credentials Credentials
	if err := strictjson.Decode(data, &credentials); err != nil {
		return nil, fmt.Errorf("decode credentials file: %w", err)
	}
	if credentials.Version != credentialsVersion {
		return nil, fmt.Errorf("unsupported credentials version %d", credentials.Version)
	}

	return &credentials, nil
}
