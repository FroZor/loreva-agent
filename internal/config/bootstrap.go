// Package config loads bounded bootstrap and portal trust configuration.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const maxConfigSize = 64 * 1024
const maxEncodedConfigSize = ((maxConfigSize + 2) / 3) * 4

// Bootstrap contains the mandatory inputs needed for first enrollment.
type Bootstrap struct {
	PortalURL          string           `json:"portal_url"`
	EnrollmentToken    string           `json:"enrollment_token"`
	PortalCA           string           `json:"portal_ca,omitempty"`
	PortalPQRoot       *agentcrypto.JWK `json:"portal_pq_root"`
	StateDir           string           `json:"state_dir,omitempty"`
	AllowDevelopmentWS bool             `json:"allow_development_ws,omitempty"`
}

type serverBootstrap struct {
	Portal       string           `json:"portal"`
	Token        string           `json:"token"`
	PortalCA     string           `json:"portal_ca,omitempty"`
	PortalPQRoot *agentcrypto.JWK `json:"portal_pq_root,omitempty"`
}

// LoadFile reads a bounded bootstrap JSON file.
func LoadFile(path string) (*Bootstrap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bootstrap config: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read bootstrap config: %w", err)
	}

	return decode(data)
}

// LoadBase64 decodes a manually generated padded Base64 bootstrap document.
func LoadBase64(encoded string) (*Bootstrap, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedConfigSize {
		return nil, errors.New("encoded bootstrap config exceeds the 64 KiB decoded limit")
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("LOREVA_CONFIG_BASE64 is not valid padded base64")
	}

	return decode(data)
}

// LoadServerBootstrap decodes the exact Base64(JSON) document returned by
// the portal's Add node endpoint.
func LoadServerBootstrap(encoded string) (*Bootstrap, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedConfigSize {
		return nil, errors.New("encoded bootstrap exceeds the 64 KiB decoded limit")
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("bootstrap is not valid padded base64")
	}
	if len(data) == 0 || len(data) > maxConfigSize {
		return nil, errors.New("bootstrap must decode to between 1 byte and 64 KiB")
	}

	var document serverBootstrap
	if err := strictjson.Decode(data, &document); err != nil {
		return nil, fmt.Errorf("decode server bootstrap: %w", err)
	}

	return &Bootstrap{
		PortalURL:       document.Portal,
		EnrollmentToken: document.Token,
		PortalCA:        document.PortalCA,
		PortalPQRoot:    document.PortalPQRoot,
	}, nil
}

func decode(data []byte) (*Bootstrap, error) {
	if len(data) == 0 || len(data) > maxConfigSize {
		return nil, errors.New("bootstrap config must be between 1 byte and 64 KiB")
	}

	var config Bootstrap
	if err := strictjson.Decode(data, &config); err != nil {
		return nil, fmt.Errorf("decode bootstrap config: %w", err)
	}

	return &config, nil
}
