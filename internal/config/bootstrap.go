// Package config loads bounded bootstrap and portal trust configuration.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const (
	maxConfigSize        = 64 * 1024
	maxEncodedConfigSize = ((maxConfigSize + 2) / 3) * 4
)

// Bootstrap contains the mandatory inputs needed for first enrollment.
type Bootstrap struct {
	PortalURL          string `json:"portal_url"`
	EnrollmentToken    string `json:"enrollment_token"`
	PortalCA           string `json:"portal_ca,omitempty"`
	StateDir           string `json:"state_dir,omitempty"`
	AllowDevelopmentWS bool   `json:"allow_development_ws,omitempty"`
}

type serverBootstrap struct {
	Portal   string `json:"portal"`
	Token    string `json:"token"`
	PortalCA string `json:"portal_ca,omitempty"`
}

// LoadFile reads a bounded bootstrap JSON file.
func LoadFile(path string) (bootstrap *Bootstrap, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bootstrap config: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close bootstrap config: %w", err))
		}
	}()

	return LoadReader(file)
}

// LoadReader reads one bounded manual bootstrap JSON document from reader.
func LoadReader(reader io.Reader) (*Bootstrap, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxConfigSize+1))
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
	if base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, errors.New("LOREVA_CONFIG_BASE64 is not canonical padded base64")
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
	if base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, errors.New("bootstrap is not canonical padded base64")
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
	}, nil
}

// LoadServerBootstrapReader reads one bounded Base64 bootstrap line from reader.
func LoadServerBootstrapReader(reader io.Reader) (*Bootstrap, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxEncodedConfigSize+3))
	if err != nil {
		return nil, fmt.Errorf("read server bootstrap: %w", err)
	}

	data = trimLineEnding(data)
	if len(data) > maxEncodedConfigSize {
		return nil, errors.New("encoded bootstrap exceeds the 64 KiB decoded limit")
	}

	return LoadServerBootstrap(string(data))
}

func trimLineEnding(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	if len(data) > 0 && data[len(data)-1] == '\r' {
		data = data[:len(data)-1]
	}

	return data
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
