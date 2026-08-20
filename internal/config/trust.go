package config

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const (
	maxPortalPQRootSize = 8 * 1024
	maxPortalCASize     = 64 * 1024
)

// LoadPortalPQRoot reads a strict AKP JWK document from path.
func LoadPortalPQRoot(path string) (*agentcrypto.JWK, error) {
	data, err := readBoundedFile(path, "portal PQ root", maxPortalPQRootSize, "8 KiB")
	if err != nil {
		return nil, err
	}

	var root agentcrypto.JWK
	if err := strictjson.Decode(data, &root); err != nil {
		return nil, fmt.Errorf("decode portal PQ root: %w", err)
	}

	if err := agentcrypto.ValidateJWK(&root); err != nil {
		return nil, fmt.Errorf("validate portal PQ root: %w", err)
	}

	return &root, nil
}

// LoadPortalCA reads a PEM trust bundle from path.
func LoadPortalCA(path string) (string, error) {
	data, err := readBoundedFile(path, "portal CA", maxPortalCASize, "64 KiB")
	if err != nil {
		return "", err
	}

	if err := validatePortalCA(data); err != nil {
		return "", err
	}

	return string(data), nil
}

func readBoundedFile(path, description string, maximum int64, maximumLabel string) (data []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", description, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close %s: %w", description, err))
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", description, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s path must reference a regular file", description)
	}

	data, err = io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", description, err)
	}

	if len(data) == 0 || int64(len(data)) > maximum {
		return nil, fmt.Errorf("%s file must be between 1 byte and %s", description, maximumLabel)
	}

	return data, nil
}

func validatePortalCA(data []byte) error {
	rest := data
	certificates := 0

	for len(bytes.TrimSpace(rest)) > 0 {
		trimmed := bytes.TrimSpace(rest)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("portal CA must contain only PEM CERTIFICATE blocks")
		}

		block, remainder := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("portal CA contains an invalid PEM block")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("parse portal CA certificate: %w", err)
		}

		certificates++
		rest = remainder
	}

	if certificates == 0 {
		return errors.New("portal CA does not contain a certificate")
	}

	return nil
}
