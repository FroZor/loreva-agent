package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPortalCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal-ca.pem")
	data := testCertificatePEM(t)

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	certificate, err := LoadPortalCA(path)
	if err != nil {
		t.Fatal(err)
	}

	if certificate != data {
		t.Fatalf("loaded portal CA = %q", certificate)
	}
}

func TestLoadPortalCARejectsNonCertificateData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal-ca.pem")

	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPortalCA(path); err == nil {
		t.Fatal("non-certificate portal CA was accepted")
	}
}

func TestLoadPortalCAEnforcesSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized")

	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxPortalCASize+1)), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPortalCA(path); err == nil || !strings.Contains(err.Error(), "file must be between") {
		t.Fatalf("oversized portal CA error = %v", err)
	}
}

func TestReadBoundedFileBoundariesAndType(t *testing.T) {
	directory := t.TempDir()

	if _, err := readBoundedFile(directory, "test", 16, "16 bytes"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readBoundedFile(empty, "test", 16, "16 bytes"); err == nil {
		t.Fatal("empty file was accepted")
	}

	exact := filepath.Join(t.TempDir(), "exact")
	if err := os.WriteFile(exact, []byte(strings.Repeat("x", 16)), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readBoundedFile(exact, "test", 16, "16 bytes"); err != nil {
		t.Fatalf("exact-size file was rejected: %v", err)
	}
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "portal.test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"portal.test"},
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
}
