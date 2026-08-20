package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
)

func TestLoadPortalPQRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal-pq-root.json")
	publicKey, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(agentcrypto.PublicJWK(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := LoadPortalPQRoot(path)
	if err != nil {
		t.Fatal(err)
	}

	if !agentcrypto.PublicKeysEqual(root, publicKey) {
		t.Fatalf("decoded portal PQ root = %#v", root)
	}
}

func TestLoadPortalPQRootRejectsAmbiguousJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal-pq-root.json")
	data := `{"kty":"AKP","alg":"ML-DSA-65","pub":"one","pub":"two"}`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPortalPQRoot(path); err == nil {
		t.Fatal("duplicate portal PQ root field was accepted")
	}
}

func TestLoadPortalPQRootRejectsInvalidKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal-pq-root.json")
	data := `{"kty":"AKP","alg":"ML-DSA-65","pub":"key"}`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPortalPQRoot(path); err == nil || !strings.Contains(err.Error(), "validate portal PQ root") {
		t.Fatalf("invalid portal PQ root error = %v", err)
	}
}

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

func TestTrustFilesEnforceSizeLimits(t *testing.T) {
	for _, test := range []struct {
		name    string
		load    func(string) error
		maximum int
	}{
		{
			name: "PQ root",
			load: func(path string) error {
				_, err := LoadPortalPQRoot(path)
				return err
			},
			maximum: maxPortalPQRootSize,
		},
		{
			name: "CA",
			load: func(path string) error {
				_, err := LoadPortalCA(path)
				return err
			},
			maximum: maxPortalCASize,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oversized")

			if err := os.WriteFile(path, []byte(strings.Repeat("x", test.maximum+1)), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := test.load(path); err == nil || !strings.Contains(err.Error(), "file must be between") {
				t.Fatalf("oversized trust file error = %v", err)
			}
		})
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
