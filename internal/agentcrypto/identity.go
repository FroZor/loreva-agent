// Package agentcrypto manages agent keys and protocol proofs of possession.
package agentcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var rawBase64 = base64.RawURLEncoding

// KeyMaterial contains one agent's classical and post-quantum private identity.
type KeyMaterial struct {
	ECDSAKey  *ecdsa.PrivateKey
	CSRDER    []byte
	CSRPEM    string
	MLDSAPub  *mldsa65.PublicKey
	MLDSAKey  *mldsa65.PrivateKey
	MLDSASeed [mldsa65.SeedSize]byte
}

// Generate creates fresh ECDSA P-256 and ML-DSA-65 identity material.
func Generate(hostname string) (*KeyMaterial, error) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA P-256 key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}, ecdsaKey)
	if err != nil {
		return nil, fmt.Errorf("create ECDSA CSR: %w", err)
	}

	var seed [mldsa65.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, fmt.Errorf("generate ML-DSA seed: %w", err)
	}

	pub, key := mldsa65.NewKeyFromSeed(&seed)

	return &KeyMaterial{
		ECDSAKey:  ecdsaKey,
		CSRDER:    csrDER,
		CSRPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		MLDSAPub:  pub,
		MLDSAKey:  key,
		MLDSASeed: seed,
	}, nil
}

// Restore rebuilds and cross-checks persisted keys and their CSR.
func Restore(privateKeyPEM, csrPEM, seedEncoded string) (*KeyMaterial, error) {
	material, err := RestoreKeys(privateKeyPEM, seedEncoded)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("restore identity: invalid PEM PKCS#10 CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("restore identity: invalid CSR signature")
	}

	csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !csrPub.Equal(&material.ECDSAKey.PublicKey) {
		return nil, errors.New("restore identity: CSR does not match ECDSA key")
	}

	material.CSRDER = block.Bytes
	material.CSRPEM = csrPEM

	return material, nil
}

// RestoreKeys rebuilds persisted keys without requiring a CSR.
func RestoreKeys(privateKeyPEM, seedEncoded string) (*KeyMaterial, error) {
	ecdsaKey, err := parseECDSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	seedBytes, err := rawBase64.DecodeString(seedEncoded)
	if err != nil || len(seedBytes) != mldsa65.SeedSize {
		return nil, errors.New("restore identity: invalid ML-DSA seed")
	}

	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)

	pub, key := mldsa65.NewKeyFromSeed(&seed)

	return &KeyMaterial{
		ECDSAKey:  ecdsaKey,
		MLDSAPub:  pub,
		MLDSAKey:  key,
		MLDSASeed: seed,
	}, nil
}

// PrivateKeyPEM encodes the ECDSA key as PKCS#8 PEM.
func (m *KeyMaterial) PrivateKeyPEM() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(m.ECDSAKey)
	if err != nil {
		return "", fmt.Errorf("marshal ECDSA private key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// SeedBase64 encodes the ML-DSA seed as unpadded Base64URL.
func (m *KeyMaterial) SeedBase64() string {
	return rawBase64.EncodeToString(m.MLDSASeed[:])
}

func parseECDSAPrivateKey(value string) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("restore identity: invalid PKCS#8 private key PEM")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("restore identity: parse PKCS#8 key: %w", err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("restore identity: private key is not ECDSA P-256")
	}

	return key, nil
}

// NewUUID returns a cryptographically random RFC 4122 version 4 UUID.
func NewUUID() (string, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}

	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80

	encoded := hex.EncodeToString(id[:])

	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

// ValidUUID reports whether value has the canonical UUID text shape.
func ValidUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}

	raw := strings.ReplaceAll(value, "-", "")
	_, err := hex.DecodeString(raw)

	return err == nil
}
