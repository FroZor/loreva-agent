// Package certpin creates the self-signed TLS identities of nodes and
// devices and identifies them by the SHA-256 of their public key. Direct
// access never relies on certificate authorities: each side pins the other
// side's key, learned from the connection key or during pairing.
package certpin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PinSize is the length of a decoded pin.
const PinSize = sha256.Size

const (
	// certificateLifetime is long on purpose: peers pin the key, so expiry
	// adds nothing but an outage.
	certificateLifetime = 20 * 365 * 24 * time.Hour
)

// Identity is a private key and its self-signed certificate, both DER and
// standard Base64 as stored in state files.
type Identity struct {
	PrivateKey  string
	Certificate string
}

// Generate creates a new ECDSA P-256 identity. P-256 keeps the door open for
// keys held in a TPM or Secure Enclave on devices.
func Generate() (Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate TLS key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Identity{}, fmt.Errorf("generate certificate serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		// The subject is empty: anyone who connects can read the certificate,
		// and it should not name the software, the node, or its owner.
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return Identity{}, fmt.Errorf("create TLS certificate: %w", err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Identity{}, fmt.Errorf("encode TLS key: %w", err)
	}

	return Identity{
		PrivateKey:  base64.StdEncoding.EncodeToString(privateKey),
		Certificate: base64.StdEncoding.EncodeToString(certificate),
	}, nil
}

// TLSCertificate parses a stored identity and checks that the key matches
// the certificate.
func (identity Identity) TLSCertificate() (tls.Certificate, error) {
	keyDER, err := base64.StdEncoding.Strict().DecodeString(identity.PrivateKey)
	if err != nil {
		return tls.Certificate{}, errors.New("TLS private key is not standard Base64")
	}
	certificateDER, err := base64.StdEncoding.Strict().DecodeString(identity.Certificate)
	if err != nil {
		return tls.Certificate{}, errors.New("TLS certificate is not standard Base64")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse TLS private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("TLS private key cannot sign")
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse TLS certificate: %w", err)
	}
	if !publicKeysEqual(signer.Public(), leaf.PublicKey) {
		return tls.Certificate{}, errors.New("TLS private key does not match the certificate")
	}

	return tls.Certificate{Certificate: [][]byte{certificateDER}, PrivateKey: signer, Leaf: leaf}, nil
}

// Pin returns the standard Base64 SHA-256 of the identity's public key.
func (identity Identity) Pin() (string, error) {
	certificate, err := identity.TLSCertificate()
	if err != nil {
		return "", err
	}

	return Of(certificate.Leaf), nil
}

// Of returns the pin of a certificate: the standard Base64 SHA-256 of its
// SubjectPublicKeyInfo. Pinning the key, not the certificate, keeps the pin
// stable if a certificate is ever reissued for the same key.
func Of(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)

	return base64.StdEncoding.EncodeToString(sum[:])
}

// Validate checks that value is a well-formed pin.
func Validate(value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != PinSize {
		return errors.New("key pin must be the standard Base64 encoding of 32 bytes")
	}

	return nil
}

// AcceptedKey reports whether a peer certificate uses a key type that direct
// access accepts: ECDSA P-256 or Ed25519.
func AcceptedKey(certificate *x509.Certificate) bool {
	switch key := certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256()
	default:
		return certificate.PublicKeyAlgorithm == x509.Ed25519
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	comparable, ok := a.(interface{ Equal(crypto.PublicKey) bool })

	return ok && comparable.Equal(b)
}
