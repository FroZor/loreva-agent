// Package tunnel runs a userspace WireGuard interface backed by an in-process
// TCP/IP stack, so the agent needs no system interface, route, or firewall rule.
package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeySize is the length of WireGuard Curve25519 keys and preshared keys.
const KeySize = 32

// Key is a WireGuard private, public, or preshared key.
type Key [KeySize]byte

// GenerateKey returns a new random key. Private keys are clamped by
// WireGuard when they are installed.
func GenerateKey() (Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return Key{}, fmt.Errorf("generate WireGuard key: %w", err)
	}

	return key, nil
}

// ParseKey decodes the standard Base64 form used by WireGuard tools.
func ParseKey(encoded string) (Key, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != KeySize {
		return Key{}, errors.New("WireGuard key must be 32 bytes in standard Base64")
	}

	var key Key
	copy(key[:], decoded)

	return key, nil
}

// PublicKey derives the Curve25519 public key of a private key.
func (k Key) PublicKey() (Key, error) {
	private, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return Key{}, fmt.Errorf("derive WireGuard public key: %w", err)
	}

	var public Key
	copy(public[:], private.PublicKey().Bytes())

	return public, nil
}

// IsZero reports whether every byte of the key is zero.
func (k Key) IsZero() bool {
	return k == Key{}
}

// String returns the standard Base64 encoding of the key.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) hex() string {
	return hex.EncodeToString(k[:])
}
