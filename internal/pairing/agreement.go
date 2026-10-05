package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	transcriptLabel = "loreva.pairing.transcript.v2"
	sasLabel        = "loreva.pairing.sas.v2"
	// ExporterLabel is the TLS exporter label (RFC 8446 §7.5) that binds the
	// transcript to the TLS connection the pairing runs on.
	ExporterLabel = "EXPORTER-loreva-pairing-v2"
	// ExporterSize is the length of the exported keying material.
	ExporterSize = 32
	// NonceSize is the length of the node's pairing nonce.
	NonceSize = 32
	// MaxDeviceNameLength bounds the device name shown on the node console.
	MaxDeviceNameLength = 64
	sasLength           = 8
)

// Transcript is everything both sides must agree on. The device fixes its
// key and name before the node picks its nonce, so an attacker cannot grind
// keys to collide with the short authentication string. The TLS exporter
// ties the code to this very connection: a relay that terminates TLS on
// either side ends up with different exporter values and a different code.
type Transcript struct {
	InviteID   string
	NodeID     string
	NodePin    string
	DevicePin  string
	DeviceName string
	NodeNonce  []byte
	Exporter   []byte
}

// Hash returns SHA-256 over the length-prefixed transcript fields.
func (t *Transcript) Hash() [sha256.Size]byte {
	digest := sha256.New()

	for _, field := range [][]byte{
		[]byte(transcriptLabel),
		[]byte(t.InviteID),
		[]byte(t.NodeID),
		[]byte(t.NodePin),
		[]byte(t.DevicePin),
		[]byte(t.DeviceName),
		t.NodeNonce,
		t.Exporter,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		digest.Write(length[:])
		digest.Write(field)
	}

	var sum [sha256.Size]byte
	copy(sum[:], digest.Sum(nil))

	return sum
}

// SAS returns the short authentication string the user compares on the node
// and on the device, formatted as XXXX-XXXX (40 bits).
func (t *Transcript) SAS() string {
	transcript := t.Hash()
	sum := sha256.Sum256(append([]byte(sasLabel), transcript[:]...))
	encoded := base32.StdEncoding.EncodeToString(sum[:])[:sasLength]

	return encoded[:sasLength/2] + "-" + encoded[sasLength/2:]
}

// NewNonce returns a fresh node nonce.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate pairing nonce: %w", err)
	}

	return nonce, nil
}

// ValidateDeviceName accepts short printable names. Control characters and
// terminal escape sequences are rejected because the node prints the name.
func ValidateDeviceName(name string) error {
	length := utf8.RuneCountInString(name)
	if !utf8.ValidString(name) || length == 0 || length > MaxDeviceNameLength {
		return fmt.Errorf("device name must be 1 to %d characters of valid UTF-8", MaxDeviceNameLength)
	}

	for _, r := range name {
		if !unicode.IsPrint(r) {
			return errors.New("device name must contain only printable characters")
		}
	}

	return nil
}
