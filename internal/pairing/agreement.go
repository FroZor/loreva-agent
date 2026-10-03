package pairing

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode"
	"unicode/utf8"

	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const (
	transcriptLabel = "loreva.pairing.transcript.v1"
	sasLabel        = "loreva.pairing.sas.v1"
	pskLabel        = "loreva.pairing.psk.v1"
	// NonceSize is the length of the node's pairing nonce.
	NonceSize = 32
	// MaxDeviceNameLength bounds the device name shown on the node console.
	MaxDeviceNameLength = 64
	sasLength           = 8
)

// Transcript is everything both sides must agree on. The device fixes its
// keys and name before the node picks its nonce, so an attacker cannot grind
// keys to collide with the short authentication string.
type Transcript struct {
	InviteID         string
	NodeID           string
	NodePublicKey    tunnel.Key
	DevicePublicKey  tunnel.Key
	DeviceName       string
	DeviceAddress    netip.Addr
	EncapsulationKey []byte
	Ciphertext       []byte
	NodeNonce        []byte
}

// Hash returns SHA-256 over the length-prefixed transcript fields.
func (t *Transcript) Hash() [sha256.Size]byte {
	digest := sha256.New()
	address := t.DeviceAddress.As16()

	for _, field := range [][]byte{
		[]byte(transcriptLabel),
		[]byte(t.InviteID),
		[]byte(t.NodeID),
		t.NodePublicKey[:],
		t.DevicePublicKey[:],
		[]byte(t.DeviceName),
		address[:],
		t.EncapsulationKey,
		t.Ciphertext,
		t.NodeNonce,
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

// PresharedKey derives the device's WireGuard PSK from the ML-KEM shared
// secret, salted with the invite PSK and bound to the transcript. Learning
// the invite later does not reveal it, and a quantum attacker who recorded
// the pairing still has to break ML-KEM-768.
func (t *Transcript) PresharedKey(sharedSecret []byte, invitePresharedKey tunnel.Key) (tunnel.Key, error) {
	if len(sharedSecret) != mlkem.SharedKeySize {
		return tunnel.Key{}, errors.New("ML-KEM shared secret has an invalid length")
	}

	transcript := t.Hash()
	secret := append(append([]byte{}, sharedSecret...), transcript[:]...)

	derived, err := hkdf.Key(sha256.New, secret, invitePresharedKey[:], pskLabel, tunnel.KeySize)
	if err != nil {
		return tunnel.Key{}, fmt.Errorf("derive device preshared key: %w", err)
	}

	var key tunnel.Key
	copy(key[:], derived)

	return key, nil
}

// Encapsulate runs the node side of ML-KEM-768 against the device's key.
func Encapsulate(encapsulationKey []byte) (sharedSecret, ciphertext []byte, err error) {
	key, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ML-KEM-768 encapsulation key: %w", err)
	}

	sharedSecret, ciphertext = key.Encapsulate()

	return sharedSecret, ciphertext, nil
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
