package pairing

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/tunnel"
)

func testInvite(t *testing.T) *Invite {
	t.Helper()

	key := func(fill byte) tunnel.Key {
		var k tunnel.Key
		for index := range k {
			k[index] = fill
		}
		return k
	}

	return &Invite{
		InviteID:      "11111111-1111-4111-8111-111111111111",
		NodeID:        "22222222-2222-4222-8222-222222222222",
		NodePublicKey: key(1),
		NodeAddress:   netip.MustParseAddr("fd00:1:2:3::1"),
		Endpoints:     []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:24000"), netip.MustParseAddrPort("[2001:db8::1]:24000")},
		PrivateKey:    key(2),
		PresharedKey:  key(3),
		Address:       netip.MustParseAddr("fd00:1:2:3::abcd"),
		ExpiresAt:     time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
	}
}

func encodeDocument(t *testing.T, document string) string {
	t.Helper()

	return InvitePrefix + base64.RawURLEncoding.EncodeToString([]byte(document))
}

func TestInviteRoundTrip(t *testing.T) {
	invite := testInvite(t)

	encoded, err := invite.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !strings.HasPrefix(encoded, InvitePrefix) {
		t.Fatalf("encoded invite %q lacks prefix", encoded)
	}

	parsed, err := ParseInvite(" " + encoded + "\n")
	if err != nil {
		t.Fatalf("ParseInvite() error = %v", err)
	}
	if parsed.InviteID != invite.InviteID || parsed.NodePublicKey != invite.NodePublicKey ||
		parsed.PresharedKey != invite.PresharedKey || parsed.Address != invite.Address ||
		!parsed.ExpiresAt.Equal(invite.ExpiresAt) || len(parsed.Endpoints) != 2 || parsed.Endpoints[1] != invite.Endpoints[1] {
		t.Fatalf("ParseInvite() = %+v, want %+v", parsed, invite)
	}
}

func TestParseInviteRejectsInvalidInput(t *testing.T) {
	valid, err := testInvite(t).Encode()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(valid, InvitePrefix))
	if err != nil {
		t.Fatal(err)
	}
	document := string(payload)

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "missing prefix", encoded: strings.TrimPrefix(valid, InvitePrefix)},
		{name: "padded base64", encoded: valid + "="},
		{name: "too long", encoded: InvitePrefix + strings.Repeat("A", maxInviteSize)},
		{name: "unknown field", encoded: encodeDocument(t, strings.Replace(document, "{", `{"extra":1,`, 1))},
		{name: "case folded duplicate", encoded: encodeDocument(t, strings.Replace(document, "{", `{"V":1,`, 1))},
		{name: "wrong version", encoded: encodeDocument(t, strings.Replace(document, `"v":1`, `"v":2`, 1))},
		{name: "bad uuid", encoded: encodeDocument(t, strings.Replace(document, "11111111-1111", "nope", 1))},
		{name: "host name endpoint", encoded: encodeDocument(t, strings.Replace(document, "203.0.113.10:24000", "example.com:24000", 1))},
		{name: "zero port", encoded: encodeDocument(t, strings.Replace(document, "203.0.113.10:24000", "203.0.113.10:0", 1))},
		{name: "IPv4 tunnel address", encoded: encodeDocument(t, strings.Replace(document, "fd00:1:2:3::abcd", "10.0.0.2", 1))},
		{name: "same tunnel addresses", encoded: encodeDocument(t, strings.Replace(document, "fd00:1:2:3::abcd", "fd00:1:2:3::1", 1))},
		{name: "zero key", encoded: encodeDocument(t, strings.Replace(document, testInvite(t).PresharedKey.String(), tunnel.Key{}.String(), 1))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseInvite(test.encoded); err == nil {
				t.Fatal("ParseInvite() succeeded, want error")
			}
		})
	}
}

func TestTranscriptAgreement(t *testing.T) {
	decapsulationKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	encapsulationKey := decapsulationKey.EncapsulationKey().Bytes()

	nodeSecret, ciphertext, err := Encapsulate(encapsulationKey)
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}
	deviceSecret, err := decapsulationKey.Decapsulate(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	invite := testInvite(t)
	transcript := Transcript{
		InviteID:         invite.InviteID,
		NodeID:           invite.NodeID,
		NodePublicKey:    invite.NodePublicKey,
		DevicePublicKey:  invite.PrivateKey,
		DeviceName:       "laptop",
		DeviceAddress:    netip.MustParseAddr("fd00:1:2:3::5"),
		EncapsulationKey: encapsulationKey,
		Ciphertext:       ciphertext,
		NodeNonce:        nonce,
	}

	nodeKey, err := transcript.PresharedKey(nodeSecret, invite.PresharedKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := transcript.PresharedKey(deviceSecret, invite.PresharedKey)
	if err != nil {
		t.Fatal(err)
	}
	if nodeKey != deviceKey || nodeKey.IsZero() {
		t.Fatal("node and device derived different preshared keys")
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}$`).MatchString(transcript.SAS()) {
		t.Fatalf("SAS() = %q", transcript.SAS())
	}

	changed := transcript
	changed.DeviceName = "laptop2"
	if changed.SAS() == transcript.SAS() && changed.Hash() == transcript.Hash() {
		t.Fatal("transcript hash ignores the device name")
	}

	// Length prefixes keep field boundaries unambiguous.
	shifted := transcript
	shifted.InviteID, shifted.NodeID = transcript.InviteID+transcript.NodeID[:1], transcript.NodeID[1:]
	if shifted.Hash() == transcript.Hash() {
		t.Fatal("transcript hash is ambiguous across field boundaries")
	}

	otherKey, err := transcript.PresharedKey(nodeSecret, invite.NodePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if otherKey == nodeKey {
		t.Fatal("preshared key ignores the invite PSK")
	}
	if _, err := transcript.PresharedKey(bytes.Repeat([]byte{1}, 16), invite.PresharedKey); err == nil {
		t.Fatal("PresharedKey() accepted a short shared secret")
	}
	if _, _, err := Encapsulate([]byte("short")); err == nil {
		t.Fatal("Encapsulate() accepted an invalid key")
	}
}

func TestValidateDeviceName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{name: "Rick's laptop", valid: true},
		{name: "ноутбук", valid: true},
		{name: "", valid: false},
		{name: strings.Repeat("a", MaxDeviceNameLength+1), valid: false},
		{name: "evil\x1b[2Jname", valid: false},
		{name: "line\nbreak", valid: false},
		{name: "bad\xffutf8", valid: false},
	}

	for _, test := range tests {
		if err := ValidateDeviceName(test.name); (err == nil) != test.valid {
			t.Errorf("ValidateDeviceName(%q) error = %v, want valid %v", test.name, err, test.valid)
		}
	}
}
