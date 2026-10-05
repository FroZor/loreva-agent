package pairing

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testPin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func testInvite(t *testing.T) *Invite {
	t.Helper()

	return &Invite{
		InviteID:  "11111111-1111-4111-8111-111111111111",
		NodeID:    "22222222-2222-4222-8222-222222222222",
		NodePin:   testPin,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:24000"), netip.MustParseAddrPort("[2001:db8::1]:24000")},
		Token:     bytes.Repeat([]byte{7}, TokenSize),
		ExpiresAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
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
	if parsed.InviteID != invite.InviteID || parsed.NodePin != invite.NodePin || !TokenEqual(parsed.Token, invite.Token) ||
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
	token := EncodeToken(testInvite(t).Token)

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "missing prefix", encoded: strings.TrimPrefix(valid, InvitePrefix)},
		{name: "padded base64", encoded: valid + "="},
		{name: "too long", encoded: InvitePrefix + strings.Repeat("A", maxInviteSize)},
		{name: "unknown field", encoded: encodeDocument(t, strings.Replace(document, "{", `{"extra":1,`, 1))},
		{name: "case folded duplicate", encoded: encodeDocument(t, strings.Replace(document, "{", `{"V":2,`, 1))},
		{name: "old version", encoded: encodeDocument(t, strings.Replace(document, `"v":2`, `"v":1`, 1))},
		{name: "bad uuid", encoded: encodeDocument(t, strings.Replace(document, "11111111-1111", "nope", 1))},
		{name: "host name endpoint", encoded: encodeDocument(t, strings.Replace(document, "203.0.113.10:24000", "example.com:24000", 1))},
		{name: "zero port", encoded: encodeDocument(t, strings.Replace(document, "203.0.113.10:24000", "203.0.113.10:0", 1))},
		{name: "short pin", encoded: encodeDocument(t, strings.Replace(document, testPin, "AAEC", 1))},
		{name: "short token", encoded: encodeDocument(t, strings.Replace(document, token, token[:10], 1))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseInvite(test.encoded); err == nil {
				t.Fatal("ParseInvite() succeeded, want error")
			}
		})
	}
}

func TestTranscriptBindsEveryField(t *testing.T) {
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	transcript := Transcript{
		InviteID:   "11111111-1111-4111-8111-111111111111",
		NodeID:     "22222222-2222-4222-8222-222222222222",
		NodePin:    testPin,
		DevicePin:  strings.Replace(testPin, "AAEC", "BBEC", 1),
		DeviceName: "laptop",
		NodeNonce:  nonce,
		Exporter:   bytes.Repeat([]byte{9}, ExporterSize),
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}$`).MatchString(transcript.SAS()) {
		t.Fatalf("SAS() = %q", transcript.SAS())
	}

	for name, mutate := range map[string]func(*Transcript){
		"device name": func(c *Transcript) { c.DeviceName = "laptop2" },
		"device pin":  func(c *Transcript) { c.DevicePin = testPin },
		"exporter":    func(c *Transcript) { c.Exporter = bytes.Repeat([]byte{8}, ExporterSize) },
		"nonce":       func(c *Transcript) { c.NodeNonce = bytes.Repeat([]byte{1}, NonceSize) },
	} {
		changed := transcript
		mutate(&changed)
		if changed.Hash() == transcript.Hash() {
			t.Errorf("transcript hash ignores the %s", name)
		}
	}

	// Length prefixes keep field boundaries unambiguous.
	shifted := transcript
	shifted.InviteID, shifted.NodeID = transcript.InviteID+transcript.NodeID[:1], transcript.NodeID[1:]
	if shifted.Hash() == transcript.Hash() {
		t.Fatal("transcript hash is ambiguous across field boundaries")
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
