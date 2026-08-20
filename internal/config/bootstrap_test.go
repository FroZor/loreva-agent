package config

import (
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestLoadBase64MatchesManualBootstrapContract(t *testing.T) {
	raw := `{"portal_url":"wss://portal.example:27460","enrollment_token":"1234567890abcdef.secret"}`
	config, err := LoadBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if config.PortalURL != "wss://portal.example:27460" || config.EnrollmentToken != "1234567890abcdef.secret" {
		t.Fatalf("decoded bootstrap = %#v", config)
	}
}

func TestLoadBase64RejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, raw := range []string{
		`{"portal_url":"a","portal_url":"b","enrollment_token":"token"}`,
		`{"portal_url":"a","enrollment_token":"token","portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"}}`,
		`{"portal_url":"a","enrollment_token":"token","unknown":true}`,
	} {
		_, err := LoadBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
		if err == nil || !strings.Contains(err.Error(), "decode bootstrap config") {
			t.Fatalf("unsafe bootstrap JSON was accepted: %s", raw)
		}
	}
}

func TestLoadServerBootstrapMatchesPortalContract(t *testing.T) {
	raw := `{"portal":"wss://portal.example:27460","token":"1234567890abcdef.secret","portal_ca":"certificate"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	config, err := LoadServerBootstrap(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if config.PortalURL != "wss://portal.example:27460" || config.EnrollmentToken != "1234567890abcdef.secret" ||
		config.PortalCA != "certificate" {
		t.Fatalf("decoded bootstrap = %#v", config)
	}
}

func TestLoadServerBootstrapRejectsNonContractJSON(t *testing.T) {
	for _, raw := range []string{
		`{"portal_url":"wss://portal.example:27460","enrollment_token":"token"}`,
		`{"portal":"a","portal":"b","token":"token"}`,
		`{"portal":"a","token":"token","portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"}}`,
		`{"portal":"a","token":"token","unknown":true}`,
	} {
		_, err := LoadServerBootstrap(base64.StdEncoding.EncodeToString([]byte(raw)))
		if err == nil || !strings.Contains(err.Error(), "decode server bootstrap") {
			t.Fatalf("non-contract bootstrap was accepted: %s", raw)
		}
	}
	if _, err := LoadServerBootstrap(base64.RawStdEncoding.EncodeToString([]byte(`{"portal":"a","token":"b"}`))); err == nil {
		t.Fatal("unpadded base64 bootstrap was accepted")
	}
}

func TestLoadServerBootstrapReader(t *testing.T) {
	raw := `{"portal":"wss://portal.example:27460","token":"1234567890abcdef.secret"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	for _, input := range []string{encoded, encoded + "\n", encoded + "\r\n"} {
		config, err := LoadServerBootstrapReader(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if config.PortalURL != "wss://portal.example:27460" || config.EnrollmentToken != "1234567890abcdef.secret" {
			t.Fatalf("decoded bootstrap = %#v", config)
		}
	}
}

func TestLoadServerBootstrapReaderRejectsExtraInput(t *testing.T) {
	raw := `{"portal":"wss://portal.example:27460","token":"1234567890abcdef.secret"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	for _, input := range []string{"", encoded + "\n\n", " " + encoded} {
		if _, err := LoadServerBootstrapReader(strings.NewReader(input)); err == nil {
			t.Fatalf("unsafe bootstrap input was accepted: %q", input)
		}
	}

	nonCanonical := encoded[:len(encoded)/2] + "\n" + encoded[len(encoded)/2:]
	if _, err := LoadServerBootstrapReader(strings.NewReader(nonCanonical)); err == nil {
		t.Fatal("non-canonical Base64 bootstrap was accepted")
	}
}

func TestLoadServerBootstrapReaderReturnsReadError(t *testing.T) {
	wantErr := errors.New("read failure")
	reader := io.MultiReader(strings.NewReader("prefix"), errorReader{err: wantErr})

	_, err := LoadServerBootstrapReader(reader)
	if !errors.Is(err, wantErr) {
		t.Fatalf("LoadServerBootstrapReader() error = %v, want %v", err, wantErr)
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
