package config

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
)

func TestLoadBase64PreservesPortalPQRootObject(t *testing.T) {
	raw := `{"portal_url":"wss://portal.example:27460","enrollment_token":"1234567890abcdef.secret","portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"}}`
	config, err := LoadBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if config.PortalPQRoot == nil || config.PortalPQRoot.Kty != "AKP" || config.PortalPQRoot.Pub != "key" {
		t.Fatal("portal_pq_root was not decoded as an object")
	}
}

func TestLoadBase64RejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, raw := range []string{
		`{"portal_url":"a","portal_url":"b","enrollment_token":"token","portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"}}`,
		`{"portal_url":"a","enrollment_token":"token","portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"},"unknown":true}`,
	} {
		_, err := LoadBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
		if err == nil || !strings.Contains(err.Error(), "decode bootstrap config") {
			t.Fatalf("unsafe bootstrap JSON was accepted: %s", raw)
		}
	}
}

func TestLoadServerBootstrapMatchesPortalContract(t *testing.T) {
	raw := `{"portal":"wss://portal.example:27460","token":"1234567890abcdef.secret","portal_ca":"certificate","portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"}}`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	config, err := LoadServerBootstrap(encoded)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := &agentcrypto.JWK{Kty: "AKP", Alg: "ML-DSA-65", Pub: "key"}
	if config.PortalURL != "wss://portal.example:27460" || config.EnrollmentToken != "1234567890abcdef.secret" ||
		config.PortalCA != "certificate" || !reflect.DeepEqual(config.PortalPQRoot, wantRoot) {
		t.Fatalf("decoded bootstrap = %#v", config)
	}
}

func TestLoadServerBootstrapRejectsNonContractJSON(t *testing.T) {
	for _, raw := range []string{
		`{"portal_url":"wss://portal.example:27460","enrollment_token":"token"}`,
		`{"portal":"a","portal":"b","token":"token"}`,
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
