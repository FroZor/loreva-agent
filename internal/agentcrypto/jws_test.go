package agentcrypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestEnrollmentPoPMatchesServerContract(t *testing.T) {
	material, err := Generate("node.example")
	if err != nil {
		t.Fatal(err)
	}

	portalID := mustUUID(t)
	requestID := mustUUID(t)

	proof, err := EnrollmentPoP(material, portalID, requestID, "challenge", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("Compact JWS has %d segments", len(parts))
	}

	headerBytes := mustDecodeBase64URL(t, parts[0])
	payloadBytes := mustDecodeBase64URL(t, parts[1])
	signature := mustDecodeBase64URL(t, parts[2])

	if len(signature) != mldsa65.SignatureSize {
		t.Fatalf("signature is %d bytes", len(signature))
	}
	var header protectedHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != MLDSAAlgorithm || !PublicKeysEqual(header.JWK, material.MLDSAPub) {
		t.Fatal("protected header does not contain the ML-DSA-65 public key")
	}
	if !mldsa65.Verify(material.MLDSAPub, []byte(parts[0]+"."+parts[1]), nil, signature) {
		t.Fatal("ML-DSA signature does not verify")
	}
	var claims popClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(material.CSRDER)
	if claims.Audience != portalID || claims.JTI != requestID || claims.CSRHash != rawBase64.EncodeToString(hash[:]) {
		t.Fatal("PoP claims do not bind the portal, request and CSR")
	}
}

func TestMaterialRoundTrip(t *testing.T) {
	material, err := Generate("node.example")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := material.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Restore(privateKey, material.CSRPEM, material.SeedBase64())
	if err != nil {
		t.Fatal(err)
	}
	if !restored.ECDSAKey.Equal(material.ECDSAKey) || !PublicKeysEqual(PublicJWK(restored.MLDSAPub), material.MLDSAPub) {
		t.Fatal("restored keys differ from generated keys")
	}
}

func TestValidateJWKRejectsNonCanonicalOrWrongKeys(t *testing.T) {
	material, err := Generate("node.example")
	if err != nil {
		t.Fatal(err)
	}
	valid := PublicJWK(material.MLDSAPub)
	if err := ValidateJWK(valid); err != nil {
		t.Fatalf("valid JWK rejected: %v", err)
	}
	thumbprint, err := JWKThumbprint(valid)
	if err != nil {
		t.Fatalf("thumbprint valid JWK: %v", err)
	}
	rawPublicKey := mustDecodeBase64URL(t, valid.Pub)
	expectedThumbprint := sha256.Sum256(rawPublicKey)
	if thumbprint != rawBase64.EncodeToString(expectedThumbprint[:]) {
		t.Fatal("JWK thumbprint does not hash the decoded public key")
	}

	tests := []struct {
		name string
		jwk  *JWK
	}{
		{name: "missing", jwk: nil},
		{name: "wrong kty", jwk: &JWK{Kty: "OKP", Alg: valid.Alg, Pub: valid.Pub}},
		{name: "wrong alg", jwk: &JWK{Kty: valid.Kty, Alg: "ML-DSA-44", Pub: valid.Pub}},
		{name: "padded", jwk: &JWK{Kty: valid.Kty, Alg: valid.Alg, Pub: valid.Pub + "="}},
		{name: "standard base64 alphabet", jwk: &JWK{Kty: valid.Kty, Alg: valid.Alg, Pub: "+" + valid.Pub[1:]}},
		{name: "wrong size", jwk: &JWK{Kty: valid.Kty, Alg: valid.Alg, Pub: rawBase64.EncodeToString(make([]byte, mldsa65.PublicKeySize-1))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateJWK(test.jwk); err == nil {
				t.Fatal("invalid JWK accepted")
			}
			if _, err := JWKThumbprint(test.jwk); err == nil {
				t.Fatal("invalid JWK thumbprint accepted")
			}
		})
	}
}

func TestVerifyCompactJWSUsesOriginalSegments(t *testing.T) {
	root, err := Generate("portal.example")
	if err != nil {
		t.Fatal(err)
	}
	header := []byte(`{ "alg" : "ML-DSA-65" }`)
	payload := []byte(`{ "value" : "kept-byte-for-byte" }`)
	token := signedTestJWS(t, root.MLDSAKey, header, payload)

	var got struct {
		Value string `json:"value"`
	}
	if err := VerifyCompactJWS(PublicJWK(root.MLDSAPub), token, &got); err != nil {
		t.Fatalf("valid portal JWS rejected: %v", err)
	}
	if got.Value != "kept-byte-for-byte" {
		t.Fatalf("decoded value = %q", got.Value)
	}

	parts := strings.Split(token, ".")
	parts[1] = rawBase64.EncodeToString([]byte(`{"value":"changed"}`))
	if err := VerifyCompactJWS(PublicJWK(root.MLDSAPub), strings.Join(parts, "."), &got); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestVerifyCompactJWSRejectsHeaderKeySubstitutionAndAmbiguousJSON(t *testing.T) {
	root, err := Generate("portal.example")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"value":"ok"}`)
	tests := []struct {
		name    string
		header  []byte
		payload []byte
	}{
		{name: "embedded jwk", header: []byte(`{"alg":"ML-DSA-65","jwk":null}`), payload: payload},
		{name: "unknown header", header: []byte(`{"alg":"ML-DSA-65","typ":"JWT"}`), payload: payload},
		{name: "duplicate alg", header: []byte(`{"alg":"ML-DSA-65","alg":"ML-DSA-65"}`), payload: payload},
		{name: "duplicate payload", header: []byte(`{"alg":"ML-DSA-65"}`), payload: []byte(`{"value":"first","value":"second"}`)},
		{name: "unknown payload", header: []byte(`{"alg":"ML-DSA-65"}`), payload: []byte(`{"value":"ok","extra":true}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signedTestJWS(t, root.MLDSAKey, test.header, test.payload)
			var target struct {
				Value string `json:"value"`
			}
			if err := VerifyCompactJWS(PublicJWK(root.MLDSAPub), token, &target); err == nil {
				t.Fatal("ambiguous or extensible portal JWS accepted")
			}
		})
	}
}

func TestVerifyCompactJWSRejectsNonCanonicalSegments(t *testing.T) {
	root, err := Generate("portal.example")
	if err != nil {
		t.Fatal(err)
	}
	token := signedTestJWS(t, root.MLDSAKey, []byte(`{"alg":"ML-DSA-65"}`), []byte(`{"value":"ok"}`))
	parts := strings.Split(token, ".")
	parts[0] += "="
	var target struct {
		Value string `json:"value"`
	}
	if err := VerifyCompactJWS(PublicJWK(root.MLDSAPub), strings.Join(parts, "."), &target); err == nil {
		t.Fatal("padded protected-header segment accepted")
	}
}

func TestRenewalPoPBindsNewKeysCSRAndSession(t *testing.T) {
	material, err := Generate("node.example")
	if err != nil {
		t.Fatal(err)
	}

	portalID := mustUUID(t)
	requestID := mustUUID(t)

	expiresAt := time.Now().Add(30 * time.Second)
	proof, err := RenewalPoP(material, portalID, requestID, "connect-session-nonce", expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("Compact JWS has %d segments", len(parts))
	}

	headerJSON := mustDecodeBase64URL(t, parts[0])
	payloadJSON := mustDecodeBase64URL(t, parts[1])
	signature := mustDecodeBase64URL(t, parts[2])

	if !mldsa65.Verify(material.MLDSAPub, []byte(parts[0]+"."+parts[1]), nil, signature) {
		t.Fatal("renewal PoP signature does not verify")
	}
	var header protectedHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != MLDSAAlgorithm || !PublicKeysEqual(header.JWK, material.MLDSAPub) {
		t.Fatal("renewal protected header does not contain the new ML-DSA key")
	}
	var claims popClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatal(err)
	}
	csrHash := sha256.Sum256(material.CSRDER)
	if claims.Audience != portalID || claims.JTI != requestID || claims.Challenge != "connect-session-nonce" ||
		claims.CSRHash != rawBase64.EncodeToString(csrHash[:]) || claims.ExpiresAt != expiresAt.Unix() {
		t.Fatalf("renewal claims do not match the contract: %+v", claims)
	}
}

func signedTestJWS(t *testing.T, key *mldsa65.PrivateKey, headerJSON, payloadJSON []byte) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(key, []byte(signingInput), nil, true, signature); err != nil {
		t.Fatal(err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mustUUID(t *testing.T) string {
	t.Helper()

	value, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}

	return value
}

func mustDecodeBase64URL(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := rawBase64.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}
