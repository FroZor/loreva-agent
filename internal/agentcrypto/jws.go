package agentcrypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/FroZor/loreva-agent/internal/strictjson"
)

// MLDSAAlgorithm is the exact JOSE algorithm identifier used by the protocol.
const MLDSAAlgorithm = "ML-DSA-65"

const maxCompactJWSSize = 64 << 10

var strictRawBase64 = base64.RawURLEncoding.Strict()

// JWK is the protocol's canonical AKP representation of an ML-DSA public key.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Pub string `json:"pub"`
}

type protectedHeader struct {
	Alg string `json:"alg"`
	JWK *JWK   `json:"jwk,omitempty"`
}

type portalProtectedHeader struct {
	Alg string `json:"alg"`
}

type popClaims struct {
	Audience  string `json:"aud"`
	JTI       string `json:"jti"`
	Challenge string `json:"challenge"`
	CSRHash   string `json:"csr_sha256,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// EnrollmentPoP binds fresh identity keys and their CSR to an enrollment challenge.
func EnrollmentPoP(material *KeyMaterial, portalID, requestID, challenge string, expiresAt time.Time) (string, error) {
	csrHash := sha256.Sum256(material.CSRDER)
	return sign(material.MLDSAKey, protectedHeader{
		Alg: MLDSAAlgorithm,
		JWK: PublicJWK(material.MLDSAPub),
	}, popClaims{
		Audience:  portalID,
		JTI:       requestID,
		Challenge: challenge,
		CSRHash:   rawBase64.EncodeToString(csrHash[:]),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
}

// ConnectPoP proves possession of the enrolled ML-DSA identity.
func ConnectPoP(material *KeyMaterial, portalID, challenge string, expiresAt time.Time) (string, error) {
	requestID, err := NewUUID()
	if err != nil {
		return "", err
	}

	return sign(material.MLDSAKey, protectedHeader{Alg: MLDSAAlgorithm}, popClaims{
		Audience:  portalID,
		JTI:       requestID,
		Challenge: challenge,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
}

// RenewalPoP proves possession of the new renewal identity. requestID is
// supplied by the caller so the same JTI can be reused when a renewal request
// has to be retried. The proof is bound to the nonce of the current connect
// session and to the new ECDSA CSR.
func RenewalPoP(material *KeyMaterial, portalID, requestID, connectNonce string, expiresAt time.Time) (string, error) {
	csrHash := sha256.Sum256(material.CSRDER)
	return sign(material.MLDSAKey, protectedHeader{
		Alg: MLDSAAlgorithm,
		JWK: PublicJWK(material.MLDSAPub),
	}, popClaims{
		Audience:  portalID,
		JTI:       requestID,
		Challenge: connectNonce,
		CSRHash:   rawBase64.EncodeToString(csrHash[:]),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
}

// PublicJWK converts an ML-DSA public key to the protocol's AKP JWK form.
func PublicJWK(pub *mldsa65.PublicKey) *JWK {
	if pub == nil {
		return nil
	}

	return &JWK{Kty: "AKP", Alg: MLDSAAlgorithm, Pub: rawBase64.EncodeToString(pub.Bytes())}
}

// ValidateJWK validates the exact AKP representation used by the protocol and
// checks that pub is a canonical, unpadded Base64URL encoding of an ML-DSA-65
// public key.
func ValidateJWK(jwk *JWK) error {
	_, err := publicKeyFromJWK(jwk)
	return err
}

// JWKThumbprint returns the protocol state-binding fingerprint: unpadded
// Base64URL of SHA-256 over the decoded 1952-byte ML-DSA public key.
func JWKThumbprint(jwk *JWK) (string, error) {
	if err := ValidateJWK(jwk); err != nil {
		return "", err
	}

	raw, err := decodeCanonicalBase64URL(jwk.Pub)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(raw)

	return rawBase64.EncodeToString(sum[:]), nil
}

// PublicKeysEqual compares a JWK and ML-DSA public key in constant time.
func PublicKeysEqual(jwk *JWK, pub *mldsa65.PublicKey) bool {
	parsed, err := publicKeyFromJWK(jwk)
	if err != nil || pub == nil {
		return false
	}

	actual, err := parsed.MarshalBinary()
	if err != nil {
		return false
	}

	expected := pub.Bytes()
	if len(actual) != len(expected) {
		return false
	}

	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// VerifyCompactJWS verifies a portal artifact with the configured ML-DSA root.
// The signature is checked against the original protected-header and payload
// segments; JSON is never re-marshaled. Portal artifacts must have exactly an
// alg protected-header field and may not embed or substitute a JWK.
func VerifyCompactJWS(root *JWK, token string, target any) error {
	pub, err := publicKeyFromJWK(root)
	if err != nil {
		return fmt.Errorf("invalid portal ML-DSA root: %w", err)
	}

	headerJSON, payloadJSON, signature, signingInput, err := splitCompactJWS(token)
	if err != nil {
		return err
	}

	var header portalProtectedHeader
	if err := strictjson.Decode(headerJSON, &header); err != nil || header.Alg != MLDSAAlgorithm {
		return errors.New("invalid Compact JWS protected header")
	}
	if !mldsa65.Verify(pub, []byte(signingInput), nil, signature) {
		return errors.New("invalid Compact JWS ML-DSA signature")
	}
	if err := strictjson.Decode(payloadJSON, target); err != nil {
		return fmt.Errorf("decode Compact JWS payload: %w", err)
	}

	return nil
}

func publicKeyFromJWK(jwk *JWK) (*mldsa65.PublicKey, error) {
	if jwk == nil {
		return nil, errors.New("ML-DSA JWK is missing")
	}
	if jwk.Kty != "AKP" || jwk.Alg != MLDSAAlgorithm {
		return nil, errors.New("ML-DSA JWK must use kty AKP and alg ML-DSA-65")
	}

	raw, err := decodeCanonicalBase64URL(jwk.Pub)
	if err != nil {
		return nil, errors.New("ML-DSA JWK pub must be canonical unpadded Base64URL")
	}
	if len(raw) != mldsa65.PublicKeySize {
		return nil, fmt.Errorf("ML-DSA JWK pub is %d bytes, want %d", len(raw), mldsa65.PublicKeySize)
	}

	pub := new(mldsa65.PublicKey)
	if err := pub.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA-65 public key: %w", err)
	}

	return pub, nil
}

func splitCompactJWS(token string) (header, payload, signature []byte, signingInput string, err error) {
	if len(token) == 0 || len(token) > maxCompactJWSSize {
		return nil, nil, nil, "", errors.New("invalid Compact JWS size")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, nil, "", errors.New("invalid Compact JWS")
	}
	if header, err = decodeCanonicalBase64URL(parts[0]); err != nil {
		return nil, nil, nil, "", errors.New("invalid Compact JWS header encoding")
	}
	if payload, err = decodeCanonicalBase64URL(parts[1]); err != nil {
		return nil, nil, nil, "", errors.New("invalid Compact JWS payload encoding")
	}
	if signature, err = decodeCanonicalBase64URL(parts[2]); err != nil || len(signature) != mldsa65.SignatureSize {
		return nil, nil, nil, "", errors.New("invalid Compact JWS signature encoding")
	}

	return header, payload, signature, parts[0] + "." + parts[1], nil
}

func decodeCanonicalBase64URL(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("empty or padded Base64URL")
	}

	decoded, err := strictRawBase64.DecodeString(value)
	if err != nil || rawBase64.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical Base64URL")
	}

	return decoded, nil
}

func sign(key *mldsa65.PrivateKey, header protectedHeader, claims any) (string, error) {
	if key == nil {
		return "", errors.New("sign ML-DSA JWS: private key is missing")
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWS header: %w", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWS payload: %w", err)
	}

	signingInput := rawBase64.EncodeToString(headerJSON) + "." + rawBase64.EncodeToString(payloadJSON)
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(key, []byte(signingInput), nil, true, signature); err != nil {
		return "", fmt.Errorf("sign ML-DSA JWS: %w", err)
	}

	return signingInput + "." + rawBase64.EncodeToString(signature), nil
}
