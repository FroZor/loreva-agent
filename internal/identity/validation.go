// Package identity validates identities issued by the portal.
package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
)

type pqCredentialClaims struct {
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	Confirmation struct {
		JWK *agentcrypto.JWK `json:"jwk"`
	} `json:"cnf"`
}

// ValidateIssued verifies that portal-issued certificates and the PQ
// credential are bound to the expected portal, node, and local key material.
func ValidateIssued(
	root *agentcrypto.JWK,
	portalID string,
	nodeID string,
	material *agentcrypto.KeyMaterial,
	certificateChain []string,
	credentialJWS string,
	renewAfter time.Time,
) error {
	if material == nil {
		return errors.New("local identity material is required")
	}

	leaf, err := validateCertificateChain(certificateChain, material.ECDSAKey, nodeID)
	if err != nil {
		return err
	}

	return validatePQCredential(root, portalID, nodeID, material, credentialJWS, renewAfter, leaf)
}

// ValidateRenewal verifies a renewal response and builds the replacement
// identity without persisting it.
func ValidateRenewal(
	current *state.Identity,
	pending *state.PendingRenewal,
	material *agentcrypto.KeyMaterial,
	accepted protocol.RenewAccepted,
) (*state.Identity, error) {
	if current == nil || pending == nil || material == nil || accepted.Type != protocol.RenewAcceptedType {
		return nil, errors.New("portal returned an invalid renewal identity")
	}
	if !sameCertificateRoot(current.CertificateChain, accepted.CertificateChain) {
		return nil, errors.New("renewed certificate chain has an unexpected portal root")
	}

	if err := ValidateIssued(
		&current.PortalPQRoot,
		current.PortalID,
		current.NodeID,
		material,
		accepted.CertificateChain,
		accepted.PQCredential,
		accepted.RenewAfter,
	); err != nil {
		return nil, err
	}

	replacement := *current
	replacement.ECDSAPrivateKey = pending.ECDSAPrivateKey
	replacement.CertificateChain = append([]string(nil), accepted.CertificateChain...)
	replacement.MLDSASeed = pending.MLDSASeed
	replacement.PQCredential = accepted.PQCredential
	replacement.RenewAfter = accepted.RenewAfter

	return &replacement, nil
}

func sameCertificateRoot(current, replacement []string) bool {
	if len(current) == 0 || len(replacement) == 0 {
		return false
	}

	currentBlock, currentRest := pem.Decode([]byte(current[len(current)-1]))
	replacementBlock, replacementRest := pem.Decode([]byte(replacement[len(replacement)-1]))

	return currentBlock != nil && replacementBlock != nil &&
		currentBlock.Type == "CERTIFICATE" && replacementBlock.Type == "CERTIFICATE" &&
		len(strings.TrimSpace(string(currentRest))) == 0 &&
		len(strings.TrimSpace(string(replacementRest))) == 0 &&
		bytes.Equal(currentBlock.Bytes, replacementBlock.Bytes)
}

func validatePQCredential(
	root *agentcrypto.JWK,
	portalID string,
	nodeID string,
	material *agentcrypto.KeyMaterial,
	credentialJWS string,
	renewAfter time.Time,
	leaf *x509.Certificate,
) error {
	now := time.Now()

	if leaf == nil || renewAfter.IsZero() || !renewAfter.After(now) || !renewAfter.Before(leaf.NotAfter) {
		return errors.New("portal returned an invalid renew_after value")
	}

	var credential pqCredentialClaims
	if err := agentcrypto.VerifyCompactJWS(root, credentialJWS, &credential); err != nil {
		return fmt.Errorf("verify pq_credential: %w", err)
	}

	if credential.Issuer != portalID || credential.Subject != nodeID ||
		credential.IssuedAt <= 0 || credential.IssuedAt > now.Add(30*time.Second).Unix() ||
		credential.ExpiresAt <= now.Unix() || credential.ExpiresAt != leaf.NotAfter.Unix() ||
		!agentcrypto.PublicKeysEqual(credential.Confirmation.JWK, material.MLDSAPub) {
		return errors.New("pq_credential is not bound to this portal, node, and ML-DSA key")
	}

	return nil
}

func validateCertificateChain(chain []string, key *ecdsa.PrivateKey, nodeID string) (*x509.Certificate, error) {
	if len(chain) < 2 || len(chain) > 8 {
		return nil, errors.New("certificate_chain must contain leaf and root certificates")
	}

	certificates := make([]*x509.Certificate, 0, len(chain))

	for _, value := range chain {
		certificate, err := parseCertificate(value)
		if err != nil {
			return nil, err
		}

		certificates = append(certificates, certificate)
	}

	leaf := certificates[0]
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return nil, errors.New("issued certificate does not match the local ECDSA key")
	}
	if !certificateHasNodeID(leaf, nodeID) {
		return nil, errors.New("issued certificate does not contain the accepted node_id")
	}

	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])

	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1 : len(certificates)-1] {
		intermediates.AddCert(certificate)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("verify issued certificate chain: %w", err)
	}

	return leaf, nil
}

func parseCertificate(value string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("certificate_chain contains invalid PEM")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate_chain: %w", err)
	}

	return certificate, nil
}

func certificateHasNodeID(certificate *x509.Certificate, nodeID string) bool {
	for _, candidate := range certificate.URIs {
		if candidate.Scheme == "loreva" && candidate.Host == "node" && strings.TrimPrefix(candidate.Path, "/") == nodeID {
			return true
		}
	}

	return certificate.Subject.CommonName == nodeID
}
