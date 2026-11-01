package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
)

const testNodeID = "6f1c2d3e-4b5a-4c6d-8e7f-901a2b3c4d5e"

type testCA struct {
	key         *ecdsa.PrivateKey
	certificate *x509.Certificate
	pem         string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test portal root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return &testCA{key: key, certificate: certificate, pem: encodeCertificate(der)}
}

// issue signs a leaf for key; mutate adjusts the template before signing.
func (ca *testCA) issue(t *testing.T, key *ecdsa.PrivateKey, mutate func(*x509.Certificate)) string {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "agent"},
		URIs:         []*url.URL{{Scheme: "loreva", Host: "node", Path: "/" + testNodeID}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	return encodeCertificate(der)
}

func encodeCertificate(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestValidateCertificateChainAcceptsBoundLeaf(t *testing.T) {
	ca := newTestCA(t)
	key := newTestKey(t)

	leaf, err := validateCertificateChain([]string{ca.issue(t, key, nil), ca.pem}, key, testNodeID)
	if err != nil {
		t.Fatalf("validateCertificateChain() error = %v", err)
	}
	if leaf == nil {
		t.Fatal("validateCertificateChain() returned no leaf")
	}
}

func TestValidateCertificateChainRejects(t *testing.T) {
	ca := newTestCA(t)
	otherCA := newTestCA(t)
	key := newTestKey(t)

	tests := []struct {
		name  string
		chain []string
		key   *ecdsa.PrivateKey
		want  string
	}{
		{name: "leaf only", chain: []string{ca.issue(t, key, nil)}, key: key, want: "leaf and root"},
		{name: "too long", chain: make([]string, 9), key: key, want: "leaf and root"},
		{name: "invalid PEM", chain: []string{"not pem", ca.pem}, key: key, want: "invalid PEM"},
		{name: "trailing data", chain: []string{ca.issue(t, key, nil) + "extra", ca.pem}, key: key, want: "invalid PEM"},
		{name: "other key", chain: []string{ca.issue(t, key, nil), ca.pem}, key: newTestKey(t), want: "local ECDSA key"},
		{
			name: "other node",
			chain: []string{ca.issue(t, key, func(template *x509.Certificate) {
				template.URIs = []*url.URL{{Scheme: "loreva", Host: "node", Path: "/other"}}
			}), ca.pem},
			key:  key,
			want: "node_id",
		},
		{name: "untrusted root", chain: []string{ca.issue(t, key, nil), otherCA.pem}, key: key, want: "verify issued certificate chain"},
		{
			name: "server usage only",
			chain: []string{ca.issue(t, key, func(template *x509.Certificate) {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}), ca.pem},
			key:  key,
			want: "verify issued certificate chain",
		},
		{
			name: "expired",
			chain: []string{ca.issue(t, key, func(template *x509.Certificate) {
				template.NotAfter = time.Now().Add(-time.Minute)
			}), ca.pem},
			key:  key,
			want: "verify issued certificate chain",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateCertificateChain(test.chain, test.key, testNodeID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateCertificateChain() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCertificateHasNodeIDFallsBackToCommonName(t *testing.T) {
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: testNodeID}}
	if !certificateHasNodeID(certificate, testNodeID) {
		t.Fatal("common name holding the node_id was not accepted")
	}
	if certificateHasNodeID(&x509.Certificate{}, testNodeID) {
		t.Fatal("certificate without the node_id was accepted")
	}
}

func TestValidatePQCredentialRejectsRenewAfterOutsideLeaf(t *testing.T) {
	leaf := &x509.Certificate{NotAfter: time.Now().Add(time.Hour)}

	for name, renewAfter := range map[string]time.Time{
		"zero":           {},
		"past":           time.Now().Add(-time.Minute),
		"after leaf end": time.Now().Add(2 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			err := validatePQCredential(nil, "portal", testNodeID, nil, "", renewAfter, leaf)
			if err == nil || !strings.Contains(err.Error(), "renew_after") {
				t.Fatalf("validatePQCredential() error = %v, want renew_after", err)
			}
		})
	}
}

func TestValidateIssuedRequiresKeyMaterial(t *testing.T) {
	if err := ValidateIssued(nil, "portal", testNodeID, nil, nil, "", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("ValidateIssued() accepted missing key material")
	}
}

func TestValidateRenewalRejectsInvalidInput(t *testing.T) {
	ca := newTestCA(t)
	material, err := agentcrypto.Generate("agent")
	if err != nil {
		t.Fatal(err)
	}
	current := &state.Identity{CertificateChain: []string{ca.issue(t, material.ECDSAKey, nil), ca.pem}}
	accepted := protocol.RenewAccepted{Type: protocol.RenewAcceptedType, CertificateChain: current.CertificateChain}

	tests := []struct {
		name     string
		current  *state.Identity
		pending  *state.PendingRenewal
		material *agentcrypto.KeyMaterial
		accepted protocol.RenewAccepted
		want     string
	}{
		{name: "no current identity", pending: &state.PendingRenewal{}, material: material, accepted: accepted, want: "invalid renewal"},
		{name: "no pending renewal", current: current, material: material, accepted: accepted, want: "invalid renewal"},
		{name: "no material", current: current, pending: &state.PendingRenewal{}, accepted: accepted, want: "invalid renewal"},
		{name: "wrong type", current: current, pending: &state.PendingRenewal{}, material: material, accepted: protocol.RenewAccepted{Type: "renew.rejected"}, want: "invalid renewal"},
		{
			name: "other root", current: current, pending: &state.PendingRenewal{}, material: material,
			accepted: protocol.RenewAccepted{Type: protocol.RenewAcceptedType, CertificateChain: []string{current.CertificateChain[0], newTestCA(t).pem}},
			want:     "unexpected portal root",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateRenewal(test.current, test.pending, test.material, test.accepted)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateRenewal() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSameCertificateRoot(t *testing.T) {
	ca := newTestCA(t)

	if !sameCertificateRoot([]string{"leaf", ca.pem}, []string{"other leaf", ca.pem}) {
		t.Fatal("identical roots were not recognized")
	}
	if sameCertificateRoot([]string{ca.pem}, []string{newTestCA(t).pem}) {
		t.Fatal("different roots were accepted")
	}
	if sameCertificateRoot(nil, []string{ca.pem}) || sameCertificateRoot([]string{ca.pem}, nil) {
		t.Fatal("an empty chain was accepted")
	}
	if sameCertificateRoot([]string{ca.pem}, []string{ca.pem + "trailing"}) {
		t.Fatal("a root with trailing data was accepted")
	}
}
