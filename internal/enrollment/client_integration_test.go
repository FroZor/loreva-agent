package enrollment_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/enrollment"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/state"
)

var rawBase64 = base64.RawURLEncoding

type testPortal struct {
	t                *testing.T
	server           *httptest.Server
	token            string
	portalID         string
	nodeID           string
	clientRoot       *x509.Certificate
	clientRootKey    *ecdsa.PrivateKey
	pqRootKey        *mldsa65.PrivateKey
	pqRootPublic     *mldsa65.PublicKey
	mu               sync.Mutex
	agentPublicKey   *mldsa65.PublicKey
	renewAfterDelay  time.Duration
	connectCount     int
	sourcesUpdate    *protocol.SourcesUpdate
	drainAfterUpdate bool
	omitPQRoot       bool
	overridePQRoot   *agentcrypto.JWK
}

func TestEnrollThenConnect(t *testing.T) {
	portal := newTestPortal(t)
	defer portal.server.Close()

	stateDir := t.TempDir()
	identity := enrollTestAgent(t, portal, stateDir)

	if identity.NodeID != portal.nodeID || identity.PortalID != portal.portalID {
		t.Fatal("enrollment returned an unexpected identity")
	}
	if !agentcrypto.PublicKeysEqual(&identity.PortalPQRoot, portal.pqRootPublic) {
		t.Fatal("enrollment did not persist the portal PQ root")
	}
	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := session.New(store, stored)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	connected := make(chan struct{})
	err = runner.Run(ctx, func(string) {
		close(connected)
		cancel()
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
	select {
	case <-connected:
	default:
		t.Fatal("agent did not complete the connect handshake")
	}
}

func TestEnrollmentRejectsMissingPortalPQRoot(t *testing.T) {
	portal := newTestPortal(t)
	defer portal.server.Close()
	portal.omitPQRoot = true

	assertEnrollmentRejectedWithoutIdentity(t, portal, "invalid portal_pq_root")
}

func TestEnrollmentRejectsPQCredentialSignedByDifferentRoot(t *testing.T) {
	portal := newTestPortal(t)
	defer portal.server.Close()

	material, err := agentcrypto.Generate("different-portal-root")
	if err != nil {
		t.Fatal(err)
	}
	portal.overridePQRoot = agentcrypto.PublicJWK(material.MLDSAPub)

	assertEnrollmentRejectedWithoutIdentity(t, portal, "verify pq_credential")
}

func assertEnrollmentRejectedWithoutIdentity(t *testing.T, portal *testPortal, expectedError string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stateDir := t.TempDir()
	_, err := enrollment.Enroll(ctx, enrollment.Options{
		PortalURL:   portal.URL(),
		Token:       portal.token,
		PortalCAPEM: portal.CAPEM(),
		StateDir:    stateDir,
		Version:     "test",
		Hostname:    "test-node",
	})
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Fatalf("Enroll() error = %v, want %q", err, expectedError)
	}

	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadIdentity(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("invalid enrollment persisted identity: %v", err)
	}
}

func TestEnrollConnectAndRenewIdentity(t *testing.T) {
	portal := newTestPortal(t)
	defer portal.server.Close()

	portal.renewAfterDelay = 100 * time.Millisecond
	stateDir := t.TempDir()
	identity := enrollTestAgent(t, portal, stateDir)

	originalKey := identity.ECDSAPrivateKey
	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := session.New(store, identity)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connections := 0
	err = runner.Run(ctx, func(string) {
		connections++
		if connections == 2 {
			cancel()
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
	renewed, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if connections != 2 || renewed.ECDSAPrivateKey == originalKey {
		t.Fatal("agent did not activate the renewed identity and reconnect")
	}
	if _, err := store.LoadRenewal(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("completed renewal state was not cleared: %v", err)
	}
}

func TestSourcesUpdateIsPersistedBeforeDrainReconnect(t *testing.T) {
	portal := newTestPortal(t)
	defer portal.server.Close()

	stateDir := t.TempDir()
	identity := enrollTestAgent(t, portal, stateDir)

	portal.mu.Lock()
	portal.sourcesUpdate = &protocol.SourcesUpdate{
		Type:    protocol.SourcesUpdateType,
		Sources: protocol.Sources{Generation: 2, ExpiresAt: time.Now().Add(time.Hour), Items: []protocol.SourceItem{}},
	}
	portal.drainAfterUpdate = true
	portal.mu.Unlock()
	store, err := state.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := session.New(store, identity)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connections := 0
	err = runner.Run(ctx, func(string) {
		connections++
		if connections == 2 {
			cancel()
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
	persisted, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if connections != 2 || persisted.Sources.Generation != 2 {
		t.Fatalf("connections=%d sources generation=%d", connections, persisted.Sources.Generation)
	}
}

func enrollTestAgent(t *testing.T, portal *testPortal, stateDir string) *state.Identity {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identity, err := enrollment.Enroll(ctx, enrollment.Options{
		PortalURL:   portal.URL(),
		Token:       portal.token,
		PortalCAPEM: portal.CAPEM(),
		StateDir:    stateDir,
		Version:     "test",
		Hostname:    "test-node",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	return identity
}

func newTestPortal(t *testing.T) *testPortal {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test agent root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	pqRootPublic, pqRoot, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	portalID, err := agentcrypto.NewUUID()
	if err != nil {
		t.Fatal(err)
	}

	nodeID, err := agentcrypto.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	portal := &testPortal{
		t: t, token: "1234567890abcdef.test-secret", portalID: portalID, nodeID: nodeID,
		clientRoot: root, clientRootKey: rootKey, pqRootKey: pqRoot, pqRootPublic: pqRootPublic,
		renewAfterDelay: time.Hour,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/enroll", portal.handleEnroll)
	mux.HandleFunc("/agent/v1/connect", portal.handleConnect)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	pool := x509.NewCertPool()
	pool.AddCert(root)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
	}
	server.StartTLS()
	portal.server = server
	return portal
}

func (p *testPortal) URL() string { return "wss" + strings.TrimPrefix(p.server.URL, "https") }

func (p *testPortal) CAPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate().Raw}))
}

func (p *testPortal) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+p.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.EnrollmentSubprotocol}})
	if err != nil {
		return
	}
	defer closeTestConnection(p.t, conn)
	challenge, err := p.challenge(protocol.EnrollmentChallenge)
	if err != nil {
		p.t.Errorf("create enrollment challenge: %v", err)
		return
	}
	if wsjson.Write(r.Context(), conn, challenge) != nil {
		return
	}
	var request protocol.EnrollmentRequest
	if wsjson.Read(r.Context(), conn, &request) != nil {
		return
	}
	csrBlock, rest := pem.Decode([]byte(request.CSR))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		p.t.Error("missing CSR")
		return
	}

	agentPublicKey, err := verifyPoP(request.PQPoP, p.portalID, challenge.Nonce, csrBlock.Bytes, nil)
	if err != nil {
		p.t.Errorf("verify enrollment proof: %v", err)
		return
	}

	chain, notAfter, err := p.issueCertificate(csrBlock.Bytes)
	if err != nil {
		p.t.Errorf("issue enrollment certificate: %v", err)
		return
	}

	credential, err := p.issueCredential(agentPublicKey, notAfter)
	if err != nil {
		p.t.Errorf("issue enrollment credential: %v", err)
		return
	}

	p.mu.Lock()
	p.agentPublicKey = agentPublicKey
	p.mu.Unlock()
	accepted := protocol.EnrollmentAccepted{
		Type: protocol.EnrollmentAcceptedType, NodeID: p.nodeID, CertificateChain: chain,
		PQCredential: credential, RenewAfter: time.Now().Add(p.renewAfterDelay),
		Sources: protocol.Sources{Generation: 1, ExpiresAt: time.Now().Add(time.Hour), Items: []protocol.SourceItem{}},
	}
	if !p.omitPQRoot {
		accepted.PortalPQRoot = p.overridePQRoot
		if accepted.PortalPQRoot == nil {
			accepted.PortalPQRoot = agentcrypto.PublicJWK(p.pqRootPublic)
		}
	}
	if err := wsjson.Write(r.Context(), conn, accepted); err != nil {
		return
	}

	_ = conn.Close(websocket.StatusNormalClosure, "")
}

func (p *testPortal) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.ConnectSubprotocol}})
	if err != nil {
		return
	}
	defer closeTestConnection(p.t, conn)
	challenge, err := p.challenge(protocol.ConnectChallenge)
	if err != nil {
		p.t.Errorf("create connect challenge: %v", err)
		return
	}

	signed, err := signJWS(p.pqRootKey, map[string]any{"alg": agentcrypto.MLDSAAlgorithm}, challenge)
	if err != nil {
		p.t.Errorf("sign connect challenge: %v", err)
		return
	}
	if wsjson.Write(r.Context(), conn, protocol.SignedChallenge{Type: protocol.ConnectChallenge, SignedChallenge: signed}) != nil {
		return
	}
	var proof protocol.ConnectProof
	if wsjson.Read(r.Context(), conn, &proof) != nil {
		return
	}
	p.mu.Lock()
	agentPublicKey := p.agentPublicKey
	p.mu.Unlock()

	if _, err := verifyPoP(proof.PQPoP, p.portalID, challenge.Nonce, nil, agentPublicKey); err != nil {
		p.t.Errorf("verify connect proof: %v", err)
		return
	}
	if err := wsjson.Write(r.Context(), conn, protocol.ConnectAccepted{Type: protocol.ConnectAcceptedType}); err != nil {
		return
	}

	p.mu.Lock()
	p.connectCount++
	sendUpdate := p.connectCount == 1 && p.sourcesUpdate != nil
	update := p.sourcesUpdate
	drainAfterUpdate := p.drainAfterUpdate
	p.mu.Unlock()
	if sendUpdate {
		if wsjson.Write(r.Context(), conn, update) != nil {
			return
		}
		if drainAfterUpdate && wsjson.Write(r.Context(), conn, protocol.Drain{Type: protocol.DrainType}) != nil {
			return
		}
	}
	for {
		var request protocol.RenewRequest
		if wsjson.Read(r.Context(), conn, &request) != nil {
			return
		}
		if request.Type != protocol.RenewRequestType {
			p.t.Errorf("unexpected working message %q", request.Type)
			return
		}
		csrBlock, rest := pem.Decode([]byte(request.CSR))
		if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
			p.t.Error("renewal CSR is missing")
			return
		}

		newPublicKey, err := verifyPoP(request.PQPoP, p.portalID, challenge.Nonce, csrBlock.Bytes, nil)
		if err != nil {
			p.t.Errorf("verify renewal proof: %v", err)
			return
		}

		chain, notAfter, err := p.issueCertificate(csrBlock.Bytes)
		if err != nil {
			p.t.Errorf("issue renewed certificate: %v", err)
			return
		}

		credential, err := p.issueCredential(newPublicKey, notAfter)
		if err != nil {
			p.t.Errorf("issue renewed credential: %v", err)
			return
		}

		p.mu.Lock()
		p.agentPublicKey = newPublicKey
		p.mu.Unlock()
		if err := wsjson.Write(r.Context(), conn, protocol.RenewAccepted{
			Type: protocol.RenewAcceptedType, CertificateChain: chain, PQCredential: credential,
			RenewAfter: notAfter.Add(-time.Hour),
		}); err != nil {
			return
		}
	}
}

func (p *testPortal) challenge(messageType string) (protocol.Challenge, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return protocol.Challenge{}, fmt.Errorf("generate challenge nonce: %w", err)
	}

	challengeID, err := agentcrypto.NewUUID()
	if err != nil {
		return protocol.Challenge{}, fmt.Errorf("generate challenge ID: %w", err)
	}

	now := time.Now()

	return protocol.Challenge{
		Type: messageType, ChallengeID: challengeID, Nonce: rawBase64.EncodeToString(nonce), PortalID: p.portalID,
		IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
	}, nil
}

func (p *testPortal) issueCertificate(csrDER []byte) ([]string, time.Time, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, time.Time{}, fmt.Errorf("verify CSR signature: %w", err)
	}

	notAfter := time.Now().Add(24 * time.Hour)
	identity, err := url.Parse("loreva://node/" + p.nodeID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("build node identity URI: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: p.nodeID}, URIs: []*url.URL{identity},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.clientRoot, csr.PublicKey, p.clientRootKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create client certificate: %w", err)
	}

	chain := []string{
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.clientRoot.Raw})),
	}

	return chain, notAfter, nil
}

func (p *testPortal) issueCredential(agentPublicKey *mldsa65.PublicKey, expires time.Time) (string, error) {
	claims := struct {
		Issuer       string `json:"iss"`
		Subject      string `json:"sub"`
		IssuedAt     int64  `json:"iat"`
		ExpiresAt    int64  `json:"exp"`
		Confirmation struct {
			JWK *agentcrypto.JWK `json:"jwk"`
		} `json:"cnf"`
	}{Issuer: p.portalID, Subject: p.nodeID, IssuedAt: time.Now().Unix(), ExpiresAt: expires.Unix()}
	claims.Confirmation.JWK = agentcrypto.PublicJWK(agentPublicKey)

	return signJWS(p.pqRootKey, map[string]any{"alg": agentcrypto.MLDSAAlgorithm}, claims)
}

func verifyPoP(token, portalID, nonce string, csrDER []byte, expected *mldsa65.PublicKey) (*mldsa65.PublicKey, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid Compact JWS")
	}

	headerBytes, err := rawBase64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWS header: %w", err)
	}

	payloadBytes, err := rawBase64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWS payload: %w", err)
	}

	signature, err := rawBase64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWS signature: %w", err)
	}

	var header struct {
		Alg string           `json:"alg"`
		JWK *agentcrypto.JWK `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("decode JWS header JSON: %w", err)
	}

	publicKey := expected
	if publicKey == nil {
		if header.JWK == nil {
			return nil, errors.New("PoP header does not contain a JWK")
		}

		raw, err := rawBase64.DecodeString(header.JWK.Pub)
		if err != nil {
			return nil, fmt.Errorf("decode ML-DSA public key: %w", err)
		}
		publicKey = new(mldsa65.PublicKey)
		if err := publicKey.UnmarshalBinary(raw); err != nil {
			return nil, fmt.Errorf("decode ML-DSA public key: %w", err)
		}
	}
	if header.Alg != agentcrypto.MLDSAAlgorithm || !mldsa65.Verify(publicKey, []byte(parts[0]+"."+parts[1]), nil, signature) {
		return nil, errors.New("invalid PoP signature")
	}

	var claims struct {
		Audience  string `json:"aud"`
		Challenge string `json:"challenge"`
		CSRHash   string `json:"csr_sha256"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("decode PoP claims: %w", err)
	}

	if claims.Audience != portalID || claims.Challenge != nonce {
		return nil, errors.New("PoP is not bound to challenge")
	}
	if csrDER != nil {
		hash := sha256.Sum256(csrDER)
		if claims.CSRHash != rawBase64.EncodeToString(hash[:]) {
			return nil, errors.New("PoP is not bound to CSR")
		}
	}

	return publicKey, nil
}

func signJWS(key *mldsa65.PrivateKey, header, claims any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encode JWS header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode JWS claims: %w", err)
	}

	input := rawBase64.EncodeToString(headerJSON) + "." + rawBase64.EncodeToString(claimsJSON)
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(key, []byte(input), nil, true, signature); err != nil {
		return "", fmt.Errorf("sign JWS: %w", err)
	}

	return input + "." + rawBase64.EncodeToString(signature), nil
}

func closeTestConnection(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	if err := conn.CloseNow(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close test WebSocket connection: %v", err)
	}
}
