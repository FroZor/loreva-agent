package session

import (
	"errors"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/challenge"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
)

func TestTerminalRejectionClassification(t *testing.T) {
	for _, code := range []string{"expired_pq_proof", "replayed_pq_proof", "internal_error"} {
		if terminalRejection(code) {
			t.Fatalf("recoverable rejection %q was classified as terminal", code)
		}
	}
	for _, code := range []string{"unsupported_protocol_version", "unsupported_security_profile", "invalid_certificate", "invalid_pq_credential", "invalid_pq_proof", "tls_policy_violation", "unknown"} {
		if !terminalRejection(code) {
			t.Fatalf("security rejection %q was classified as retryable", code)
		}
	}
}

func TestApplySourcesUpdatePersistsAndReconnectsRemovedGateway(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gateway := "wss://gateway.example/agent/v1/connect"
	identity := &state.Identity{Sources: protocol.Sources{
		Generation: 1,
		ExpiresAt:  time.Now().Add(time.Hour),
		Items: []protocol.SourceItem{{
			URL: gateway, Priority: 1, Weight: 100, SecurityProfile: protocol.SecurityProfile,
		}},
	}}
	if err := store.SaveIdentity(identity); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{store: store, identity: identity, masterEndpoint: "wss://master.example/agent/v1/connect"}
	updated := protocol.Sources{Generation: 2, ExpiresAt: time.Now().Add(2 * time.Hour), Items: []protocol.SourceItem{}}
	reconnect, err := runner.applySourcesUpdate(gateway, updated)
	if err != nil {
		t.Fatal(err)
	}
	if !reconnect {
		t.Fatal("removed current gateway did not request reconnect")
	}
	persisted, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !sourcesEqual(persisted.Sources, updated) {
		t.Fatalf("persisted sources = %#v, want %#v", persisted.Sources, updated)
	}
}

func TestApplySourcesUpdateRejectsRollbackAndEquivocation(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := protocol.Sources{Generation: 2, ExpiresAt: time.Now().Add(time.Hour), Items: []protocol.SourceItem{}}
	identity := &state.Identity{Sources: current}
	if err := store.SaveIdentity(identity); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{store: store, identity: identity, masterEndpoint: "wss://master.example/agent/v1/connect"}
	if reconnect, err := runner.applySourcesUpdate(runner.masterEndpoint, cloneSources(current)); err != nil || reconnect {
		t.Fatalf("identical generation was not a no-op: reconnect=%v err=%v", reconnect, err)
	}
	changed := cloneSources(current)
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Minute)
	if _, err := runner.applySourcesUpdate(runner.masterEndpoint, changed); err == nil {
		t.Fatal("same-generation equivocation was accepted")
	}
	rollback := cloneSources(current)
	rollback.Generation--
	if reconnect, err := runner.applySourcesUpdate(runner.masterEndpoint, rollback); err != nil || reconnect {
		t.Fatalf("stale generation was not ignored: reconnect=%v err=%v", reconnect, err)
	}
	if runner.identity.Sources.Generation != current.Generation {
		t.Fatal("stale generation replaced the current pool")
	}
}

func TestExpiredConnectChallengeIsRecoverable(t *testing.T) {
	challengeID, err := agentcrypto.NewUUID()
	if err != nil {
		t.Fatal(err)
	}

	portalID, err := agentcrypto.NewUUID()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	err = challenge.Validate(protocol.Challenge{
		Type: protocol.ConnectChallenge, ChallengeID: challengeID, PortalID: portalID,
		Nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second),
	}, protocol.ConnectChallenge, portalID)
	if !errors.Is(err, challenge.ErrExpired) {
		t.Fatalf("expired challenge error = %v, want challenge.ErrExpired", err)
	}
}

func TestMalformedRenewalResponseIsEndpointScoped(t *testing.T) {
	runner := &Runner{masterEndpoint: "wss://master.example/agent/v1/connect"}
	gateway := "wss://gateway.example/agent/v1/connect"

	gatewayErr := runner.handleRenewalResponse(nil, gateway, nil, []byte(`{`))
	if _, ok := errors.AsType[*endpointPolicyError](gatewayErr); !ok {
		t.Fatalf("gateway renewal error = %T, want endpointPolicyError", gatewayErr)
	}
	if IsTerminal(gatewayErr) {
		t.Fatal("gateway renewal error became globally terminal")
	}

	masterErr := runner.handleRenewalResponse(nil, runner.masterEndpoint, nil, []byte(`{`))
	if !IsTerminal(masterErr) {
		t.Fatalf("master renewal error was not terminal: %v", masterErr)
	}
}

func TestDrainDoesNotUseImmediateReconnectReset(t *testing.T) {
	client, _ := newWebSocketPair(t)
	runner := &Runner{masterEndpoint: "wss://master.example/agent/v1/connect"}

	err := runner.handleDrain(
		client,
		runner.masterEndpoint,
		[]byte(`{"type":"drain"}`),
	)
	if !errors.Is(err, errDrainRequested) {
		t.Fatalf("drain error = %v, want errDrainRequested", err)
	}
	if errors.Is(err, errReconnectRequested) {
		t.Fatal("drain reused the immediate reconnect path")
	}
}
