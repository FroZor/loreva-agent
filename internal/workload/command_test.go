package workload

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestVerifyCommandBindsIdentitySessionAndLifetime(t *testing.T) {
	portalID := "d1b181c1-52ec-4d55-b2c9-b1428305b294"
	nodeID := "65a1876f-a715-45fc-9ac0-e4bc31067059"
	workloadID := "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"
	requestID := "6e0c1d91-5145-440f-bf97-d84db4f83644"
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	now := time.Now().UTC()
	command := protocol.WorkloadCommand{
		Type:          protocol.WorkloadStopRequestType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     requestID,
		PortalID:      portalID,
		NodeID:        nodeID,
		WorkloadID:    workloadID,
		SessionNonce:  nonce,
		IssuedAt:      now.Add(-time.Second),
		ExpiresAt:     now.Add(30 * time.Second),
		Payload:       json.RawMessage(`{"timeout_seconds":30}`),
	}

	root, signed := signPortalCommand(t, command)
	verified, err := VerifyCommand(root, signed, portalID, nodeID, nonce, now)
	if err != nil {
		t.Fatalf("verify valid command: %v", err)
	}
	if verified.RequestID != requestID {
		t.Fatalf("verified request_id = %q", verified.RequestID)
	}

	otherNonce := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	if _, err := VerifyCommand(root, signed, portalID, nodeID, otherNonce, now); err == nil {
		t.Fatal("command bound to another session was accepted")
	}
	if _, err := VerifyCommand(root, signed, portalID, nodeID, nonce, now.Add(time.Minute)); err == nil {
		t.Fatal("expired command was accepted")
	}
}

func signPortalCommand(t *testing.T, command protocol.WorkloadCommand) (*agentcrypto.JWK, string) {
	t.Helper()

	var seed [mldsa65.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := mldsa65.NewKeyFromSeed(&seed)

	header, err := json.Marshal(map[string]string{"alg": agentcrypto.MLDSAAlgorithm})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}

	encoding := base64.RawURLEncoding
	signingInput := encoding.EncodeToString(header) + "." + encoding.EncodeToString(payload)
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(privateKey, []byte(signingInput), nil, true, signature); err != nil {
		t.Fatal(err)
	}

	return agentcrypto.PublicJWK(publicKey), signingInput + "." + encoding.EncodeToString(signature)
}

func TestDeviceCommandUsesTheNodeControllerScope(t *testing.T) {
	nodeID := "65a1876f-a715-45fc-9ac0-e4bc31067059"
	request := protocol.DeviceWorkloadCommand{
		Type:          protocol.WorkloadStopRequestType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     "6e0c1d91-5145-440f-bf97-d84db4f83644",
		WorkloadID:    "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		Payload:       json.RawMessage(`{"timeout_seconds":30}`),
	}

	command, err := DeviceCommand(request, nodeID, time.Now())
	if err != nil {
		t.Fatalf("DeviceCommand() error = %v", err)
	}
	if command.PortalID != nodeID || command.NodeID != nodeID || command.SessionNonce != "" {
		t.Fatalf("command = %+v", command)
	}

	invalid := []func(*protocol.DeviceWorkloadCommand){
		func(r *protocol.DeviceWorkloadCommand) { r.SchemaVersion = 2 },
		func(r *protocol.DeviceWorkloadCommand) { r.Type = protocol.WorkloadPlanResultType },
		func(r *protocol.DeviceWorkloadCommand) { r.RequestID = "not-a-uuid" },
		func(r *protocol.DeviceWorkloadCommand) { r.Payload = json.RawMessage("null") },
	}
	for index, mutate := range invalid {
		candidate := request
		mutate(&candidate)
		if _, err := DeviceCommand(candidate, nodeID, time.Now()); err == nil {
			t.Errorf("invalid request %d accepted", index)
		}
	}
}
