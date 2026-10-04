package workload

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestCommandDigestIgnoresRenewedSessionClaims(t *testing.T) {
	command := protocol.WorkloadCommand{
		Type:          protocol.WorkloadStopRequestType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		PortalID:      testPortalID,
		NodeID:        testNodeID,
		WorkloadID:    testWorkloadID,
		SessionNonce:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		IssuedAt:      time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		ExpiresAt:     time.Date(2030, 1, 2, 3, 4, 35, 0, time.UTC),
		Payload:       json.RawMessage(`{"timeout_seconds":30}`),
	}

	original := mustCommandDigest(t, command)
	command.SessionNonce = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	command.IssuedAt = command.IssuedAt.Add(time.Minute)
	command.ExpiresAt = command.ExpiresAt.Add(time.Minute)
	if renewed := mustCommandDigest(t, command); renewed != original {
		t.Fatalf("session renewal changed semantic command digest: %s != %s", renewed, original)
	}
}

func TestCommandDigestBindsPayloadAndIdentity(t *testing.T) {
	command := protocol.WorkloadCommand{
		Type: protocol.WorkloadStopRequestType, SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		PortalID:  testPortalID, NodeID: testNodeID, WorkloadID: testWorkloadID,
		Payload: json.RawMessage(`{"timeout_seconds":30}`),
	}
	original := mustCommandDigest(t, command)

	command.Payload = json.RawMessage(`{"timeout_seconds":60}`)
	if mustCommandDigest(t, command) == original {
		t.Fatal("payload change did not change semantic command digest")
	}
	command.Payload = json.RawMessage(`{"timeout_seconds":30}`)
	command.PortalID = "6e0c1d91-5145-440f-bf97-d84db4f83644"
	if mustCommandDigest(t, command) == original {
		t.Fatal("portal change did not change semantic command digest")
	}
}

func mustCommandDigest(t *testing.T, command protocol.WorkloadCommand) string {
	t.Helper()

	digest, err := commandDigest(command)
	if err != nil {
		t.Fatalf("digest workload command: %v", err)
	}

	return digest
}
