package protocol

import "testing"

func TestDecodeStrictRejectsDuplicateFields(t *testing.T) {
	var message ConnectAccepted
	if err := DecodeStrict([]byte(`{"type":"connect.accepted","type":"connect.rejected"}`), &message); err == nil {
		t.Fatal("duplicate protocol field was accepted")
	}
}

func TestDecodeStrictSignedChallengeAndRenewal(t *testing.T) {
	var challenge SignedChallenge
	if err := DecodeStrict([]byte(`{"type":"connect.challenge","signed_challenge":"a.b.c"}`), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Type != ConnectChallenge || challenge.SignedChallenge != "a.b.c" {
		t.Fatal("signed connect challenge changed during decoding")
	}
	var accepted RenewAccepted
	if err := DecodeStrict([]byte(`{"type":"renew.accepted","certificate_chain":[],"pq_credential":"a.b.c","renew_after":"2030-01-02T03:04:05Z"}`), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Type != RenewAcceptedType || accepted.PQCredential != "a.b.c" {
		t.Fatal("renew.accepted changed during decoding")
	}
}

func TestDecodeStrictEnrollmentAcceptedPortalRoot(t *testing.T) {
	var accepted EnrollmentAccepted
	raw := []byte(`{"type":"enrollment.accepted","node_id":"node","certificate_chain":[],"portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"key"},"pq_credential":"a.b.c","renew_after":"2030-01-02T03:04:05Z","sources":{"generation":1,"expires_at":"2030-01-02T03:04:05Z","items":[]}}`)
	if err := DecodeStrict(raw, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.PortalPQRoot == nil || accepted.PortalPQRoot.Alg != "ML-DSA-65" {
		t.Fatal("enrollment.accepted portal_pq_root changed during decoding")
	}

	duplicate := []byte(`{"type":"enrollment.accepted","node_id":"node","certificate_chain":[],"portal_pq_root":{"kty":"AKP","alg":"ML-DSA-65","pub":"one","pub":"two"},"pq_credential":"a.b.c","renew_after":"2030-01-02T03:04:05Z","sources":{"generation":1,"expires_at":"2030-01-02T03:04:05Z","items":[]}}`)
	if err := DecodeStrict(duplicate, &accepted); err == nil {
		t.Fatal("duplicate portal_pq_root field was accepted")
	}
}

func TestMessageTypeRequiresType(t *testing.T) {
	messageType, err := MessageType([]byte(`{"type":"sources.update","generation":1}`))
	if err != nil || messageType != SourcesUpdateType {
		t.Fatalf("MessageType() = %q, %v", messageType, err)
	}

	if _, err := MessageType([]byte(`{"generation":1}`)); err == nil {
		t.Fatal("MessageType() accepted a message without type")
	}
}

func TestDecodeStrictNodeReports(t *testing.T) {
	var specifications NodeSpecificationsReport
	if err := DecodeStrict([]byte(`{
        "type":"node.specifications.report",
        "schema_version":1,
        "request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
        "observed_at":"2030-01-02T03:04:05Z",
        "observation_scope":"host",
        "specifications":{
            "system":{"hostname":"node-a","architecture":"amd64","os":{"type":"linux"}},
            "cpu":{"architecture":"amd64","physical_core_count":2,"logical_processor_count":4,"packages":[],"numa_nodes":[],"logical_processors":[]},
            "memory":{"total_bytes":1024,"modules":[]},
            "gpus":[],"storage_devices":[],"network_interfaces":[]
        }
    }`), &specifications); err != nil {
		t.Fatal(err)
	}
	if specifications.Type != NodeSpecificationsReportType || specifications.SchemaVersion != 1 {
		t.Fatalf("unexpected specifications report: %#v", specifications)
	}

	var network NodeNetworkReport
	if err := DecodeStrict([]byte(`{
        "type":"node.network.report",
        "schema_version":1,
        "request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
        "observed_at":"2030-01-02T03:04:05Z",
        "observation_scope":"host",
        "network":{
            "interfaces":[],"routes":[],"listening_ports":[],
            "firewall":{"status":"inactive","providers":[],"rules":[],"truncated":false}
        }
    }`), &network); err != nil {
		t.Fatal(err)
	}
	if network.Type != NodeNetworkReportType || network.SchemaVersion != 1 {
		t.Fatalf("unexpected network report: %#v", network)
	}
}
