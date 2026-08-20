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

func TestMessageTypeRequiresType(t *testing.T) {
	messageType, err := MessageType([]byte(`{"type":"sources.update","generation":1}`))
	if err != nil || messageType != SourcesUpdateType {
		t.Fatalf("MessageType() = %q, %v", messageType, err)
	}

	if _, err := MessageType([]byte(`{"generation":1}`)); err == nil {
		t.Fatal("MessageType() accepted a message without type")
	}
}
