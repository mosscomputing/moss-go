package sidecar

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestIsRevokedByID(t *testing.T) {
	feed := &RevocationFeed{Revocations: []Revocation{
		{AgentID: "11111111-1111-1111-1111-111111111111", Subject: "agent-a"},
		{AgentID: "22222222-2222-2222-2222-222222222222", Subject: "agent-b"},
	}}
	if !feed.IsRevoked("11111111-1111-1111-1111-111111111111", "") {
		t.Error("expected revoked by id")
	}
	if !feed.IsRevoked("", "agent-b") {
		t.Error("expected revoked by subject")
	}
	if feed.IsRevoked("33333333-3333-3333-3333-333333333333", "") {
		t.Error("non-revoked id should not match")
	}
	if feed.IsRevoked("", "agent-c") {
		t.Error("non-revoked subject should not match")
	}
}

func TestSignedPayloadCanonical(t *testing.T) {
	feed := &RevocationFeed{
		Epoch:        42,
		GeneratedAt:  "2026-06-28T00:00:00+00:00",
		NotAfter:     "2026-06-28T01:00:00+00:00",
		Revocations:  []Revocation{{AgentID: "a1", Subject: "s1", RevokedAt: "2026-06-28T00:00:01+00:00", Reason: "test"}},
	}
	msg, err := feed.signedPayload()
	if err != nil {
		t.Fatalf("signedPayload: %v", err)
	}
	s := string(msg)
	// Compact (no spaces after separators).
	if strings.Contains(s, ", ") || strings.Contains(s, ": ") {
		t.Errorf("canonical payload not compact: %s", s)
	}
	// Keys must be sorted at every level.
	if !strings.HasPrefix(s, "{\"epoch\":") {
		t.Errorf("expected sorted keys starting with epoch, got: %s", s[:min(len(s), 40)])
	}
	if strings.Contains(s, "\"signature\"") || strings.Contains(s, "\"key_id\"") || strings.Contains(s, "\"algorithm\"") {
		t.Errorf("signed payload must not contain signature metadata: %s", s)
	}
}

func TestFeedVerifyRejectsBadAlgorithm(t *testing.T) {
	feed := &RevocationFeed{Algorithm: "Ed25519", Signature: base64.StdEncoding.EncodeToString(make([]byte, MLDSA44SignatureSize))}
	err := feed.Verify(make([]byte, MLDSA44PublicKeySize))
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("expected algorithm error, got %v", err)
	}
}

func TestFeedVerifyRejectsBadSigSize(t *testing.T) {
	feed := &RevocationFeed{Algorithm: MLDSA44Algorithm, Signature: base64.StdEncoding.EncodeToString([]byte("too short"))}
	err := feed.Verify(make([]byte, MLDSA44PublicKeySize))
	if err == nil {
		t.Fatal("expected error for bad signature size")
	}
}
