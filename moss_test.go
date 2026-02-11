package moss

import (
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(Config{})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestNewClientWithAPIKey(t *testing.T) {
	client, err := NewClient(Config{APIKey: "test_key"})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if !client.EnterpriseEnabled() {
		t.Error("EnterpriseEnabled should return true with API key")
	}
}

func TestSignLocal(t *testing.T) {
	client, _ := NewClient(Config{})

	result, err := client.Sign(SignRequest{
		Payload: map[string]any{"action": "test", "amount": 100},
		AgentID: "test-agent",
	})

	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if result.Envelope == nil {
		t.Fatal("Sign returned nil envelope")
	}

	if result.Envelope.Spec != SPEC {
		t.Errorf("Expected spec %s, got %s", SPEC, result.Envelope.Spec)
	}

	if result.Envelope.Subject != "test-agent" {
		t.Errorf("Expected subject test-agent, got %s", result.Envelope.Subject)
	}

	if result.Envelope.PayloadHash == "" {
		t.Error("PayloadHash should not be empty")
	}
}

func TestSignSequenceIncrement(t *testing.T) {
	client, _ := NewClient(Config{})

	result1, _ := client.Sign(SignRequest{Payload: "test1", AgentID: "agent"})
	result2, _ := client.Sign(SignRequest{Payload: "test2", AgentID: "agent"})

	if result2.Envelope.Seq <= result1.Envelope.Seq {
		t.Error("Sequence should increment")
	}
}

func TestVerify(t *testing.T) {
	client, _ := NewClient(Config{})

	payload := map[string]any{"action": "test", "value": 42}

	signResult, _ := client.Sign(SignRequest{
		Payload: payload,
		AgentID: "test-agent",
	})

	verifyResult, err := client.Verify(payload, signResult.Envelope)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResult.Valid {
		t.Error("Verify should return Valid=true")
	}

	if verifyResult.Subject != "test-agent" {
		t.Errorf("Expected subject test-agent, got %s", verifyResult.Subject)
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	client, _ := NewClient(Config{})

	payload := map[string]any{"action": "test", "value": 42}

	signResult, _ := client.Sign(SignRequest{
		Payload: payload,
		AgentID: "test-agent",
	})

	// Tamper with payload
	tamperedPayload := map[string]any{"action": "test", "value": 9999}

	verifyResult, _ := client.Verify(tamperedPayload, signResult.Envelope)

	if verifyResult.Valid {
		t.Error("Verify should return Valid=false for tampered payload")
	}
}

func TestVerifyNilEnvelope(t *testing.T) {
	client, _ := NewClient(Config{})

	result, _ := client.Verify("test", nil)
	if result.Valid {
		t.Error("Verify should return Valid=false for nil envelope")
	}
}

func TestEnvelopeTimestamp(t *testing.T) {
	client, _ := NewClient(Config{})

	before := time.Now().Unix()

	result, _ := client.Sign(SignRequest{
		Payload: "test",
		AgentID: "agent",
	})

	after := time.Now().Unix()

	if result.Envelope.IssuedAt < before || result.Envelope.IssuedAt > after {
		t.Error("IssuedAt should be within test bounds")
	}
}

func TestEnvelopeFields(t *testing.T) {
	client, _ := NewClient(Config{})

	result, _ := client.Sign(SignRequest{
		Payload: map[string]string{"key": "value"},
		AgentID: "my-agent",
	})

	env := result.Envelope

	if env.Spec != "moss-0001" {
		t.Errorf("Expected spec moss-0001, got %s", env.Spec)
	}

	if env.Version != 1 {
		t.Errorf("Expected version 1, got %d", env.Version)
	}

	if env.Alg != "ML-DSA-44" {
		t.Errorf("Expected alg ML-DSA-44, got %s", env.Alg)
	}

	if env.KeyVersion != 1 {
		t.Errorf("Expected key_version 1, got %d", env.KeyVersion)
	}
}

func TestDefaultAgentID(t *testing.T) {
	client, _ := NewClient(Config{})

	result, _ := client.Sign(SignRequest{
		Payload: "test",
	})

	if result.Envelope.Subject != "moss:local:default" {
		t.Errorf("Expected default subject, got %s", result.Envelope.Subject)
	}
}
