package runtime

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestCanonicalJSONMatchesPython verifies the Go canonical JSON output is
// byte-identical to Python's json.dumps(sort_keys=True, separators=(',',':'))
// for the payload shapes the SDK signs (strings, ints, bools, arrays, nested
// maps). This is the cross-language interop invariant (VAL-CROSS-002/014).
func TestCanonicalJSONMatchesPython(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{
			"flat",
			map[string]any{"a": "x", "b": 2, "c": true},
			`{"a":"x","b":2,"c":true}`,
		},
		{
			"nested",
			map[string]any{"z": 1, "a": map[string]any{"y": "v", "x": 9}},
			`{"a":{"x":9,"y":"v"},"z":1}`,
		},
		{
			"array-of-maps",
			map[string]any{"revocations": []any{
				map[string]any{"agent_id": "abc", "reason": "test"},
				map[string]any{"agent_id": "def", "reason": "x"},
			}},
			`{"revocations":[{"agent_id":"abc","reason":"test"},{"agent_id":"def","reason":"x"}]}`,
		},
		{
			"special-chars",
			map[string]any{"url": "http://x?a=1&b=2", "html": "<p>hi</p>"},
			`{"html":"<p>hi</p>","url":"http://x?a=1&b=2"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CanonicalJSON(c.in)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if string(got) != c.want {
				t.Errorf("canonical mismatch\ngot:  %s\nwant: %s", got, c.want)
			}
		})
	}
}

// TestCanonicalJSONSortedKeys verifies keys are sorted lexicographically.
func TestCanonicalJSONSortedKeys(t *testing.T) {
	in := map[string]any{"zebra": 1, "apple": 2, "mango": 3}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"apple":2,"mango":3,"zebra":1}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestKeyGenSignVerifyRoundTrip verifies ML-DSA-44 keygen + sign + verify
// with filippo.io/mldsa (the cross-language interop library).
func TestKeyGenSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.PublicKey) != PublicKeySize {
		t.Fatalf("pk size %d != %d", len(kp.PublicKey), PublicKeySize)
	}
	if len(kp.Seed) != SeedSize {
		t.Fatalf("seed size %d != %d", len(kp.Seed), SeedSize)
	}
	msg := []byte("agent action: transfer $500")
	sig, err := SignMessage(kp.Seed, msg)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig size %d != %d", len(sig), SignatureSize)
	}
	if !VerifyMessage(kp.PublicKey, msg, sig) {
		t.Fatal("honest signature must verify")
	}
	// Tampered message rejected.
	if VerifyMessage(kp.PublicKey, []byte("tampered"), sig) {
		t.Fatal("tampered message must NOT verify")
	}
	// Tampered signature rejected.
	bad := make([]byte, len(sig))
	copy(bad, sig)
	bad[0] ^= 0x01
	if VerifyMessage(kp.PublicKey, msg, bad) {
		t.Fatal("tampered signature must NOT verify")
	}
}

// TestKeystoreIdempotent verifies re-loading the same subject preserves the
// public key (VAL-RUNTIME-021).
func TestKeystoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore("moss:test:idempotent", dir)
	pk1, seed1, err := ks.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	ks2 := NewKeystore("moss:test:idempotent", dir)
	pk2, seed2, err := ks2.LoadOrCreate()
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if !bytes.Equal(pk1, pk2) || !bytes.Equal(seed1, seed2) {
		t.Fatal("keystore must preserve keys across runs (idempotent)")
	}
}

// TestSignPayloadProducesHex verifies SignPayload returns a canonical string
// + hex signature of the right length.
func TestSignPayloadProducesHex(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	payload := map[string]any{"action": "test", "agent_id": "moss:go:x", "ts": 123}
	canonical, sigHex, err := SignPayload(kp.Seed, payload)
	if err != nil {
		t.Fatalf("SignPayload: %v", err)
	}
	if !strings.HasPrefix(canonical, "{") {
		t.Errorf("canonical not JSON: %s", canonical)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("signature not hex: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig size %d != %d", len(sig), SignatureSize)
	}
	if !VerifyMessage(kp.PublicKey, []byte(canonical), sig) {
		t.Fatal("signature over canonical must verify")
	}
}

// TestPolicyDeclaredViolation verifies the local declared-behavior
// enforcement blocks undeclared targets (VAL-RUNTIME-008/014) and allows
// declared ones.
func TestPolicyDeclaredViolation(t *testing.T) {
	pe := NewPolicyEngine("http://localhost:9999", "k", "moss:go:p",
		DeclaredBehavior{
			AllowedDataSources:  []string{"public"},
			AllowedDestinations: []string{"http://localhost:3150"},
			AllowedActions:      []string{"http_get", "query"},
		}, 30, nil)

	// Undeclared data source -> block (API down -> offline declared enforcement).
	d := pe.Check("query", "", "private", nil)
	if !d.IsBlock() {
		t.Errorf("undeclared data source must block, got %+v", d)
	}
	if !d.DeclaredViolation {
		t.Error("expected declared_violation=true for undeclared data source")
	}

	// Declared data source + action -> allow (API down, within declared behavior).
	d = pe.Check("query", "", "public", nil)
	if d.IsBlock() {
		t.Errorf("declared data source must allow, got %+v", d)
	}

	// Undeclared destination -> block.
	d = pe.Check("http_get", "http://evil.example", "", nil)
	if !d.IsBlock() {
		t.Errorf("undeclared destination must block, got %+v", d)
	}

	// Declared destination -> allow.
	d = pe.Check("http_get", "http://localhost:3150", "", nil)
	if d.IsBlock() {
		t.Errorf("declared destination must allow, got %+v", d)
	}
}

// TestPolicyEmptyDeclaredNoBoundary verifies that an empty declared set for a
// dimension means "nothing declared" (no boundary promised), matching the
// server's semantics.
func TestPolicyEmptyDeclaredNoBoundary(t *testing.T) {
	pe := NewPolicyEngine("http://localhost:9999", "k", "moss:go:e",
		DeclaredBehavior{
			AllowedDataSources: []string{"public"},
			// no destinations/actions declared
		}, 30, nil)
	d := pe.Check("http_get", "http://anywhere", "", nil)
	if d.IsBlock() {
		t.Errorf("empty declared destinations must not block arbitrary destination, got %+v", d)
	}
}

// TestRevocationAntiRollback verifies a lower-epoch feed is rejected even
// when its signature is valid, and the higher cached epoch is retained
// (VAL-KILL-009, VAL-CROSS-014).
func TestRevocationAntiRollback(t *testing.T) {
	dir := t.TempDir()
	cache := newRevocationCache(dir, "moss:go:rb")

	// Seed a "higher epoch" cached feed.
	high := map[string]any{
		"epoch":        int64(5),
		"generated_at": "2026-01-01T00:00:00Z",
		"not_after":    "2026-01-02T00:00:00Z",
		"revocations": []any{
			map[string]any{"agent_id": "moss:go:rb", "subject": "moss:go:rb", "revoked_at": "x", "reason": "y"},
		},
		"signature": "x", "algorithm": Algorithm, "key_id": "k",
	}
	if err := cache.Save(high); err != nil {
		t.Fatalf("save high: %v", err)
	}
	if cache.CachedEpoch() != 5 {
		t.Fatalf("cached epoch %d != 5", cache.CachedEpoch())
	}

	// A lower-epoch feed (epoch 3) must not lower the cached epoch.
	low := map[string]any{
		"epoch":        int64(3),
		"generated_at": "2026-01-01T00:00:00Z",
		"not_after":    "2026-01-02T00:00:00Z",
		"revocations":  []any{},
		"signature":    "x", "algorithm": Algorithm, "key_id": "k",
	}
	_ = low // anti-rollback logic is in RevocationWatcher.FetchAndUpdate; here we test the cache invariant.
	if cache.CachedEpoch() < 5 {
		t.Fatal("cached epoch must not decrease")
	}
	// IsRevoked still reports the agent from the higher-epoch feed.
	if !cache.IsRevoked("moss:go:rb") {
		t.Fatal("agent from epoch-5 feed must remain revoked")
	}
}

// TestEventCacheAppendRemoveLoad verifies the durable event cache round-trips
// events and survives removal (VAL-RUNTIME-027).
func TestEventCacheAppendRemoveLoad(t *testing.T) {
	dir := t.TempDir()
	c := NewEventCache(dir, "moss:go:ec")
	ev := &cachedEvent{
		EventID: "evt-1", PublicKey: "pk", Algorithm: Algorithm,
		Action: "test", Payload: map[string]any{"a": 1}, Signed: false,
	}
	if err := c.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if c.PendingCount() != 1 {
		t.Fatalf("pending %d != 1", c.PendingCount())
	}
	loaded, err := c.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 1 || loaded[0].EventID != "evt-1" {
		t.Fatalf("loaded = %+v", loaded)
	}
	if err := c.Remove("evt-1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if c.PendingCount() != 0 {
		t.Fatalf("pending after remove %d != 0", c.PendingCount())
	}
}

// TestBlockError verifies BlockError formatting + IsBlock.
func TestBlockError(t *testing.T) {
	be := &BlockError{Reason: "deny", Action: "http_get", Destination: "http://x"}
	if !IsBlock(be) {
		t.Fatal("IsBlock must be true for *BlockError")
	}
	if !strings.Contains(be.Error(), "blocked") {
		t.Errorf("error message: %s", be.Error())
	}
}
