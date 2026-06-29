package sidecar

import (
	"os"
	"testing"
)

// TestVerifyRealRevocationFeed verifies that filippo.io/mldsa can verify the
// real MOSS revocation feed signature produced by the server's dilithium-py
// signer. The fixtures are captured from a running local API (see
// sidecar/verify_test.go comment) and prove cross-language interop.
//
// Regenerate fixtures against a running API on :3100:
//
//	curl -s -H "Authorization: Bearer moss_live_seed_owner_LOCAL_DEMO_ONLY" \
//	  "http://localhost:3100/v1/revocations?since=0" > /tmp/feed.json
//	KID=$(python3 -c "import json;print(json.load(open('/tmp/feed.json'))['key_id'])")
//	curl -s "http://localhost:3100/.well-known/moss-keys/$KID" > /tmp/key.json
//	python3 -c "import json,base64; f=json.load(open('/tmp/feed.json')); \
//	  k=json.load(open('/tmp/key.json')); p={'epoch':f['epoch'], \
//	  'generated_at':f['generated_at'],'not_after':f['not_after'], \
//	  'revocations':f['revocations']}; \
//	  c=json.dumps(p,sort_keys=True,separators=(',',':')); \
//	  open('/tmp/canonical.json','wb').write(c.encode()); \
//	  open('/tmp/sig.bin','wb').write(base64.b64decode(f['signature'])); \
//	  open('/tmp/pk.bin','wb').write(bytes.fromhex(k['public_key']))"
//
// This is a live-fixture test gated on the presence of /tmp/pk.bin so it is
// skipped in CI environments without a running API.
func TestVerifyRealRevocationFeed(t *testing.T) {
	pkBytes, err := os.ReadFile("/tmp/pk.bin")
	if err != nil {
		t.Skipf("missing /tmp/pk.bin fixture: %v", err)
	}
	msg, err := os.ReadFile("/tmp/canonical.json")
	if err != nil {
		t.Skipf("missing /tmp/canonical.json fixture: %v", err)
	}
	sig, err := os.ReadFile("/tmp/sig.bin")
	if err != nil {
		t.Skipf("missing /tmp/sig.bin fixture: %v", err)
	}

	if len(pkBytes) != MLDSA44PublicKeySize {
		t.Fatalf("public key fixture size %d != %d", len(pkBytes), MLDSA44PublicKeySize)
	}
	if len(sig) != MLDSA44SignatureSize {
		t.Fatalf("signature fixture size %d != %d", len(sig), MLDSA44SignatureSize)
	}

	ok, err := VerifyMLDSA44(pkBytes, msg, sig)
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if !ok {
		t.Fatal("ML-DSA-44 verification of real revocation feed FAILED; expected true")
	}
}

// TestVerifyRejectsTamperedMessage ensures a modified canonical payload is
// rejected (tamper-evidence).
func TestVerifyRejectsTamperedMessage(t *testing.T) {
	pkBytes, err := os.ReadFile("/tmp/pk.bin")
	if err != nil {
		t.Skipf("missing /tmp/pk.bin fixture: %v", err)
	}
	msg, err := os.ReadFile("/tmp/canonical.json")
	if err != nil {
		t.Skipf("missing /tmp/canonical.json fixture: %v", err)
	}
	sig, err := os.ReadFile("/tmp/sig.bin")
	if err != nil {
		t.Skipf("missing /tmp/sig.bin fixture: %v", err)
	}

	// Flip a byte in the canonical payload.
	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[len(tampered)-10] ^= 0xFF

	ok, err := VerifyMLDSA44(pkBytes, tampered, sig)
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if ok {
		t.Fatal("tampered canonical payload was accepted; expected rejection")
	}
}

// TestDecodePublicKeyHex validates the hex decoder and size check.
func TestDecodePublicKeyHex(t *testing.T) {
	pkBytes, err := os.ReadFile("/tmp/pk.bin")
	if err != nil {
		t.Skipf("missing /tmp/pk.bin fixture: %v", err)
	}
	hexKey := hexEncode(pkBytes)
	decoded, err := DecodePublicKeyHex(hexKey)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded) != MLDSA44PublicKeySize {
		t.Fatalf("decoded size %d != %d", len(decoded), MLDSA44PublicKeySize)
	}
}

func hexEncode(b []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = chars[v>>4]
		out[i*2+1] = chars[v&0x0F]
	}
	return string(out)
}
