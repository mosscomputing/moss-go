package moss

import (
	"testing"
)

// TestSignSignatureSize verifies ML-DSA-44 signature and key sizes (VAL-SDK-006).
func TestSignSignatureSize(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if len(kp.PublicKey) != PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(kp.PublicKey), PublicKeySize)
	}
	if PublicKeySize != 1312 {
		t.Errorf("PublicKeySize constant: got %d, want 1312", PublicKeySize)
	}

	if len(kp.SecretKey) != SecretKeySize {
		t.Errorf("secret key size: got %d, want %d", len(kp.SecretKey), SecretKeySize)
	}
	if SecretKeySize != 2560 {
		t.Errorf("SecretKeySize constant: got %d, want 2560", SecretKeySize)
	}

	payload := []byte("canonical event payload")
	sig, err := Sign(payload, kp.SecretKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != SignatureSize {
		t.Errorf("signature size: got %d, want %d", len(sig), SignatureSize)
	}
	if SignatureSize != 2420 {
		t.Errorf("SignatureSize constant: got %d, want 2420", SignatureSize)
	}
}

// TestVerifyHonestAndTampered verifies honest signatures pass and tampered ones fail (VAL-SDK-007).
func TestVerifyHonestAndTampered(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	payload := []byte("agent action: transfer $500")
	sig, err := Sign(payload, kp.SecretKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Honest signature must verify
	verified := Verify(payload, kp.PublicKey, sig)
	if !verified {
		t.Error("Verify should return true for an honest signature")
	}

	// Bit-flipped signature must be rejected
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0x01
	verified = Verify(payload, kp.PublicKey, tamperedSig)
	if verified {
		t.Error("Verify should return false for a bit-flipped signature")
	}
}

// TestVerifyRejectsZeroSignature verifies all-zeros 2420-byte signature is rejected (VAL-SDK-008).
func TestVerifyRejectsZeroSignature(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	payload := []byte("some payload")
	zeroSig := make([]byte, SignatureSize) // all zeros

	verified := Verify(payload, kp.PublicKey, zeroSig)
	if verified {
		t.Error("Verify must reject an all-zeros 2420-byte signature")
	}
}
