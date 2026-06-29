// Package sidecar implements the MOSS Kubernetes sidecar that watches the
// revocation feed on behalf of a non-embedding agent and terminates that
// agent's process/pod when MOSS revokes it.
//
// This file provides ML-DSA-44 (FIPS 204) signature verification using
// filippo.io/mldsa, matching the cross-language convention: empty context,
// pure (non-prehash) ML-DSA, raw public-key bytes exchanged as hex, canonical
// JSON payload (sorted keys, compact separators).
package sidecar

import (
	"encoding/hex"
	"fmt"

	"filippo.io/mldsa"
)

// MLD SA-44 parameter sizes (FIPS 204).
const (
	MLDSA44PublicKeySize  = 1312
	MLDSA44SignatureSize  = 2420
	MLDSA44Algorithm      = "ML-DSA-44"
)

// VerifyMLDSA44 verifies an ML-DSA-44 signature over message using publicKey.
// publicKey must be the raw 1312-byte encoded public key. signature must be
// the raw 2420-byte signature. Verification uses an empty context and the
// pure (non-prehash) ML-DSA scheme, matching the MOSS cross-language
// convention verified against the server's dilithium-py verifier.
func VerifyMLDSA44(publicKey, message, signature []byte) (bool, error) {
	if len(publicKey) != MLDSA44PublicKeySize {
		return false, fmt.Errorf("sidecar: public key size %d != %d", len(publicKey), MLDSA44PublicKeySize)
	}
	if len(signature) != MLDSA44SignatureSize {
		return false, fmt.Errorf("sidecar: signature size %d != %d", len(signature), MLDSA44SignatureSize)
	}

	params := mldsa.MLDSA44()
	pk, err := mldsa.NewPublicKey(params, publicKey)
	if err != nil {
		return false, fmt.Errorf("sidecar: decode public key: %w", err)
	}

	// Pure ML-DSA with an empty context. Options{} leaves Context empty and
	// does not request a prehash, which matches the server's
	// ML_DSA_44.sign/_verify (dilithium-py) usage. Verify returns nil on
	// success and a non-nil error (mldsa.ErrVerification) on failure.
	if err := mldsa.Verify(pk, message, signature, &mldsa.Options{}); err != nil {
		return false, nil
	}
	return true, nil
}

// DecodePublicKeyHex decodes a hex-encoded ML-DSA-44 public key (2624 hex
// chars -> 1312 bytes) and validates its length.
func DecodePublicKeyHex(hexKey string) ([]byte, error) {
	pk, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("sidecar: decode public key hex: %w", err)
	}
	if len(pk) != MLDSA44PublicKeySize {
		return nil, fmt.Errorf("sidecar: public key size %d != %d", len(pk), MLDSA44PublicKeySize)
	}
	return pk, nil
}
