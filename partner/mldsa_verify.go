package partner

import (
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// verifyMLDSA44 verifies an ML-DSA-44 signature over msg against the public
// key bytes (1312-byte raw public key). Used by ComplianceService.VerifyReport
// for offline compliance-PDF signature verification. Signing is server-side
// only — the SDK only verifies.
func verifyMLDSA44(msg, publicKey, signature []byte) bool {
	if len(publicKey) != mldsa44.PublicKeySize || len(signature) != mldsa44.SignatureSize {
		return false
	}
	var pk mldsa44.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa44.Verify(&pk, msg, nil, signature)
}
