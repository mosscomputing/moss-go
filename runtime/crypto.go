package runtime

// ML-DSA-44 (FIPS 204) cryptographic helpers for the Go runtime SDK.
//
// Uses filippo.io/mldsa (the same library the K8s sidecar uses for offline
// feed verification) for signing events. The convention is identical to
// the Python + TS reference SDKs:
//
//	canonical = compact JSON with sorted keys (byte-identical to Python's
//	            json.dumps(payload, sort_keys=True, separators=(',',':')))
//	sig       = ML-DSA-44 pure (empty context, non-prehash) signature
//	send      canonical_payload (string) + signature (hex) + public_key
//	          (hex) + algorithm "ML-DSA-44"
//
// Cross-language interop is proven: the server's dilithium-py verifier
// accepts signatures produced by filippo.io/mldsa.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/mldsa"
)

// ML-DSA-44 parameter sizes (FIPS 204).
const (
	PublicKeySize  = 1312 // raw encoded public key
	SignatureSize  = 2420 // raw signature
	SeedSize       = 32   // secret seed (sk.Bytes())
)

// KeyPair holds an ML-DSA-44 public key (raw 1312 bytes) and secret seed
// (raw 32 bytes). The seed is sufficient to reconstruct the full
// PrivateKey via mldsa.NewPrivateKey.
type KeyPair struct {
	PublicKey []byte // 1312 bytes
	Seed      []byte // 32 bytes (the secret seed; sk.Bytes())
}

// GenerateKeyPair generates a fresh ML-DSA-44 key pair using filippo.io/mldsa.
func GenerateKeyPair() (*KeyPair, error) {
	params := mldsa.MLDSA44()
	sk, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, fmt.Errorf("runtime: mldsa keygen: %w", err)
	}
	pk := sk.Public().(*mldsa.PublicKey)
	return &KeyPair{
		PublicKey: append([]byte(nil), pk.Bytes()...),
		Seed:      append([]byte(nil), sk.Bytes()...),
	}, nil
}

// SignMessage signs message with the secret seed and returns the 2420-byte
// signature. Pure ML-DSA with an empty context (Options{}), matching the
// server's dilithium-py usage.
func SignMessage(seed, message []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("runtime: secret seed size %d != %d", len(seed), SeedSize)
	}
	params := mldsa.MLDSA44()
	sk, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, fmt.Errorf("runtime: reconstruct secret key: %w", err)
	}
	sig, err := sk.Sign(nil, message, &mldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("runtime: mldsa sign: %w", err)
	}
	return sig, nil
}

// VerifyMessage verifies an ML-DSA-44 signature over message using the raw
// 1312-byte public key. Returns true if valid.
func VerifyMessage(publicKey, message, signature []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}
	params := mldsa.MLDSA44()
	pk, err := mldsa.NewPublicKey(params, publicKey)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, message, signature, &mldsa.Options{}) == nil
}

// CanonicalJSON serializes v to compact JSON with sorted keys and HTML
// escaping disabled, byte-identical to Python's
// `json.dumps(v, sort_keys=True, separators=(',',':'))` for payloads that
// contain only strings, ints, bools, arrays, and nested maps (no floats).
//
// Go's encoding/json sorts map keys lexicographically, matching Python's
// sort_keys=True. SetEscapeHTML(false) matches Python's default (no HTML
// entity escaping). The trailing newline added by Encoder.Encode is
// trimmed to match Python's separators output.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("runtime: canonical encode: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SignPayload signs a payload (canonicalized to compact sorted JSON) and
// returns (canonical_payload string, signature hex). This is the exact
// pair sent to POST /v1/agents/{subject}/event.
func SignPayload(seed []byte, payload map[string]any) (string, string, error) {
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return "", "", err
	}
	sig, err := SignMessage(seed, canonical)
	if err != nil {
		return "", "", err
	}
	return string(canonical), hex.EncodeToString(sig), nil
}

// DecodePublicKeyHex decodes a hex-encoded ML-DSA-44 public key (2624 hex
// chars -> 1312 bytes) and validates its length.
func DecodePublicKeyHex(hexKey string) ([]byte, error) {
	pk, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("runtime: decode public key hex: %w", err)
	}
	if len(pk) != PublicKeySize {
		return nil, fmt.Errorf("runtime: public key size %d != %d", len(pk), PublicKeySize)
	}
	return pk, nil
}

// Keystore is a persistent, idempotent ML-DSA-44 key store keyed by agent
// subject. Re-running the same agent subject loads the same keypair,
// preserving the registered public_key (VAL-RUNTIME-021). Keys are stored
// as hex in a per-subject JSON file.
type Keystore struct {
	subject string
	path    string

	mu   sync.Mutex
	pk   []byte
	seed []byte
}

// NewKeystore constructs a Keystore rooted at keystoreDir for the given
// agent subject. The key file path mirrors the Python SDK layout:
// <keystoreDir>/<ns>/<name>.json where subject "moss:ns:name" splits into
// ns/name; other subjects land under "agent/".
func NewKeystore(subject, keystoreDir string) *Keystore {
	ns, name := "agent", strings.ReplaceAll(subject, ":", "_")
	if parts := strings.SplitN(subject, ":", 3); len(parts) == 3 && parts[0] == "moss" {
		ns, name = parts[1], parts[2]
	}
	return &Keystore{
		subject: subject,
		path:    filepath.Join(keystoreDir, ns, name+".json"),
	}
}

// LoadOrCreate loads the existing keypair from disk or generates + persists
// a new one (idempotent). Returns the public key + secret seed.
func (k *Keystore) LoadOrCreate() ([]byte, []byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pk != nil && k.seed != nil {
		return k.pk, k.seed, nil
	}
	if data, err := os.ReadFile(k.path); err == nil {
		var rec struct {
			Subject    string `json:"subject"`
			Algorithm  string `json:"algorithm"`
			PublicKey  string `json:"public_key"`
			SecretSeed string `json:"secret_seed"`
		}
		if err := json.Unmarshal(data, &rec); err == nil {
			pk, err := hex.DecodeString(rec.PublicKey)
			if err == nil && len(pk) == PublicKeySize {
				seed, err := hex.DecodeString(rec.SecretSeed)
				if err == nil && len(seed) == SeedSize {
					k.pk, k.seed = pk, seed
					return pk, seed, nil
				}
			}
		}
		// fall through to regenerate on malformed store
	}
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	k.pk, k.seed = kp.PublicKey, kp.Seed
	if err := k.saveLocked(); err != nil {
		return nil, nil, err
	}
	return k.pk, k.seed, nil
}

func (k *Keystore) saveLocked() error {
	if k.pk == nil || k.seed == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return fmt.Errorf("runtime: keystore mkdir: %w", err)
	}
	rec := map[string]string{
		"subject":     k.subject,
		"algorithm":   Algorithm,
		"public_key":  hex.EncodeToString(k.pk),
		"secret_seed": hex.EncodeToString(k.seed),
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("runtime: keystore marshal: %w", err)
	}
	if err := os.WriteFile(k.path, data, 0o600); err != nil {
		return fmt.Errorf("runtime: keystore write: %w", err)
	}
	return nil
}

// PublicKey returns the raw 1312-byte public key.
func (k *Keystore) PublicKey() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.pk
}

// PublicKeyHex returns the hex-encoded public key (2624 chars).
func (k *Keystore) PublicKeyHex() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return hex.EncodeToString(k.pk)
}

// Seed returns the raw 32-byte secret seed.
func (k *Keystore) Seed() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.seed
}

// randNonce returns 8 random hex bytes (16 hex chars), matching the Python
// SDK's secrets.token_hex(8).
func randNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a zero nonce (should never happen with crypto/rand).
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
