package sidecar

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Revocation is a single entry in the MOSS revocation feed.
type Revocation struct {
	AgentID   string `json:"agent_id"`
	Subject   string `json:"subject"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason"`
}

// RevocationFeed is the MOSS signed revocation feed (GET /v1/revocations).
// The first four fields form the signed payload; Signature/Algorithm/KeyID
// are the detached signature metadata.
type RevocationFeed struct {
	Epoch        int64         `json:"epoch"`
	GeneratedAt  string        `json:"generated_at"`
	NotAfter     string        `json:"not_after"`
	Revocations  []Revocation  `json:"revocations"`
	Signature    string        `json:"signature"`
	Algorithm    string        `json:"algorithm"`
	KeyID        string        `json:"key_id"`
}

// WellKnownKey is the public-key response from
// /.well-known/moss-keys/{key_id}.
type WellKnownKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // hex-encoded 1312-byte key
}

// FetchRevocationFeed fetches the signed revocation feed from the API. The
// `since` parameter requests only entries added after the given epoch; pass 0
// to fetch the full current list.
func FetchRevocationFeed(cfg Config, since int64) (*RevocationFeed, error) {
	url := strings.TrimRight(cfg.APIURL, "/") + fmt.Sprintf("/v1/revocations?since=%d", since)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("sidecar: build revocations request: %w", err)
	}
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar: revocations request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sidecar: read revocations body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sidecar: revocations HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var feed RevocationFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("sidecar: parse revocations feed: %w", err)
	}
	return &feed, nil
}

// FetchPublicKey fetches the MOSS public key (hex) for keyID from the API's
// well-known endpoint. No authentication required.
func FetchPublicKey(cfg Config, keyID string) (string, error) {
	url := strings.TrimRight(cfg.APIURL, "/") + "/.well-known/moss-keys/" + keyID
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("sidecar: build well-known key request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("sidecar: well-known key request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("sidecar: read well-known key body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sidecar: well-known key HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var wk WellKnownKey
	if err := json.Unmarshal(body, &wk); err != nil {
		return "", fmt.Errorf("sidecar: parse well-known key: %w", err)
	}
	if wk.PublicKey == "" {
		return "", fmt.Errorf("sidecar: well-known key %s returned empty public_key", keyID)
	}
	return wk.PublicKey, nil
}

// signedPayload builds the canonical bytes that the server signed for the
// feed. The signed payload is exactly {epoch, generated_at, not_after,
// revocations[]} in compact, sorted-key JSON.
func (f *RevocationFeed) signedPayload() ([]byte, error) {
	// Re-encode the revocations slice through a generic slice of maps so
	// that json.Marshal produces sorted keys for each entry (struct encoding
	// already follows field order, but building a map guarantees the same
	// shape the server used: a list of dicts).
	revs := make([]map[string]any, 0, len(f.Revocations))
	for _, r := range f.Revocations {
		revs = append(revs, map[string]any{
			"agent_id":   r.AgentID,
			"subject":    r.Subject,
			"revoked_at": r.RevokedAt,
			"reason":     r.Reason,
		})
	}
	payload := map[string]any{
		"epoch":        f.Epoch,
		"generated_at": f.GeneratedAt,
		"not_after":    f.NotAfter,
		"revocations":  revs,
	}
	return canonicalJSON(payload)
}

// Verify verifies the feed's ML-DSA-44 signature against the provided MOSS
// public key (raw 1312 bytes) and checks the algorithm field. Returns nil if
// the signature is valid.
func (f *RevocationFeed) Verify(publicKey []byte) error {
	if f.Algorithm != MLDSA44Algorithm {
		return fmt.Errorf("sidecar: feed algorithm %q != %q", f.Algorithm, MLDSA44Algorithm)
	}
	if f.Signature == "" {
		return fmt.Errorf("sidecar: feed has empty signature")
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return fmt.Errorf("sidecar: decode feed signature: %w", err)
	}
	if len(sig) != MLDSA44SignatureSize {
		return fmt.Errorf("sidecar: feed signature size %d != %d", len(sig), MLDSA44SignatureSize)
	}
	msg, err := f.signedPayload()
	if err != nil {
		return fmt.Errorf("sidecar: build signed payload: %w", err)
	}
	ok, err := VerifyMLDSA44(publicKey, msg, sig)
	if err != nil {
		return fmt.Errorf("sidecar: verify feed: %w", err)
	}
	if !ok {
		return fmt.Errorf("sidecar: revocation feed signature verification FAILED")
	}
	return nil
}

// IsRevoked reports whether the given agent (by id and/or subject) appears in
// the feed's revocation list.
func (f *RevocationFeed) IsRevoked(agentID, agentSubject string) bool {
	for _, r := range f.Revocations {
		if agentID != "" && (strings.EqualFold(r.AgentID, agentID) || strings.EqualFold(r.Subject, agentID)) {
			return true
		}
		if agentSubject != "" && strings.EqualFold(r.Subject, agentSubject) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
