package runtime

// Offline signed revocation cache (CRL-style).
//
// The SDK periodically fetches GET /v1/revocations?since=epoch, verifies
// the ML-DSA-44 signature offline with the embedded MOSS public key (via
// filippo.io/mldsa MLDSA44), persists the feed locally, and rejects
// lower-epoch feeds (anti-rollback, VAL-KILL-009). When the API is down
// the SDK enforces revocation from the cached feed (VAL-KILL-010). The
// MOSS public key for offline verification is fetched once from the API's
// /.well-known/moss-keys/{key_id} endpoint and cached.
//
// Revocation epoch consistency across all three SDKs is asserted by
// VAL-CROSS-014: the same feed produces the same cached epoch + revoked
// set, and each rejects the same lower-epoch rollback feed.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// RevocationWatcher fetches + verifies the signed revocation feed.
type RevocationWatcher struct {
	baseURL       string
	apiKey        string
	subject       string
	cache         *revocationCache
	refreshPeriod time.Duration
	httpClient    *http.Client
	onRevoked     func()

	mu        sync.Mutex
	mossPK    []byte // raw 1312-byte MOSS public key
	cachedFid string // last fetched key_id

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewRevocationWatcher constructs a RevocationWatcher.
func NewRevocationWatcher(baseURL, apiKey, subject string, cache *revocationCache, refresh time.Duration, client *http.Client, onRevoked func()) *RevocationWatcher {
	if refresh <= 0 {
		refresh = 10 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &RevocationWatcher{
		baseURL:       trimRightSlash(baseURL),
		apiKey:        apiKey,
		subject:       subject,
		cache:         cache,
		refreshPeriod: refresh,
		httpClient:    client,
		onRevoked:     onRevoked,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Start launches the watcher goroutine.
func (w *RevocationWatcher) Start() {
	go w.run()
}

// Stop signals the watcher to exit and waits up to timeout.
func (w *RevocationWatcher) Stop(timeout time.Duration) {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	select {
	case <-w.doneCh:
	case <-time.After(timeout):
	}
}

// MossPublicKey returns the cached MOSS public key (raw bytes) or nil.
func (w *RevocationWatcher) MossPublicKey() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mossPK
}

// IsSelfRevoked reports whether this agent appears in the cached feed.
func (w *RevocationWatcher) IsSelfRevoked() bool {
	return w.cache.IsRevoked(w.subject)
}

// IsRevoked reports whether the given agent id/subject is revoked per the
// cached feed.
func (w *RevocationWatcher) IsRevoked(agentIDOrSubject string) bool {
	return w.cache.IsRevoked(agentIDOrSubject)
}

// CachedEpoch returns the highest verified revocation epoch seen so far.
func (w *RevocationWatcher) CachedEpoch() int64 {
	return w.cache.CachedEpoch()
}

// FetchAndUpdate fetches the revocation feed, verifies + persists it
// (anti-rollback). Returns the verified feed (or the cached feed on
// rollback). Exposed for tests + explicit refresh.
func (w *RevocationWatcher) FetchAndUpdate() (map[string]any, error) {
	if w.mossPK == nil {
		if err := w.FetchMossPublicKey(); err != nil {
			return nil, err
		}
	}
	since := w.cache.CachedEpoch()
	url := fmt.Sprintf("%s/v1/revocations?since=%d", w.baseURL, since)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		time.Sleep(time.Second)
		return w.FetchAndUpdate()
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("runtime: revocations HTTP %d: %s", resp.StatusCode, truncStr(string(body), 200))
	}
	var feed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("runtime: parse revocations feed: %w", err)
	}
	if !w.VerifyFeed(feed) {
		return nil, fmt.Errorf("runtime: revocation feed signature verification failed")
	}
	epoch := epochOf(feed)
	if epoch < w.cache.CachedEpoch() {
		// Anti-rollback: reject lower-epoch feed (VAL-KILL-009).
		cached, _ := w.cache.Load()
		return cached, fmt.Errorf("runtime: rollback rejected (feed epoch %d < cached %d)", epoch, w.cache.CachedEpoch())
	}
	if err := w.cache.Save(feed); err != nil {
		return nil, err
	}
	// Push notification: if *we* are now revoked, fire the callback.
	if w.onRevoked != nil && w.cache.IsRevoked(w.subject) {
		w.onRevoked()
	}
	return feed, nil
}

// VerifyFeed verifies the ML-DSA-44 signature over the canonical feed
// payload using the cached MOSS public key.
func (w *RevocationWatcher) VerifyFeed(feed map[string]any) bool {
	sigField, _ := feed["signature"].(string)
	alg, _ := feed["algorithm"].(string)
	if sigField == "" || alg != Algorithm {
		return false
	}
	if w.mossPK == nil {
		return false
	}
	payload := map[string]any{
		"epoch":         feed["epoch"],
		"generated_at":  feed["generated_at"],
		"not_after":     feed["not_after"],
		"revocations":   feed["revocations"],
	}
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return false
	}
	// The server encodes the signature as base64.
	sigBytes, err := base64.StdEncoding.DecodeString(sigField)
	if err != nil {
		sigBytes, err = hex.DecodeString(sigField)
		if err != nil {
			return false
		}
	}
	return VerifyMessage(w.mossPK, canonical, sigBytes)
}

// FetchMossPublicKey fetches the MOSS signing public key once for offline
// verification, using the well-known key discovery endpoints. The key_id
// is read from a bootstrap revocation feed fetch (or the pinned key_id).
func (w *RevocationWatcher) FetchMossPublicKey() error {
	w.mu.Lock()
	if w.mossPK != nil {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()

	keyID := ""
	// Bootstrap: fetch the feed once to discover the key_id.
	feed, err := w.fetchFeedRaw(0)
	if err == nil {
		if kid, ok := feed["key_id"].(string); ok {
			keyID = kid
		}
		// Accept the bootstrap epoch as the baseline (do not verify yet).
		w.cache.SetCachedEpoch(epochOf(feed) - 1)
		w.cachedFid = keyID
	}
	if keyID == "" {
		return fmt.Errorf("runtime: could not discover revocation key_id")
	}
	pkHex, err := w.fetchWellKnownKey(keyID)
	if err != nil {
		return err
	}
	pk, err := DecodePublicKeyHex(pkHex)
	if err != nil {
		return fmt.Errorf("runtime: decode MOSS public key: %w", err)
	}
	w.mu.Lock()
	w.mossPK = pk
	w.mu.Unlock()
	return nil
}

func (w *RevocationWatcher) fetchFeedRaw(since int64) (map[string]any, error) {
	url := fmt.Sprintf("%s/v1/revocations?since=%d", w.baseURL, since)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("runtime: revocations HTTP %d: %s", resp.StatusCode, truncStr(string(body), 200))
	}
	var feed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}
	return feed, nil
}

func (w *RevocationWatcher) fetchWellKnownKey(keyID string) (string, error) {
	url := w.baseURL + "/.well-known/moss-keys/" + keyID
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("runtime: well-known key HTTP %d: %s", resp.StatusCode, truncStr(string(body), 200))
	}
	var wk struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return "", err
	}
	if wk.PublicKey == "" {
		return "", fmt.Errorf("runtime: well-known key %s returned empty public_key", keyID)
	}
	return wk.PublicKey, nil
}

func (w *RevocationWatcher) run() {
	defer close(w.doneCh)
	ticker := time.NewTicker(w.refreshPeriod)
	defer ticker.Stop()
	// One immediate check on startup.
	if _, err := w.FetchAndUpdate(); err != nil {
		// Non-fatal: transient API errors; cache + dead-man's switch handle offline.
		_ = err
	}
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			if _, err := w.FetchAndUpdate(); err != nil {
				_ = err
			}
		}
	}
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
