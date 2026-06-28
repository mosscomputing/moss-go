package runtime

// Heartbeat loop + lease management (dead-man's switch).
//
// A background goroutine posts POST /v1/agents/{subject}/heartbeat every
// interval seconds (default ~5s, configurable, VAL-KILL-029). The response
// carries lease_expires_at, revocation_epoch, revoked, and server_time. If
// revoked:true the SDK auto-invokes kill() (push revocation, VAL-KILL-004).
// If the API is unreachable past the cached lease TTL, the dead-man's
// switch self-terminates the process (fail-closed, VAL-KILL-005,
// VAL-CROSS-012).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// HeartbeatResponse is the body returned by POST /v1/agents/{id}/heartbeat.
type HeartbeatResponse struct {
	LeaseExpiresAt  string `json:"lease_expires_at"`
	RevocationEpoch int64  `json:"revocation_epoch"`
	Revoked         bool   `json:"revoked"`
	ServerTime      string `json:"server_time"`
}

// HeartbeatLoop posts heartbeats on a recurring cadence and tracks the
// lease for the dead-man's switch.
type HeartbeatLoop struct {
	baseURL    string
	apiKey     string
	subject    string
	interval   time.Duration
	leaseTTL   int
	httpClient *http.Client
	onRevoked  func()
	onExpired  func()

	mu              sync.Mutex
	leaseExpiresAt  time.Time
	revocationEpoch int64
	lastSuccess     time.Time
	lastResponse    *HeartbeatResponse
	firedDeadMan    bool
	requiresReg     func() bool

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewHeartbeatLoop constructs a HeartbeatLoop.
func NewHeartbeatLoop(baseURL, apiKey, subject string, interval time.Duration, leaseTTL int, client *http.Client, onRevoked, onExpired func(), requiresReg func() bool) *HeartbeatLoop {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if client == nil {
		// Short timeout so the dead-man's switch check runs promptly
		// even when the API is unreachable (fail-closed <10s).
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return &HeartbeatLoop{
		baseURL:    trimRightSlash(baseURL),
		apiKey:     apiKey,
		subject:    subject,
		interval:   interval,
		leaseTTL:   leaseTTL,
		httpClient: client,
		onRevoked:  onRevoked,
		onExpired:  onExpired,
		requiresReg: requiresReg,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// Start launches the heartbeat goroutine.
func (h *HeartbeatLoop) Start() {
	go h.run()
}

// Stop signals the loop to exit and waits up to timeout.
func (h *HeartbeatLoop) Stop(timeout time.Duration) {
	select {
	case <-h.stopCh:
	default:
		close(h.stopCh)
	}
	select {
	case <-h.doneCh:
	case <-time.After(timeout):
	}
}

// LeaseExpiresAt returns the cached lease expiry (zero if no heartbeat yet).
func (h *HeartbeatLoop) LeaseExpiresAt() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.leaseExpiresAt
}

// RevocationEpoch returns the last seen revocation epoch.
func (h *HeartbeatLoop) RevocationEpoch() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.revocationEpoch
}

// SetLeaseExpiry seeds the cached lease expiry (used by the offline
// fail-closed test to arm the dead-man's switch without a live heartbeat).
func (h *HeartbeatLoop) SetLeaseExpiry(exp time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.leaseExpiresAt = exp
}

// BeatOnce sends a single heartbeat and updates lease state. Exposed for
// tests + explicit heartbeat.
func (h *HeartbeatLoop) BeatOnce() *HeartbeatResponse {
	body := map[string]any{
		"sdk_version":  SDKVersion,
		"runtime_info": runtimeInfo(),
		"lease_ttl":    h.leaseTTL,
	}
	raw, _ := json.Marshal(body)
	url := h.baseURL + "/v1/agents/" + h.subject + "/heartbeat"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	var data HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}
	h.mu.Lock()
	h.lastSuccess = time.Now()
	h.lastResponse = &data
	h.revocationEpoch = data.RevocationEpoch
	if data.LeaseExpiresAt != "" {
		if exp, err := parseISOTime(data.LeaseExpiresAt); err == nil {
			h.leaseExpiresAt = exp
		}
	}
	revoked := data.Revoked
	h.mu.Unlock()
	if revoked && h.onRevoked != nil {
		h.onRevoked()
	}
	return &data
}

func (h *HeartbeatLoop) run() {
	defer close(h.doneCh)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		// Only heartbeat once the agent is registered (heartbeat 404s otherwise).
		if h.requiresReg == nil || h.requiresReg() {
			h.BeatOnce()
		}
		h.checkDeadMansSwitch()
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// checkDeadMansSwitch fails closed: if the API is unreachable past the
// lease TTL (plus a grace of one interval), self-terminate.
func (h *HeartbeatLoop) checkDeadMansSwitch() {
	h.mu.Lock()
	if h.firedDeadMan || h.leaseExpiresAt.IsZero() {
		h.mu.Unlock()
		return
	}
	now := time.Now()
	if now.After(h.leaseExpiresAt.Add(h.interval)) {
		h.firedDeadMan = true
		h.mu.Unlock()
		if h.onExpired != nil {
			h.onExpired()
		}
		return
	}
	h.mu.Unlock()
}

// parseISOTime parses an ISO8601 timestamp (with optional trailing Z).
func parseISOTime(s string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	}
	t := s
	if len(t) > 0 && t[len(t)-1] == 'Z' {
		// time.Parse handles Z natively for RFC3339; try as-is first.
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, t); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("runtime: cannot parse time %q", s)
}
