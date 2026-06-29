package runtime

// Signed event logging for governed actions.
//
// Events are signed with ML-DSA-44 over canonical JSON and POSTed to
// /v1/agents/{subject}/event. Logging is async/batched and non-blocking on
// the hot path: when the API is reachable the event is delivered in a
// background goroutine; when the API is unreachable the event is durably
// cached locally and synced on reconnect (VAL-RUNTIME-019/020/027).
//
// The POST body MUST include the original payload dict alongside
// canonical_payload + signature + public_key + algorithm, so the server
// stores data_source/destination in audit_logs.parameters.payload for
// observed-behavior analysis (VAL-RUNTIME-013, VAL-CROSS-008).
//
// Design: the on-disk EventCache is the single source of truth (the queue).
// Log() appends to the cache and signals the worker; the worker loads all
// pending events from the cache, signs + POSTs each, and removes successful
// ones. This avoids the duplication race a separate in-memory channel would
// introduce (an event re-queued from the cache while still in the channel
// would be POSTed twice, with the duplicate rejected by server dedup and
// left stranded in the cache).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventLogger is an async, batched, durable signed-event logger.
type EventLogger struct {
	baseURL       string
	apiKey        string
	subject       string
	keystore      *Keystore
	cache         *EventCache
	batchInterval time.Duration
	autoRegister  bool
	publicKeyHex  string
	httpClient    *http.Client

	mu         sync.Mutex
	registered bool

	notifyCh chan struct{}
	flushCh  chan chan bool
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewEventLogger constructs an EventLogger.
func NewEventLogger(baseURL, apiKey, subject string, keystore *Keystore, cache *EventCache, batchInterval time.Duration, client *http.Client) *EventLogger {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if batchInterval <= 0 {
		batchInterval = 500 * time.Millisecond
	}
	return &EventLogger{
		baseURL:       trimRightSlash(baseURL),
		apiKey:        apiKey,
		subject:       subject,
		keystore:      keystore,
		cache:         cache,
		batchInterval: batchInterval,
		autoRegister:  true,
		publicKeyHex:  keystore.PublicKeyHex(),
		httpClient:    client,
		notifyCh:      make(chan struct{}, 1),
		flushCh:       make(chan chan bool, 16),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Start launches the background worker. It picks up persisted events from
// the cache (abrupt-crash recovery) on the first tick.
func (e *EventLogger) Start() {
	go e.run()
}

// Stop signals the worker to drain + exit and waits up to timeout.
func (e *EventLogger) Stop(timeout time.Duration) {
	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}
	select {
	case <-e.doneCh:
	case <-time.After(timeout):
	}
}

func (e *EventLogger) signal() {
	select {
	case e.notifyCh <- struct{}{}:
	default:
	}
}

// Log queues an event for async signing + delivery. Returns the event_id.
// Signing happens in the background worker, NOT on the hot path, so the
// calling goroutine is not blocked by crypto (perf budget). The unsigned
// event is persisted immediately so it survives an abrupt SIGKILL.
func (e *EventLogger) Log(payload map[string]any, action string) string {
	eventID := uuid.NewString()
	nonce := randNonce()
	full := map[string]any{}
	for k, v := range payload {
		full[k] = v
	}
	full["agent_id"] = e.subject
	full["event_id"] = eventID
	full["nonce"] = nonce
	full["ts"] = time.Now().Unix()
	if _, ok := full["action"]; !ok && action != "" {
		full["action"] = action
	}

	e.mu.Lock()
	autoReg := e.autoRegister && !e.registered
	e.mu.Unlock()

	ev := &cachedEvent{
		EventID:      eventID,
		PublicKey:    e.publicKeyHex,
		Algorithm:    Algorithm,
		AutoRegister: autoReg,
		Action:       action,
		Payload:      full,
		Signed:       false,
	}
	_ = e.cache.Append(ev)
	e.signal()
	return eventID
}

// Flush blocks until the cache is drained or timeout elapses. Performs up
// to a few drain cycles to cover reconnect-sync of persisted events.
func (e *EventLogger) Flush(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if e.cache.PendingCount() == 0 {
			return true
		}
		if !time.Now().Before(deadline) {
			return e.cache.PendingCount() == 0
		}
		ack := make(chan bool, 1)
		remaining := time.Until(deadline)
		select {
		case e.flushCh <- ack:
		default:
			e.signal()
			select {
			case e.flushCh <- ack:
			case <-time.After(remaining):
				return e.cache.PendingCount() == 0
			}
		}
		select {
		case ok := <-ack:
			if ok || !time.Now().Before(deadline) {
				return ok
			}
		case <-time.After(remaining):
			return e.cache.PendingCount() == 0
		}
	}
}

// PendingCount returns the number of events currently in the durable cache.
func (e *EventLogger) PendingCount() int { return e.cache.PendingCount() }

// IsRegistered reports whether the agent has successfully auto-registered
// (first event returned verified:true).
func (e *EventLogger) IsRegistered() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.registered
}

// MarkRegistered forces the registered flag on.
func (e *EventLogger) MarkRegistered() {
	e.mu.Lock()
	e.registered = true
	e.mu.Unlock()
}

// WriteFinalRecord writes a final signed forensic record (used by kill()).
func (e *EventLogger) WriteFinalRecord(reason string, flushTimeout time.Duration) string {
	payload := map[string]any{
		"action":   "MOSS_KILL",
		"agent_id": e.subject,
		"reason":   reason,
		"final":    true,
	}
	eid := e.Log(payload, "MOSS_KILL")
	e.Flush(flushTimeout)
	return eid
}

// run is the background worker loop. The cache is the single source of
// truth: each cycle loads all pending events, signs + POSTs them, and
// removes successful ones.
func (e *EventLogger) run() {
	defer close(e.doneCh)
	ticker := time.NewTicker(e.batchInterval)
	defer ticker.Stop()
	for {
		e.drainCycle()
		select {
		case <-e.stopCh:
			e.drainCycle()
			return
		case <-e.notifyCh:
		case <-ticker.C:
		case ack := <-e.flushCh:
			// Drain a few times to cover reconnect-sync.
			for i := 0; i < 3; i++ {
				e.drainCycle()
				if e.cache.PendingCount() == 0 {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			ack <- (e.cache.PendingCount() == 0)
		}
	}
}

// drainCycle loads all pending events from the cache, signs + POSTs each,
// and removes successful ones. Failed events remain in the cache for the
// next cycle (graceful degradation + abrupt-crash survival).
func (e *EventLogger) drainCycle() {
	events, err := e.cache.Load()
	if err != nil || len(events) == 0 {
		return
	}
	url := e.baseURL + "/v1/agents/" + e.subject + "/event"
	for _, ev := range events {
		if !ev.Signed {
			canonical, sigHex, err := SignPayload(e.keystore.Seed(), ev.Payload)
			if err != nil {
				continue // keep cached for retry
			}
			ev.CanonicalPayload = canonical
			ev.Signature = sigHex
			ev.Signed = true
			// Re-persist the signed form so recovery has the signature.
			_ = e.cache.Remove(ev.EventID)
			_ = e.cache.Append(ev)
		}
		body := map[string]any{
			"canonical_payload": ev.CanonicalPayload,
			"signature":         ev.Signature,
			"public_key":        ev.PublicKey,
			"algorithm":         ev.Algorithm,
			"auto_register":     ev.AutoRegister,
		}
		// Include the original payload dict so the server stores
		// data_source/destination in audit_logs.parameters.payload.
		if ev.Payload != nil {
			body["payload"] = ev.Payload
		}
		if ev.Action != "" {
			body["action"] = ev.Action
		}
		if eid, ok := ev.Payload["event_id"]; ok {
			body["event_id"] = eid
		}
		if nonce, ok := ev.Payload["nonce"]; ok {
			body["nonce"] = nonce
		}
		raw, err := json.Marshal(body)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := e.httpClient.Do(req)
		if err != nil {
			continue // network error -> keep cached for retry
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var data struct {
				Verified bool `json:"verified"`
			}
			if json.Unmarshal(respBody, &data) == nil && data.Verified {
				_ = e.cache.Remove(ev.EventID)
				e.mu.Lock()
				if !e.registered {
					e.registered = true
				}
				e.mu.Unlock()
				continue
			}
			// verified:false -> keep cached (will retry)
		} else if resp.StatusCode == http.StatusForbidden {
			// Agent revoked -> cannot log further; drop to avoid loops.
			_ = e.cache.Remove(ev.EventID)
			continue
		}
		// 4xx/5xx -> keep cached for retry
	}
}

// EnsureRegistered triggers an explicit registration event if nothing has
// been logged yet, then waits for it to land.
func (e *EventLogger) EnsureRegistered(timeout time.Duration) bool {
	if e.IsRegistered() {
		return true
	}
	if e.PendingCount() == 0 {
		e.Log(map[string]any{
			"action":   "MOSS_REGISTER",
			"agent_id": e.subject,
		}, "MOSS_REGISTER")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		e.Flush(time.Second)
		if e.IsRegistered() {
			return true
		}
	}
	return e.IsRegistered()
}

// SyncDeclaredBehavior persists declared behavior to MOSS via PATCH
// (idempotent, with retries).
func SyncDeclaredBehavior(baseURL, apiKey, subject string, declared DeclaredBehavior, client *http.Client) error {
	body := map[string]any{
		"declared_capabilities": declared.DeclaredCapabilities,
		"allowed_data_sources":   declared.AllowedDataSources,
		"allowed_actions":        declared.AllowedActions,
		"allowed_destinations":   declared.AllowedDestinations,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("runtime: marshal declared behavior: %w", err)
	}
	url := trimRightSlash(baseURL) + "/v1/agents/" + subject + "/declared-behavior"
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			time.Sleep(time.Second)
			continue
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("runtime: declared-behavior sync failed after retries")
}
