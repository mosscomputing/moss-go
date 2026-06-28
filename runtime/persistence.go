package runtime

// On-disk durable caches for events (offline + abrupt-crash recovery) and
// the signed revocation feed. Mirrors the Python SDK persistence layer so
// the Go SDK satisfies VAL-RUNTIME-019/020/027 (offline cache + reconnect
// sync + abrupt-crash survival) and VAL-KILL-008/009/010 (offline signed
// revocation cache + anti-rollback + fail-closed).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// cachedEvent is the on-disk representation of a queued event (signed or
// unsigned). It mirrors the Python/TS EventCache record.
type cachedEvent struct {
	EventID          string         `json:"event_id"`
	PublicKey        string         `json:"public_key"`
	Algorithm        string         `json:"algorithm"`
	AutoRegister     bool           `json:"auto_register"`
	Action           string         `json:"action,omitempty"`
	Payload          map[string]any `json:"payload"`
	Signed           bool           `json:"signed"`
	CanonicalPayload string         `json:"canonical_payload,omitempty"`
	Signature        string         `json:"signature,omitempty"`
}

// EventCache is a durable, append-only-on-disk queue of pending events.
// Events are persisted immediately on log() (so they survive SIGKILL) and
// removed once the server accepts them (verified:true).
type EventCache struct {
	mu   sync.Mutex
	path string
}

// NewEventCache constructs an EventCache rooted at dir for the given
// agent subject. The cache file is <dir>/events-<safe-subject>.jsonl
// (one JSON event per line).
func NewEventCache(dir, subject string) *EventCache {
	return &EventCache{path: filepath.Join(dir, "events-"+safeSubject(subject)+".jsonl")}
}

// Append persists ev to the cache file (creating the file + parent dirs).
func (c *EventCache) Append(ev *cachedEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("runtime: event cache mkdir: %w", err)
	}
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("runtime: event cache open: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(ev)
}

// Remove removes the event with the given event_id from the cache file
// (rewrite-without). Idempotent.
func (c *EventCache) Remove(eventID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("runtime: event cache read: %w", err)
	}
	var kept []*cachedEvent
	for _, line := range splitJSONL(data) {
		if len(line) == 0 {
			continue
		}
		var ev cachedEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.EventID == eventID {
			continue
		}
		kept = append(kept, &ev)
	}
	return c.rewriteLocked(kept)
}

// Load returns all currently-persisted events (in append order).
func (c *EventCache) Load() ([]*cachedEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("runtime: event cache read: %w", err)
	}
	var out []*cachedEvent
	for _, line := range splitJSONL(data) {
		if len(line) == 0 {
			continue
		}
		var ev cachedEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		out = append(out, &ev)
	}
	return out, nil
}

// PendingCount returns the number of events currently in the cache.
func (c *EventCache) PendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range splitJSONL(data) {
		if len(line) > 0 {
			n++
		}
	}
	return n
}

func (c *EventCache) rewriteLocked(events []*cachedEvent) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, c.path)
}

// RevocationCache holds the last verified revocation feed on disk so the
// SDK can enforce revocation offline (VAL-KILL-010) and reject lower-epoch
// feeds (anti-rollback, VAL-KILL-009).
type revocationCache struct {
	mu          sync.Mutex
	path        string
	cachedEpoch int64
	feed        map[string]any
}

func newRevocationCache(dir, subject string) *revocationCache {
	return &revocationCache{path: filepath.Join(dir, "revocations-"+safeSubject(subject)+".json")}
}

// Load returns the cached feed (or nil) and its epoch.
func (r *revocationCache) Load() (map[string]any, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.feed != nil {
		return r.feed, r.cachedEpoch
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, 0
	}
	var feed map[string]any
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, 0
	}
	epoch := epochOf(feed)
	r.feed = feed
	r.cachedEpoch = epoch
	return feed, epoch
}

// Save persists the feed and updates the cached epoch.
func (r *revocationCache) Save(feed map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(feed)
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.path, data, 0o600); err != nil {
		return err
	}
	r.feed = feed
	r.cachedEpoch = epochOf(feed)
	return nil
}

// CachedEpoch returns the highest verified epoch seen so far.
func (r *revocationCache) CachedEpoch() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cachedEpoch
}

// SetCachedEpoch records a baseline epoch (e.g. after a bootstrap fetch).
func (r *revocationCache) SetCachedEpoch(epoch int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if epoch > r.cachedEpoch {
		r.cachedEpoch = epoch
	}
}

// IsRevoked reports whether the given agent id or subject appears in the
// cached feed's revocation list.
func (r *revocationCache) IsRevoked(agentIDOrSubject string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.feed == nil {
		return false
	}
	revs, ok := r.feed["revocations"].([]any)
	if !ok {
		return false
	}
	target := strings.ToLower(agentIDOrSubject)
	for _, rany := range revs {
		rm, ok := rany.(map[string]any)
		if !ok {
			continue
		}
		aid, _ := rm["agent_id"].(string)
		subj, _ := rm["subject"].(string)
		if strings.EqualFold(aid, target) || strings.EqualFold(subj, target) {
			return true
		}
	}
	return false
}

func epochOf(feed map[string]any) int64 {
	if v, ok := feed["epoch"]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		}
	}
	return 0
}

// splitJSONL splits newline-delimited JSON bytes into per-record byte
// slices (trimming whitespace).
func splitJSONL(data []byte) [][]byte {
	var out [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim != "" {
			out = append(out, []byte(trim))
		}
	}
	return out
}

func safeSubject(subject string) string {
	s := strings.ReplaceAll(subject, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
