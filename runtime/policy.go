package runtime

// Policy decision cache + live policy-check calls.
//
// The SDK calls POST /v1/agents/{subject}/policy-check (cached or live) on
// every governed action. A cached allow expires after cacheTTL so a
// server-side policy flip to block is honoured within the refresh window
// (VAL-RUNTIME-026). When the API is down the SDK falls back to the
// declared-behavior comparison (declared violation => block) so the
// headline guarantee still holds offline (VAL-CROSS-012).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// DeclaredBehavior is the set of capabilities/data sources/destinations an
// agent declares at init. It is the source of truth for local enforcement.
type DeclaredBehavior struct {
	DeclaredCapabilities []string `json:"declared_capabilities"`
	AllowedDataSources   []string `json:"allowed_data_sources"`
	AllowedActions       []string `json:"allowed_actions"`
	AllowedDestinations  []string `json:"allowed_destinations"`
}

// PolicyDecision is the result of a policy-check (live or offline).
type PolicyDecision struct {
	Decision          string `json:"decision"`
	Reason            string `json:"reason"`
	PolicyVersion     string `json:"policy_version"`
	DeclaredViolation bool   `json:"declared_violation"`
}

// IsBlock reports whether the decision blocks the action. A call is blocked
// when policy denies OR the target is undeclared (the headline guarantee:
// an agent cannot reach an unauthorized/undeclared data source, even when
// the server's default policy is permissive).
func (d *PolicyDecision) IsBlock() bool {
	return d.Decision != "allow" || d.DeclaredViolation
}

// PolicyEngine evaluates policy decisions (cached or live) and merges them
// with the agent's declared behavior.
type PolicyEngine struct {
	baseURL    string
	apiKey     string
	subject    string
	declared   DeclaredBehavior
	cacheTTL   time.Duration
	httpClient *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	decision PolicyDecision
	at       time.Time
}

// NewPolicyEngine constructs a PolicyEngine.
func NewPolicyEngine(baseURL, apiKey, subject string, declared DeclaredBehavior, cacheTTL time.Duration, client *http.Client) *PolicyEngine {
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &PolicyEngine{
		baseURL:    trimRightSlash(baseURL),
		apiKey:     apiKey,
		subject:    subject,
		declared:   declared,
		cacheTTL:   cacheTTL,
		httpClient: client,
		cache:      make(map[string]cacheEntry),
	}
}

// RefreshDeclared updates the declared behavior and invalidates the cache.
func (p *PolicyEngine) RefreshDeclared(declared DeclaredBehavior) {
	p.mu.Lock()
	p.declared = declared
	p.cache = make(map[string]cacheEntry)
	p.mu.Unlock()
}

// Invalidate clears the decision cache.
func (p *PolicyEngine) Invalidate() {
	p.mu.Lock()
	p.cache = make(map[string]cacheEntry)
	p.mu.Unlock()
}

func (p *PolicyEngine) cacheKey(action, destination, dataSource string) string {
	return action + "|" + destination + "|" + dataSource
}

// declaredViolation returns true iff the request targets something outside
// the declared set. Uses the SAME exact-match semantics as the server: a
// dimension only counts as a violation when the agent declared a non-empty
// set for that dimension AND the request's value is not in it.
func (p *PolicyEngine) declaredViolation(action, destination, dataSource string) bool {
	if p.declared.AllowedActions != nil && action != "" && !contains(p.declared.AllowedActions, action) {
		return true
	}
	if p.declared.AllowedDestinations != nil && destination != "" && !contains(p.declared.AllowedDestinations, destination) {
		return true
	}
	if p.declared.AllowedDataSources != nil && dataSource != "" && !contains(p.declared.AllowedDataSources, dataSource) {
		return true
	}
	return false
}

// Check returns a policy decision, merging the live server decision with
// the local declared-behavior check (which is authoritative for what the
// agent declared).
func (p *PolicyEngine) Check(action, destination, dataSource string, attributes map[string]any) PolicyDecision {
	key := p.cacheKey(action, destination, dataSource)
	now := time.Now()

	p.mu.Lock()
	if entry, ok := p.cache[key]; ok && now.Sub(entry.at) < p.cacheTTL {
		p.mu.Unlock()
		return entry.decision
	}
	p.mu.Unlock()

	localViolation := p.declaredViolation(action, destination, dataSource)
	decision := p.liveCheck(action, destination, dataSource, attributes)
	if decision == nil {
		// API down: fall back to declared-behavior enforcement.
		if localViolation {
			decision = &PolicyDecision{
				Decision:          "block",
				Reason:            "Undeclared target (offline declared-behavior enforcement)",
				DeclaredViolation: true,
				PolicyVersion:     "offline-declared",
			}
		} else {
			decision = &PolicyDecision{
				Decision:      "allow",
				Reason:        "Allowed (offline, within declared behavior)",
				PolicyVersion: "offline-declared",
			}
		}
	} else {
		merged := decision.DeclaredViolation || localViolation
		decision.DeclaredViolation = merged
		if merged && decision.Decision == "allow" {
			decision.Decision = "block"
			if decision.Reason == "" {
				decision.Reason = "Undeclared target (declared-behavior enforcement)"
			}
		}
	}

	p.mu.Lock()
	p.cache[key] = cacheEntry{decision: *decision, at: now}
	p.mu.Unlock()
	return *decision
}

func (p *PolicyEngine) liveCheck(action, destination, dataSource string, attributes map[string]any) *PolicyDecision {
	body := map[string]any{
		"action":      action,
		"destination": destination,
		"data_source": dataSource,
	}
	if attributes != nil {
		body["attributes"] = attributes
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	url := p.baseURL + "/v1/agents/" + p.subject + "/policy-check"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	var dec PolicyDecision
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		return nil
	}
	return &dec
}

// contains reports whether s contains v (exact match).
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func trimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
