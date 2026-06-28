package runtime

// MossAgent is the main runtime SDK handle. It mirrors the Python
// reference SDK (moss_agent_sdk.MossAgent) and the TS runtime SDK
// (moss-sdk-ts/runtime MossAgent) lifecycle:
//
//  1. init(apiKey, agentSubject, declaredBehavior, baseURL) loads/creates
//     an ML-DSA-44 keypair and starts the heartbeat, revocation, and event
//     workers. No explicit registration call; the first governed action
//     auto-registers via POST /v1/agents/{subject}/event with
//     auto_register:true.
//  2. HTTP egress interception (http.RoundTripper) + explicit decision API
//     (Guard).
//  3. Heartbeat loop + offline revocation cache + graceful degradation.
//  4. kill(reason) -> flush events + final signed record + user hook +
//     os.Exit, with a watchdog escalation. Dead-man's switch
//     self-terminates on unrenewed lease past TTL.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Options configures a MossAgent. The zero-value Options starts workers by
// default (matching the Python/TS reference SDKs where start_workers defaults
// to true). Set DisableWorkers=true to construct without starting the
// background event/heartbeat/revocation goroutines.
type Options struct {
	APIKey                   string
	AgentSubject             string
	DeclaredBehavior         DeclaredBehavior
	BaseURL                  string
	HeartbeatInterval        time.Duration
	LeaseTTL                 int
	PolicyCacheTTL           time.Duration
	RevocationRefresh        time.Duration
	KillGraceSeconds         time.Duration
	EventBatchInterval       time.Duration
	OfflineCacheDir          string
	KeystoreDir              string
	DisableWorkers           bool // default false -> workers start
}

// Agent is the live governed agent handle.
type Agent struct {
	APIKey            string
	Subject           string
	DeclaredBehavior  DeclaredBehavior
	BaseURL           string
	HeartbeatInterval time.Duration
	LeaseTTL          int
	KillGraceSeconds  time.Duration
	OfflineCacheDir   string

	Keystore         *Keystore
	PublicKeyHex     string
	EventCache       *EventCache
	RevocationCache  *revocationCache
	PolicyEngine     *PolicyEngine
	EventLogger      *EventLogger
	Transport        *GovernedTransport
	RevocationWatcher *RevocationWatcher
	Heartbeat        *HeartbeatLoop

	httpClient *http.Client

	mu          sync.Mutex
	shutdownHook func()
	killed      bool
	forensicPath string
	started     bool
}

// Init initializes a governed agent handle (VAL-RUNTIME-001). No explicit
// registration call is required: the first governed action auto-registers
// the agent with MOSS.
func Init(opts Options) (*Agent, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("runtime: APIKey is required")
	}
	if opts.AgentSubject == "" {
		return nil, fmt.Errorf("runtime: AgentSubject is required")
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURLFromEnv()
	}
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = time.Duration(envFloat("MOSS_HEARTBEAT_INTERVAL", defaultHeartbeatInterval) * float64(time.Second))
	}
	if opts.LeaseTTL == 0 {
		opts.LeaseTTL = defaultLeaseTTL
	}
	if opts.PolicyCacheTTL <= 0 {
		opts.PolicyCacheTTL = time.Duration(envFloat("MOSS_POLICY_CACHE_TTL", defaultPolicyCacheTTL) * float64(time.Second))
	}
	if opts.RevocationRefresh <= 0 {
		opts.RevocationRefresh = time.Duration(envFloat("MOSS_REVOCATION_REFRESH_INTERVAL", defaultRevocationRefresh) * float64(time.Second))
	}
	if opts.KillGraceSeconds <= 0 {
		opts.KillGraceSeconds = time.Duration(envFloat("MOSS_KILL_GRACE", defaultKillGraceSeconds) * float64(time.Second))
	}
	if opts.EventBatchInterval <= 0 {
		opts.EventBatchInterval = time.Duration(envFloat("MOSS_EVENT_BATCH_INTERVAL", defaultEventBatchInterval) * float64(time.Second))
	}
	if opts.OfflineCacheDir == "" {
		opts.OfflineCacheDir = defaultOfflineCacheDir()
	}
	if opts.KeystoreDir == "" {
		opts.KeystoreDir = defaultKeystoreDir()
	}

	a := &Agent{
		APIKey:            opts.APIKey,
		Subject:           opts.AgentSubject,
		DeclaredBehavior:  opts.DeclaredBehavior,
		BaseURL:           trimRightSlash(opts.BaseURL),
		HeartbeatInterval: opts.HeartbeatInterval,
		LeaseTTL:          opts.LeaseTTL,
		KillGraceSeconds:  opts.KillGraceSeconds,
		OfflineCacheDir:   opts.OfflineCacheDir,
		forensicPath:      filepath.Join(opts.OfflineCacheDir, "forensic-"+safeSubject(opts.AgentSubject)+".json"),
	}

	// Keystore (idempotent: same subject -> same keypair).
	a.Keystore = NewKeystore(opts.AgentSubject, opts.KeystoreDir)
	if _, _, err := a.Keystore.LoadOrCreate(); err != nil {
		return nil, fmt.Errorf("runtime: keystore: %w", err)
	}
	a.PublicKeyHex = a.Keystore.PublicKeyHex()

	// Shared HTTP client for all SDK components (minimize RSS overhead).
	a.httpClient = &http.Client{Timeout: 10 * time.Second}

	// Caches + engines.
	a.EventCache = NewEventCache(opts.OfflineCacheDir, opts.AgentSubject)
	a.RevocationCache = newRevocationCache(opts.OfflineCacheDir, opts.AgentSubject)
	a.PolicyEngine = NewPolicyEngine(opts.BaseURL, opts.APIKey, opts.AgentSubject, opts.DeclaredBehavior, opts.PolicyCacheTTL, a.httpClient)
	a.EventLogger = NewEventLogger(opts.BaseURL, opts.APIKey, opts.AgentSubject, a.Keystore, a.EventCache, opts.EventBatchInterval, a.httpClient)
	a.Transport = NewGovernedTransport(a.PolicyEngine, a.EventLogger, nil)
	a.RevocationWatcher = NewRevocationWatcher(opts.BaseURL, opts.APIKey, opts.AgentSubject, a.RevocationCache, opts.RevocationRefresh, a.httpClient, a.onRevocationPush)
	a.Heartbeat = NewHeartbeatLoop(opts.BaseURL, opts.APIKey, opts.AgentSubject, opts.HeartbeatInterval, opts.LeaseTTL, a.httpClient, a.onRevocationPush, a.onDeadMansSwitch, func() bool { return a.EventLogger.IsRegistered() })

	if !opts.DisableWorkers {
		a.Start()
	}
	return a, nil
}

// Start launches the background workers (event logger, revocation watcher,
// heartbeat).
func (a *Agent) Start() {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return
	}
	a.started = true
	a.mu.Unlock()
	a.EventLogger.Start()
	a.RevocationWatcher.Start()
	a.Heartbeat.Start()
}

// Shutdown stops all background workers (does not exit the process).
func (a *Agent) Shutdown() {
	a.Heartbeat.Stop(2 * time.Second)
	a.RevocationWatcher.Stop(2 * time.Second)
	a.EventLogger.Stop(2 * time.Second)
}

// EnsureRegistered ensures the agent is registered + declared behavior
// persisted. Auto-register happens on the first governed action; after the
// first successful event the declared behavior is pushed via PATCH
// (VAL-RUNTIME-003). Idempotent (VAL-RUNTIME-021).
func (a *Agent) EnsureRegistered() {
	if !a.EventLogger.EnsureRegistered(8 * time.Second) {
		return
	}
	_ = SyncDeclaredBehavior(a.BaseURL, a.APIKey, a.Subject, a.DeclaredBehavior, a.httpClient)
}

// HTTPClient returns an *http.Client whose transport is governed by MOSS.
// Egress through this client is intercepted + signed-logged.
func (a *Agent) HTTPClient(timeout time.Duration) *http.Client {
	return GuardedClient(a.Transport, timeout)
}

// Guard is the explicit decision API for non-HTTP actions. It pre-checks
// policy; if blocked it returns a *BlockError (fn does not execute). On
// allow it runs fn and logs a signed event (VAL-RUNTIME-007/009).
func (a *Agent) Guard(ctx context.Context, action string, attrs map[string]any, fn func() error) error {
	a.EnsureRegistered()
	destination, dataSource := attrStr(attrs, "destination"), attrStr(attrs, "data_source")
	extra := stripAttrs(attrs, "destination", "data_source")
	decision := a.PolicyEngine.Check(action, destination, dataSource, extra)
	if decision.IsBlock() {
		a.EventLogger.Log(map[string]any{
			"action":      action,
			"destination": destination,
			"data_source": dataSource,
			"blocked":     true,
			"attrs":       extra,
		}, action)
		return &BlockError{
			Reason:            decision.Reason,
			Action:            action,
			Destination:       destination,
			DeclaredViolation: decision.DeclaredViolation,
			PolicyVersion:     decision.PolicyVersion,
		}
	}
	var runErr error
	if fn != nil {
		runErr = fn()
	}
	a.EventLogger.Log(map[string]any{
		"action":      action,
		"destination": destination,
		"data_source": dataSource,
		"blocked":     false,
		"attrs":       extra,
		"ran":         runErr == nil,
	}, action)
	return runErr
}

// Decide returns the policy decision for an action without executing it.
func (a *Agent) Decide(action string, attrs map[string]any) PolicyDecision {
	destination, dataSource := attrStr(attrs, "destination"), attrStr(attrs, "data_source")
	extra := stripAttrs(attrs, "destination", "data_source")
	return a.PolicyEngine.Check(action, destination, dataSource, extra)
}

// onRevocationPush is called when heartbeat/revocation feed says we are
// revoked. It invokes kill() with a hard exit (fail-closed).
func (a *Agent) onRevocationPush() {
	a.kill("revocation_push", true, true)
}

// onDeadMansSwitch fails closed: lease expired with API unreachable ->
// self-terminate.
func (a *Agent) onDeadMansSwitch() {
	a.kill("lease_expired_dead_mans_switch", true, true)
}

// OnShutdown registers a user shutdown hook run by kill().
func (a *Agent) OnShutdown(hook func()) {
	a.mu.Lock()
	a.shutdownHook = hook
	a.mu.Unlock()
}

// Kill performs a graceful shutdown: flush events + final signed record +
// hook + exit (if requested). A watchdog escalates to a hard exit if the
// shutdown hook stalls past the grace window (VAL-KILL-006/007).
func (a *Agent) Kill(reason string) {
	a.kill(reason, false, false)
}

func (a *Agent) kill(reason string, exitProcess, force bool) {
	a.mu.Lock()
	if a.killed {
		a.mu.Unlock()
		return
	}
	a.killed = true
	hook := a.shutdownHook
	a.mu.Unlock()

	// 1. Final signed forensic record (best effort, short flush when force-exiting).
	flushTimeout := 3 * time.Second
	if force {
		flushTimeout = 1 * time.Second
	}
	a.EventLogger.WriteFinalRecord(reason, flushTimeout)

	// 2. Write a local forensic marker (survives crash).
	a.writeForensicMarker(reason)

	// 3. Run the user shutdown hook with a watchdog.
	hookDone := make(chan struct{})
	if hook != nil {
		go func() {
			defer close(hookDone)
			hook()
		}()
		select {
		case <-hookDone:
		case <-time.After(a.KillGraceSeconds):
			force = true
		}
	}

	// 4. Stop workers (skip graceful shutdown when force-exiting from a
	//    background goroutine; os.Exit reaps everything).
	if !force {
		a.Shutdown()
	} else {
		a.Heartbeat.Stop(0)
		a.RevocationWatcher.Stop(0)
		a.EventLogger.Stop(0)
	}

	// 5. Exit the process if requested.
	if exitProcess {
		if force {
			os.Exit(70) // watchdog / fail-closed hard exit
		}
		os.Exit(70)
	}
}

func (a *Agent) writeForensicMarker(reason string) {
	if err := os.MkdirAll(filepath.Dir(a.forensicPath), 0o700); err != nil {
		return
	}
	marker := map[string]any{
		"subject":         a.Subject,
		"reason":          reason,
		"ts":              time.Now().Unix(),
		"sdk_version":     SDKVersion,
		"runtime_info":    runtimeInfo(),
		"pending_events":  a.EventLogger.PendingCount(),
	}
	raw, err := json.Marshal(marker)
	if err != nil {
		return
	}
	_ = os.WriteFile(a.forensicPath, raw, 0o600)
}

// IsKilled reports whether kill() has been invoked.
func (a *Agent) IsKilled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.killed
}

// IsRevoked reports whether this agent is revoked per the cached feed.
func (a *Agent) IsRevoked() bool {
	return a.RevocationWatcher.IsSelfRevoked()
}

// PendingEvents returns the count of undelivered cached events.
func (a *Agent) PendingEvents() int {
	return a.EventLogger.PendingCount()
}

// SDKVersion returns the SDK version string.
func (a *Agent) SDKVersion() string { return SDKVersion }

// ── helpers ──────────────────────────────────────────────────

func attrStr(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	if v, ok := attrs[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func stripAttrs(attrs map[string]any, keys ...string) map[string]any {
	if attrs == nil {
		return nil
	}
	out := make(map[string]any, len(attrs))
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[k] = true
	}
	for k, v := range attrs {
		if !drop[k] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
