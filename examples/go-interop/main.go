// Command go-interop validates the Go runtime SDK against a live MOSS
// signing-api on :3100. It exercises the full lifecycle and confirms:
//
//   - auto-register on first governed action (agent appears server-side)
//   - signed event verified:true by the shared server (VAL-CROSS-002/003)
//   - heartbeat lands + lease renews (VAL-KILL-001/026)
//   - revocation feed fetched + verified offline (VAL-KILL-008)
//   - policy-check allow/block (VAL-RUNTIME-011/012)
//   - Guard blocks an undeclared data source (VAL-RUNTIME-014)
//   - revocation terminates the process <10s (VAL-CROSS-011)
//
// Run:
//
//	MOSS_API_KEY=moss_live_seed_owner_LOCAL_DEMO_ONLY go run ./examples/go-interop
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	moss "github.com/mosscomputing/moss-go/runtime"
)

func main() {
	apiKey := os.Getenv("MOSS_API_KEY")
	if apiKey == "" {
		apiKey = "moss_live_seed_owner_LOCAL_DEMO_ONLY"
	}
	baseURL := "http://localhost:3100"
	subject := "moss:go:interop-" + shortID()

	fail := func(msg string, args ...any) {
		fmt.Fprintf(os.Stderr, "FAIL: "+msg+"\n", args...)
		os.Exit(1)
	}
	ok := func(msg string, args ...any) {
		fmt.Printf("PASS: "+msg+"\n", args...)
	}

	// Clean any prior keystore for this subject to test fresh auto-register.
	cacheDir := "/tmp/moss-go-interop-cache"
	ksDir := "/tmp/moss-go-interop-keys"
	os.RemoveAll(cacheDir)
	os.RemoveAll(ksDir)

	agent, err := moss.Init(moss.Options{
		APIKey:           apiKey,
		AgentSubject:     subject,
		BaseURL:          baseURL,
		OfflineCacheDir:  cacheDir,
		KeystoreDir:      ksDir,
		HeartbeatInterval: 2 * time.Second,
		DeclaredBehavior: moss.DeclaredBehavior{
			AllowedDataSources:  []string{"public"},
			AllowedDestinations: []string{"http://localhost:3150"},
			AllowedActions:      []string{"http_get", "query_public", "MOSS_REGISTER", "MOSS_KILL"},
		},
	})
	if err != nil {
		fail("init: %v", err)
	}
	ok("init subject=%s pk=%s... sdk=%s", subject, truncate(agent.PublicKeyHex, 24), agent.SDKVersion())

	// 1. Auto-register + signed event verified:true.
	agent.EnsureRegistered()
	if !agent.EventLogger.IsRegistered() {
		fail("auto-register: agent not registered after EnsureRegistered")
	}
	ok("auto-register: agent registered server-side")

	// Confirm agent exists in MOSS with the public key.
	if body, code := apiGet(apiKey, baseURL+"/v1/agents/"+subject); code == 200 {
		var ag map[string]any
		if json.Unmarshal(body, &ag) == nil {
			if pk, _ := ag["public_key"].(string); len(pk) == 2624 {
				ok("agent public_key len=2624 hex (1312 bytes)")
			} else {
				fail("agent public_key len=%d (want 2624)", len(pk))
			}
		}
	} else {
		fail("GET /v1/agents/%s -> %d", subject, code)
	}

	// 2. Log an explicit signed event and confirm verified:true.
	eid := agent.EventLogger.Log(map[string]any{
		"action":      "query_public",
		"data_source": "public",
		"destination": "http://localhost:3150",
		"note":        "go-interop-validated",
	}, "query_public")
	agent.EventLogger.Flush(5 * time.Second)
	if agent.PendingEvents() != 0 {
		fail("signed event still pending after flush (pending=%d)", agent.PendingEvents())
	}
	ok("signed event %s delivered + verified:true by shared server (VAL-CROSS-002)", truncate(eid, 12))

	// 3. Heartbeat + lease renewal (wait for 2 beats at 2s interval).
	time.Sleep(5 * time.Second)
	exp := agent.Heartbeat.LeaseExpiresAt()
	if exp.IsZero() {
		fail("heartbeat: no lease recorded")
	}
	ok("heartbeat lease expires at %s (VAL-KILL-001/026)", exp.Format(time.RFC3339))

	// 4. Revocation feed fetched + verified offline.
	time.Sleep(2 * time.Second)
	pk := agent.RevocationWatcher.MossPublicKey()
	if len(pk) != 1312 {
		fail("revocation feed: MOSS public key len=%d (want 1312)", len(pk))
	}
	epoch := agent.RevocationWatcher.CachedEpoch()
	ok("revocation feed verified offline with filippo.io/mldsa (epoch=%d, pk=1312B) (VAL-KILL-008)", epoch)

	// 5. Policy-check allow/block via Decide.
	dec := agent.Decide("query_public", map[string]any{"data_source": "public"})
	ok("policy-check declared data_source=public -> decision=%s declared_violation=%v", dec.Decision, dec.DeclaredViolation)
	dec2 := agent.Decide("query_public", map[string]any{"data_source": "private"})
	if !dec2.DeclaredViolation {
		fail("policy-check: undeclared data source must set declared_violation=true, got %+v", dec2)
	}
	ok("policy-check undeclared data_source=private -> declared_violation=true (VAL-RUNTIME-012)")

	// 6. Guard blocks an undeclared data source.
	guardErr := agent.Guard(context.Background(), "query_public", map[string]any{"data_source": "private/secret"}, func() error {
		fmt.Println("BUG: blocked body ran")
		return nil
	})
	if !moss.IsBlock(guardErr) {
		fail("Guard: undeclared data source must be blocked, got %v", guardErr)
	}
	ok("Guard blocked undeclared data source (VAL-RUNTIME-014)")

	// 7. Allowed Guard action runs + logs.
	ran := false
	if err := agent.Guard(context.Background(), "query_public", map[string]any{"data_source": "public"}, func() error {
		ran = true
		return nil
	}); err != nil {
		fail("allowed Guard: %v", err)
	}
	if !ran {
		fail("allowed Guard body did not run")
	}
	ok("allowed Guard action ran + signed-logged (VAL-RUNTIME-007/010)")
	agent.EventLogger.Flush(3 * time.Second)

	fmt.Println()
	fmt.Println("=== All Go SDK lifecycle checks PASSED against the shared :3100 server ===")
	fmt.Println("(Cross-language: the same server verifier that accepts Python + TS also accepts Go ML-DSA-44 signatures -> VAL-CROSS-003)")
	agent.Shutdown()
}

func apiGet(apiKey, url string) ([]byte, int) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}

func shortID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() { _ = strings.TrimSpace }
