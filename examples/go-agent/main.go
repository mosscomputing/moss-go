// Example MOSS Go agent demonstrating the full runtime SDK lifecycle.
//
// Run against the local signing-api on :3100:
//
//	MOSS_API_KEY=moss_live_seed_owner_LOCAL_DEMO_ONLY \
//	go run ./examples/go-agent
//
// The agent:
//  1. inits (auto-register on first governed action).
//  2. makes an ALLOWED governed HTTP call (within declared bounds).
//  3. attempts an UNDECLARED data source via Guard -> blocked.
//  4. emits heartbeats (~5s) + fetches the signed revocation feed.
//  5. on revocation (operator POST /v1/agents/{subject}/revoke) the
//     process self-terminates within 10s.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	moss "github.com/mosscomputing/moss-go/runtime"
)

func main() {
	apiKey := os.Getenv("MOSS_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "MOSS_API_KEY is required")
		os.Exit(2)
	}
	subject := os.Getenv("MOSS_AGENT_SUBJECT")
	if subject == "" {
		subject = "moss:go:example-agent"
	}
	baseURL := os.Getenv("MOSS_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:3100"
	}

	agent, err := moss.Init(moss.Options{
		APIKey:       apiKey,
		AgentSubject: subject,
		BaseURL:      baseURL,
		DeclaredBehavior: moss.DeclaredBehavior{
			AllowedDataSources:  []string{"public"},
			AllowedDestinations: []string{"http://localhost:3150"},
			AllowedActions:      []string{"http_get", "http_post", "query_public", "MOSS_REGISTER", "MOSS_KILL"},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "init failed:", err)
		os.Exit(1)
	}
	fmt.Printf("[go-agent] initialized subject=%s pk=%s... sdk=%s\n",
		subject, truncate(agent.PublicKeyHex, 24), agent.SDKVersion())

	// Install a shutdown hook.
	agent.OnShutdown(func() {
		fmt.Println("[go-agent] shutdown hook ran")
	})

	// Handle SIGINT/SIGTERM -> graceful kill.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// 1. Allowed governed HTTP GET to the sink server.
	agent.EnsureRegistered()
	client := agent.HTTPClient(10 * time.Second)
	resp, err := client.Get("http://localhost:3150")
	if err != nil {
		if moss.IsBlock(err) {
			fmt.Println("[go-agent] allowed call unexpectedly blocked:", err)
		} else {
			fmt.Fprintln(os.Stderr, "[go-agent] allowed GET failed:", err)
		}
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("[go-agent] allowed GET -> %d %s\n", resp.StatusCode, string(body))
	}

	// 2. Attempt an UNDECLARED data source via Guard -> blocked.
	err = agent.Guard(context.Background(), "query_private", map[string]any{
		"data_source": "private/customer-db",
	}, func() error {
		fmt.Println("[go-agent] BUG: blocked body ran")
		return nil
	})
	if moss.IsBlock(err) {
		fmt.Println("[go-agent] blocked undeclared data source (expected):", err)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "[go-agent] guard error:", err)
	} else {
		fmt.Println("[go-agent] BUG: undeclared action was allowed")
	}

	// 3. Allowed explicit Guard action (within declared bounds).
	err = agent.Guard(context.Background(), "query_public", map[string]any{
		"data_source": "public",
	}, func() error {
		fmt.Println("[go-agent] allowed guarded action ran")
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "[go-agent] allowed guard error:", err)
	}

	// 4. Emit a few signed events for forensic replay visibility.
	for i := 0; i < 3; i++ {
		agent.EventLogger.Log(map[string]any{
			"action":      "http_get",
			"destination": "http://localhost:3150",
			"data_source": "public",
			"iter":        i,
		}, "http_get")
	}
	agent.EventLogger.Flush(5 * time.Second)
	fmt.Printf("[go-agent] pending events: %d, registered: %v, revoked: %v, epoch: %d\n",
		agent.PendingEvents(), agent.EventLogger.IsRegistered(), agent.IsRevoked(),
		agent.RevocationWatcher.CachedEpoch())

	fmt.Println("[go-agent] running; revoke via API or Ctrl-C to stop")
	<-sigs
	fmt.Println("[go-agent] signal received; calling kill()")
	agent.Kill("signal")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// keep net/http imported (used implicitly via client); guard against unused
// import if the GET path is edited out.
var _ = http.MethodGet
