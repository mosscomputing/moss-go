// Command go-revoke-timing validates VAL-CROSS-011: revocation terminates
// the live Go agent process within 10 seconds.
//
// The agent registers, heartbeats (~2s), and runs until it sees revoked:true
// on a heartbeat (push fast path) -> kill() -> os.Exit(70). An external
// script revokes via the API and measures wall-clock time from revoke to
// process exit.
//
// Usage (from a script):
//
//	MOSS_API_KEY=... go run ./examples/go-revoke-timing &
//	PID=$!
//	# wait for "READY <subject> <pid>"
//	curl -X POST -H "Authorization: Bearer $KEY" \
//	  -H "Content-Type: application/json" -d '{"reason":"timing-test"}' \
//	  http://localhost:3100/v1/agents/<subject>/revoke
//	# time how long until $PID exits
package main

import (
	"fmt"
	"os"
	"time"

	moss "github.com/mosscomputing/moss-go/runtime"
)

func main() {
	apiKey := os.Getenv("MOSS_API_KEY")
	if apiKey == "" {
		apiKey = "moss_live_seed_owner_LOCAL_DEMO_ONLY"
	}
	baseURL := "http://localhost:3100"
	subject := "moss:go:revoke-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000)

	os.RemoveAll("/tmp/moss-go-revoke-cache")
	os.RemoveAll("/tmp/moss-go-revoke-keys")

	agent, err := moss.Init(moss.Options{
		APIKey:            apiKey,
		AgentSubject:      subject,
		BaseURL:           baseURL,
		OfflineCacheDir:   "/tmp/moss-go-revoke-cache",
		KeystoreDir:       "/tmp/moss-go-revoke-keys",
		HeartbeatInterval: 2 * time.Second,
		LeaseTTL:          20,
		DeclaredBehavior: moss.DeclaredBehavior{
			AllowedDataSources:  []string{"public"},
			AllowedActions:      []string{"MOSS_REGISTER", "MOSS_KILL"},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		os.Exit(1)
	}
	agent.EnsureRegistered()
	agent.EventLogger.Flush(3 * time.Second)

	// Signal readiness to the parent script.
	fmt.Printf("READY %s %d\n", subject, os.Getpid())
	fmt.Fprintf(os.Stderr, "READY %s %d\n", subject, os.Getpid())

	// Block until revocation push fires kill() -> os.Exit(70). The
	// heartbeat goroutine calls onRevocationPush -> kill(force=true).
	select {}
}
