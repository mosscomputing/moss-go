// Command go-offline-failclosed validates VAL-CROSS-012: offline fail-closed
// dead-man's switch. When the MOSS API is unreachable, the agent continues
// briefly from the cached revocation list, then self-terminates after the
// cached lease TTL elapses without a successful heartbeat (fail-closed).
//
// The agent registers against a reachable API, gets a lease, then the API
// is made unreachable (wrong port). The dead-man's switch fires after
// leaseExpiresAt + one heartbeat interval -> kill() -> os.Exit(70). No
// server contact is required for the self-termination.
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
	realBase := "http://localhost:3100"
	subject := "moss:go:offline-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000)

	os.RemoveAll("/tmp/moss-go-offline-cache")
	os.RemoveAll("/tmp/moss-go-offline-keys")

	// 1. Register against the reachable API, then get a lease + epoch.
	regAgent, err := moss.Init(moss.Options{
		APIKey:           apiKey,
		AgentSubject:     subject,
		BaseURL:          realBase,
		OfflineCacheDir:  "/tmp/moss-go-offline-cache",
		KeystoreDir:      "/tmp/moss-go-offline-keys",
		HeartbeatInterval: 2 * time.Second,
		LeaseTTL:          20,
		DisableWorkers:    true,
		DeclaredBehavior: moss.DeclaredBehavior{
			AllowedDataSources: []string{"public"},
			AllowedActions:     []string{"MOSS_REGISTER", "MOSS_KILL"},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "reg init:", err)
		os.Exit(1)
	}
	regAgent.EventLogger.Start()
	regAgent.EventLogger.EnsureRegistered(8 * time.Second)
	// Get a lease + cache it so the dead-man's switch has a TTL to count down.
	hb := regAgent.Heartbeat
	hb.BeatOnce()
	leaseExp := hb.LeaseExpiresAt()
	if leaseExp.IsZero() {
		fmt.Fprintln(os.Stderr, "FAIL: no lease from registration heartbeat")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "registered + lease expires at %s\n", leaseExp.Format(time.RFC3339))
	regAgent.Shutdown()

	// 2. Re-init against an UNREACHABLE API (wrong port), reusing the same
	//    keystore + cache so the lease expiry is carried over via a fresh
	//    heartbeat against the wrong port (which will fail). We seed the
	//    new heartbeat's lease with the cached expiry so the dead-man's
	//    switch fires after the TTL.
	agent, err := moss.Init(moss.Options{
		APIKey:            apiKey,
		AgentSubject:      subject,
		BaseURL:           "http://localhost:3199", // unreachable
		OfflineCacheDir:   "/tmp/moss-go-offline-cache",
		KeystoreDir:       "/tmp/moss-go-offline-keys",
		HeartbeatInterval: 2 * time.Second,
		LeaseTTL:          20,
		KillGraceSeconds:  3 * time.Second,
		DeclaredBehavior: moss.DeclaredBehavior{
			AllowedDataSources: []string{"public"},
			AllowedActions:     []string{"MOSS_REGISTER", "MOSS_KILL"},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "offline init:", err)
		os.Exit(1)
	}
	// Seed the lease expiry so the dead-man's switch counts down from the
	// real lease (the unreachable API will never renew it).
	agent.Heartbeat.SetLeaseExpiry(leaseExp)

	fmt.Printf("READY %s %d lease_exp=%s\n", subject, os.Getpid(), leaseExp.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "READY %s %d lease_exp=%s (API unreachable; dead-man's switch armed)\n",
		subject, os.Getpid(), leaseExp.Format(time.RFC3339))

	// The heartbeat goroutine will fail to reach the API, and once
	// now > leaseExpiresAt + interval, onDeadMansSwitch -> kill -> os.Exit(70).
	select {}
}
