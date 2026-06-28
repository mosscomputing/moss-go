// Command moss-sidecar is the MOSS Kubernetes native sidecar. It watches the
// MOSS signed revocation feed (and optionally polls the heartbeat endpoint)
// on behalf of a non-embedding agent and, when MOSS revokes that agent,
// terminates it via two mechanisms:
//
//  1. Primary (in-pod): with shareProcessNamespace: true, send SIGTERM then
//     SIGKILL to the agent PID in the sibling container (sub-second).
//  2. Authoritative: client-go pod delete (gracePeriodSeconds:0), gated by a
//     namespace-scoped RBAC Role + RoleBinding to the sidecar ServiceAccount.
//
// When pod-delete RBAC is denied (Forbidden), the in-pod signal path still
// terminates the agent within the kill deadline.
//
// Configuration is via environment variables (see sidecar.Config / FromEnv).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mosscomputing/moss-go/sidecar"
)

func main() {
	cfg := sidecar.FromEnv()

	if cfg.APIKey == "" {
		log.Fatal("[sidecar] MOSS_API_KEY is required")
	}
	if cfg.AgentID == "" && cfg.AgentSubject == "" {
		log.Fatal("[sidecar] MOSS_AGENT_ID or MOSS_AGENT_SUBJECT is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	watcher, err := sidecar.NewWatcher(ctx, cfg)
	if err != nil {
		log.Fatalf("[sidecar] init failed: %v", err)
	}

	if err := watcher.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("[sidecar] exited with error: %v", err)
	}
	os.Exit(0)
}
