package sidecar

import (
	"context"
	"fmt"
	"log"
	"time"
)

// KillAction records what the killer did and is used for verification +
// logging in tests and the main loop.
type KillAction struct {
	// SignalPIDs is the list of agent PIDs killed via process signals.
	SignalPIDs []int
	// SignalError is the error from the signal path (empty on success).
	SignalError error
	// PodDeleted is true if the pod was deleted via client-go.
	PodDeleted bool
	// PodDeleteError is the error from the pod-delete path. For an RBAC
	// Forbidden, this is a non-nil error and PodDeleted stays false so the
	// caller can log the fallback.
	PodDeleteError error
	// PodDeleteForbidden is true when the pod delete was denied by RBAC.
	PodDeleteForbidden bool
	// VerifiedDead is true if death verification confirmed the agent/pod
	// is gone.
	VerifiedDead bool
}

// wantsSignal reports whether the configured kill mode uses the in-pod
// signal path.
func (c Config) wantsSignal() bool {
	return c.KillMode == "" || c.KillMode == "both" || c.KillMode == "signal"
}

// wantsDelete reports whether the configured kill mode uses the client-go
// pod-delete path.
func (c Config) wantsDelete() bool {
	return c.KillMode == "" || c.KillMode == "both" || c.KillMode == "delete"
}

// killDeadline returns the overall kill budget as a Duration.
func (c Config) killDeadline() time.Duration {
	if c.KillDeadline <= 0 {
		return 9 * time.Second
	}
	return time.Duration(c.KillDeadline) * time.Second
}

// termGrace returns the SIGTERM->SIGKILL grace period.
func (c Config) termGrace() time.Duration {
	if c.SignalTermGrace <= 0 {
		return 3 * time.Second
	}
	return time.Duration(c.SignalTermGrace) * time.Second
}

// Kill carries out the revocation kill action using the configured
// mechanisms, within the configured kill deadline. The signal path is
// attempted first (sub-second when shareProcessNamespace is enabled); the
// pod-delete path is attempted second as the authoritative fallback. When
// pod-delete is denied by RBAC (Forbidden), it is logged and the signal
// path result stands.
//
// The provided signalKiller and podDeleter allow tests to inject fakes; pass
// nil to use the real implementations (realSignalKiller / realPodDeleter).
func (c Config) Kill(ctx context.Context, signalKiller SignalKiller, podDeleter PodDeleter) KillAction {
	deadline := c.killDeadline()
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	var act KillAction

	// 1. Primary: in-pod shareProcessNamespace SIGTERM -> SIGKILL.
	if c.wantsSignal() && c.AgentCmdlineMatch != "" && signalKiller != nil {
		pids, err := signalKiller.KillByCmdline(ctx, c.AgentCmdlineMatch, c.termGrace())
		act.SignalPIDs = pids
		act.SignalError = err
		if err != nil {
			log.Printf("[sidecar] signal kill error: %v", err)
		} else if len(pids) > 0 {
			log.Printf("[sidecar] signal kill terminated agent PIDs %v (match=%q)", pids, c.AgentCmdlineMatch)
		} else {
			log.Printf("[sidecar] signal kill found no process matching %q (agent may already be dead)", c.AgentCmdlineMatch)
		}
	}

	// 2. Authoritative: client-go pod delete (gracePeriodSeconds:0).
	if c.wantsDelete() && c.PodName != "" && c.PodNamespace != "" && podDeleter != nil {
		err := podDeleter.DeletePod(ctx, c.PodNamespace, c.PodName)
		if err != nil {
			act.PodDeleteError = err
			if isForbidden(err) {
				act.PodDeleteForbidden = true
				log.Printf("[sidecar] pod-delete RBAC denied (Forbidden): %v -- falling back to signal path", err)
			} else {
				// A 404 (pod already gone, e.g. signal path caused the
				// pod to fail and the controller removed it) is acceptable.
				if isNotFound(err) {
					act.PodDeleted = true
					log.Printf("[sidecar] pod already gone (404) before delete: %v", err)
				} else {
					log.Printf("[sidecar] pod-delete error: %v", err)
				}
			}
		} else {
			act.PodDeleted = true
			log.Printf("[sidecar] pod-delete succeeded (gracePeriodSeconds:0) for %s/%s", c.PodNamespace, c.PodName)
		}

		// 3. Verify death: poll the pod until 404/Deleted (only meaningful
		// when the delete path is in play).
		if act.PodDeleted && !act.PodDeleteForbidden {
			gone, verifyErr := podDeleter.VerifyPodGone(ctx, c.PodNamespace, c.PodName)
			if verifyErr != nil {
				log.Printf("[sidecar] verify-death error: %v", verifyErr)
			}
			act.VerifiedDead = gone
			if gone {
				log.Printf("[sidecar] verified pod %s/%s is gone (404/Deleted)", c.PodNamespace, c.PodName)
			}
		}
	}

	// If only the signal path ran, verify the agent process is gone.
	if !act.PodDeleted && c.wantsSignal() && signalKiller != nil && c.AgentCmdlineMatch != "" {
		gone, verifyErr := signalKiller.VerifyGone(ctx, c.AgentCmdlineMatch)
		if verifyErr != nil {
			log.Printf("[sidecar] verify-death (signal) error: %v", verifyErr)
		}
		act.VerifiedDead = gone
	}

	return act
}

// Summary returns a one-line human-readable summary of the kill action for
// logs/handoff.
func (a KillAction) Summary() string {
	return fmt.Sprintf("signal_pids=%v signal_err=%v pod_deleted=%v forbidden=%v verified_dead=%v",
		a.SignalPIDs, a.SignalError, a.PodDeleted, a.PodDeleteForbidden, a.VerifiedDead)
}
