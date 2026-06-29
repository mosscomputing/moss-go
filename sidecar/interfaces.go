package sidecar

import (
	"context"
	"errors"
	"strings"
	"time"
)

// SignalKiller locates and terminates the sibling agent process via OS
// signals when shareProcessNamespace is enabled.
type SignalKiller interface {
	// KillByCmdline sends SIGTERM to every process whose /proc/<pid>/cmdline
	// contains match (excluding the sidecar's own PID), waits up to termGrace,
	// then escalates to SIGKILL for any survivors. Returns the PIDs that were
	// terminated. A nil error with no PIDs means no matching process was
	// found (the agent may already be dead).
	KillByCmdline(ctx context.Context, match string, termGrace time.Duration) ([]int, error)
	// VerifyGone reports whether no live process matches the cmdline
	// substring. Used to verify death after the signal path.
	VerifyGone(ctx context.Context, match string) (bool, error)
}

// PodDeleter performs the authoritative client-go pod delete + death
// verification.
type PodDeleter interface {
	// DeletePod deletes the pod with gracePeriodSeconds:0. Returns an error
	// if the delete was denied (Forbidden) or failed for another reason.
	DeletePod(ctx context.Context, namespace, name string) error
	// VerifyPodGone polls the pod until it returns 404/NotFound or the
	// context deadline passes.
	VerifyPodGone(ctx context.Context, namespace, name string) (bool, error)
}

// isForbidden reports whether err is a Kubernetes 403 Forbidden (RBAC
// denied). Works against both the structured APIStatus error and the
// plain-text error returned by the in-cluster client.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "forbidden") || strings.Contains(msg, "statuscode=403") || strings.Contains(msg, "403")
}

// isNotFound reports whether err is a Kubernetes 404 NotFound.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "statuscode=404") || strings.Contains(msg, "404")
}

// errNoMatch is returned when no process matches the cmdline substring.
var errNoMatch = errors.New("sidecar: no matching process")
