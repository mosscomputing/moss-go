//go:build linux

package sidecar

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// realSignalKiller scans /proc/*/cmdline (visible because the pod runs with
// shareProcessNamespace: true) and terminates matching processes with
// SIGTERM then SIGKILL.
type realSignalKiller struct {
	selfPID int
}

func newSignalKiller() SignalKiller {
	return &realSignalKiller{selfPID: os.Getpid()}
}

// readCmdline reads /proc/<pid>/cmdline and returns the space-joined command
// line (NUL bytes replaced by spaces).
func readCmdline(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", nil
	}
	// Replace NUL separators with spaces for substring matching.
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " "), nil
}

// findMatchingPIDs returns the PIDs whose cmdline contains match, excluding
// the sidecar's own PID.
func (k *realSignalKiller) findMatchingPIDs(match string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("sidecar: read /proc: %w", err)
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == k.selfPID || pid == 1 {
			// Skip the sidecar itself and the shared-namespace init (PID 1).
			continue
		}
		cmd, err := readCmdline(pid)
		if err != nil {
			continue
		}
		if strings.Contains(cmd, match) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func (k *realSignalKiller) KillByCmdline(ctx context.Context, match string, termGrace time.Duration) ([]int, error) {
	pids, err := k.findMatchingPIDs(match)
	if err != nil {
		return nil, err
	}
	if len(pids) == 0 {
		return nil, nil
	}

	// 1. SIGTERM every match. Record EPERM errors (the sidecar lacks
	//    permission to signal the target uid — typically because it is not
	//    running as root / lacks CAP_KILL in the shared PID namespace).
	var permErrs []int
	for _, pid := range pids {
		if e := syscall.Kill(pid, syscall.SIGTERM); e != nil {
			if e == syscall.EPERM {
				permErrs = append(permErrs, pid)
			}
			// ESRCH (process gone) is benign here.
		}
	}
	if len(permErrs) > 0 {
		return pids, fmt.Errorf("sidecar: SIGTERM denied (EPERM) for pids %v (run the sidecar as root or grant CAP_KILL)", permErrs)
	}

	// 2. Wait the grace period (honouring context cancellation).
	deadline := time.NewTimer(termGrace)
	defer deadline.Stop()
	select {
	case <-deadline.C:
	case <-ctx.Done():
	}

	// 3. SIGKILL any survivors.
	for _, pid := range pids {
		if alive(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	return pids, nil
}

func (k *realSignalKiller) VerifyGone(ctx context.Context, match string) (bool, error) {
	pids, err := k.findMatchingPIDs(match)
	if err != nil {
		return false, err
	}
	return len(pids) == 0, nil
}

// alive reports whether a process with the given PID exists (kill 0 probe).
func alive(pid int) bool {
	if err := syscall.Kill(pid, 0); err == nil {
		return true
	}
	return false
}

// ensure filepath is referenced so the import is not unused if future edits
// drop its only use.
var _ = filepath.Clean
