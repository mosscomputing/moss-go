//go:build !linux

package sidecar

import (
	"context"
	"fmt"
	"time"
)

// realSignalKiller is a non-linux stub. The signal kill path requires a
// Linux /proc filesystem (the sidecar runs in a Linux container with
// shareProcessNamespace: true). On non-linux hosts the real killer is
// unavailable; tests inject a fake SignalKiller instead.
type realSignalKiller struct{}

func newSignalKiller() SignalKiller {
	return &realSignalKiller{}
}

func (k *realSignalKiller) KillByCmdline(_ context.Context, _ string, _ time.Duration) ([]int, error) {
	return nil, fmt.Errorf("sidecar: signal killer requires Linux /proc (shareProcessNamespace)")
}

func (k *realSignalKiller) VerifyGone(_ context.Context, _ string) (bool, error) {
	return false, fmt.Errorf("sidecar: signal killer requires Linux /proc (shareProcessNamespace)")
}
