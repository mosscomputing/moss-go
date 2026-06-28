package sidecar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeSignalKiller records calls and optionally simulates killed PIDs.
type fakeSignalKiller struct {
	mu          sync.Mutex
	killedPIDs  []int
	killCalls   int
	verifyGone  bool
	verifyCalls int
	failKill    error
}

func (f *fakeSignalKiller) KillByCmdline(_ context.Context, _ string, _ time.Duration) ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killCalls++
	if f.failKill != nil {
		return nil, f.failKill
	}
	if len(f.killedPIDs) == 0 {
		f.killedPIDs = []int{4242}
	}
	return f.killedPIDs, nil
}

func (f *fakeSignalKiller) VerifyGone(_ context.Context, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls++
	return f.verifyGone, nil
}

// fakePodDeleter records calls and simulates Forbidden / success / 404.
type fakePodDeleter struct {
	mu               sync.Mutex
	deleteCalls      int
	verifyCalls      int
	deleteForbidden  bool
	deleteNotFound   bool
	verifyGone       bool
	deleteErr        error
}

func (f *fakePodDeleter) DeletePod(_ context.Context, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls++
	if f.deleteForbidden {
		return errors.New("pods is forbidden: User \"sidecar\" cannot delete resource \"pods\"")
	}
	if f.deleteNotFound {
		return errors.New("pods \"moss-agent\" not found")
	}
	return f.deleteErr
}

func (f *fakePodDeleter) VerifyPodGone(_ context.Context, _, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls++
	return f.verifyGone, nil
}

func TestKillBothPathsSignalThenDelete(t *testing.T) {
	sk := &fakeSignalKiller{killedPIDs: []int{111}}
	pd := &fakePodDeleter{verifyGone: true}
	cfg := Config{
		KillMode:           "both",
		AgentCmdlineMatch:  "sleep 3600",
		PodName:            "moss-agent",
		PodNamespace:       "default",
		SignalTermGrace:    1,
		KillDeadline:       5,
	}
	act := cfg.Kill(context.Background(), sk, pd)
	if len(act.SignalPIDs) != 1 || act.SignalPIDs[0] != 111 {
		t.Fatalf("signal PIDs = %v, want [111]", act.SignalPIDs)
	}
	if !act.PodDeleted {
		t.Error("PodDeleted = false, want true")
	}
	if act.PodDeleteForbidden {
		t.Error("PodDeleteForbidden = true, want false")
	}
	if !act.VerifiedDead {
		t.Error("VerifiedDead = false, want true")
	}
	if pd.deleteCalls != 1 {
		t.Errorf("delete calls = %d, want 1", pd.deleteCalls)
	}
	if pd.verifyCalls != 1 {
		t.Errorf("verify calls = %d, want 1", pd.verifyCalls)
	}
}

func TestKillRBACDeniedFallsBackToSignal(t *testing.T) {
	sk := &fakeSignalKiller{killedPIDs: []int{222}, verifyGone: true}
	pd := &fakePodDeleter{deleteForbidden: true}
	cfg := Config{
		KillMode:          "both",
		AgentCmdlineMatch: "sleep 3600",
		PodName:           "moss-agent",
		PodNamespace:      "default",
		SignalTermGrace:   1,
		KillDeadline:      5,
	}
	act := cfg.Kill(context.Background(), sk, pd)
	if len(act.SignalPIDs) != 1 || act.SignalPIDs[0] != 222 {
		t.Fatalf("signal PIDs = %v, want [222]", act.SignalPIDs)
	}
	if act.PodDeleted {
		t.Error("PodDeleted = true, want false (Forbidden)")
	}
	if !act.PodDeleteForbidden {
		t.Error("PodDeleteForbidden = false, want true")
	}
	// Signal-path death verification still runs because delete did not
	// succeed.
	if !act.VerifiedDead {
		t.Error("VerifiedDead = false, want true (signal verify)")
	}
}

func TestKillSignalOnlyVerifiesViaProc(t *testing.T) {
	sk := &fakeSignalKiller{killedPIDs: []int{333}, verifyGone: true}
	pd := &fakePodDeleter{}
	cfg := Config{
		KillMode:          "signal",
		AgentCmdlineMatch: "sleep 3600",
		SignalTermGrace:   1,
		KillDeadline:      5,
	}
	act := cfg.Kill(context.Background(), sk, pd)
	if pd.deleteCalls != 0 {
		t.Errorf("delete calls = %d, want 0 (signal-only mode)", pd.deleteCalls)
	}
	if len(act.SignalPIDs) != 1 || act.SignalPIDs[0] != 333 {
		t.Fatalf("signal PIDs = %v, want [333]", act.SignalPIDs)
	}
	if !act.VerifiedDead {
		t.Error("VerifiedDead = false, want true")
	}
}

func TestKillDeleteOnlySkipsSignal(t *testing.T) {
	sk := &fakeSignalKiller{}
	pd := &fakePodDeleter{verifyGone: true}
	cfg := Config{
		KillMode:          "delete",
		AgentCmdlineMatch: "sleep 3600",
		PodName:           "moss-agent",
		PodNamespace:      "default",
		KillDeadline:      5,
	}
	act := cfg.Kill(context.Background(), sk, pd)
	if len(act.SignalPIDs) != 0 {
		t.Errorf("signal PIDs = %v, want [] (delete-only mode)", act.SignalPIDs)
	}
	if sk.killCalls != 0 {
		t.Errorf("signal kill calls = %d, want 0 (delete-only mode)", sk.killCalls)
	}
	if !act.PodDeleted || !act.VerifiedDead {
		t.Errorf("PodDeleted=%v VerifiedDead=%v, want true/true", act.PodDeleted, act.VerifiedDead)
	}
}

func TestKillDelete404CountsAsGone(t *testing.T) {
	sk := &fakeSignalKiller{}
	pd := &fakePodDeleter{deleteNotFound: true, verifyGone: true}
	cfg := Config{
		KillMode:     "delete",
		PodName:      "moss-agent",
		PodNamespace: "default",
		KillDeadline: 5,
	}
	act := cfg.Kill(context.Background(), sk, pd)
	if !act.PodDeleted {
		t.Error("PodDeleted = false on 404, want true (already gone)")
	}
}

func TestIsForbiddenAndNotFound(t *testing.T) {
	if !isForbidden(errors.New("pods is forbidden: User sidecar cannot delete")) {
		t.Error("isForbidden should be true for forbidden message")
	}
	if isForbidden(errors.New("pods not found")) {
		t.Error("isForbidden should be false for not-found message")
	}
	if !isNotFound(errors.New("pods \"x\" not found")) {
		t.Error("isNotFound should be true for not-found message")
	}
	if isNotFound(errors.New("forbidden")) {
		t.Error("isNotFound should be false for forbidden message")
	}
}

func TestWantsSignalAndDelete(t *testing.T) {
	cases := []struct {
		mode                            string
		wantSignal, wantDelete          bool
	}{
		{"", true, true},
		{"both", true, true},
		{"signal", true, false},
		{"delete", false, true},
	}
	for _, c := range cases {
		cfg := Config{KillMode: c.mode}
		if cfg.wantsSignal() != c.wantSignal {
			t.Errorf("mode %q wantsSignal=%v want %v", c.mode, cfg.wantsSignal(), c.wantSignal)
		}
		if cfg.wantsDelete() != c.wantDelete {
			t.Errorf("mode %q wantsDelete=%v want %v", c.mode, cfg.wantsDelete(), c.wantDelete)
		}
	}
}
