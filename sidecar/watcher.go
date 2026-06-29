package sidecar

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Watcher is the MOSS sidecar revocation watcher. It polls the signed
// revocation feed (and optionally the heartbeat endpoint) and, when the
// watched agent is revoked, terminates the agent via process signals and/or
// an authoritative client-go pod delete.
type Watcher struct {
	cfg Config

	// publicKey is the cached MOSS public key (raw bytes) used for offline
	// feed verification.
	publicKey []byte

	// cachedEpoch is the highest verified revocation epoch seen so far
	// (anti-rollback: lower-epoch feeds are rejected).
	cachedEpoch int64

	// signalKiller / podDeleter are injected for tests; when nil the real
	// implementations are constructed lazily.
	signalKiller SignalKiller
	podDeleter   PodDeleter

	// killed is true once the kill action has been executed; the watcher
	// keeps re-killing on subsequent polls to suppress restarts but only
	// logs the first action.
	killed bool
}

// NewWatcher constructs a Watcher from the given config. The public key is
// resolved (embedded hex or fetched from the API well-known endpoint) and
// verified to be a 1312-byte ML-DSA-44 key.
func NewWatcher(ctx context.Context, cfg Config) (*Watcher, error) {
	w := &Watcher{cfg: cfg}

	// Resolve the MOSS public key.
	pkHex := cfg.PublicKeyHex
	if pkHex == "" {
		// If a key_id is pinned, fetch that; otherwise fetch the feed once
		// to discover the key_id, then fetch the key.
		keyID := cfg.KeyID
		if keyID == "" {
			feed, err := FetchRevocationFeed(cfg, 0)
			if err != nil {
				return nil, fmt.Errorf("sidecar: bootstrap revocation feed: %w", err)
			}
			keyID = feed.KeyID
			w.cachedEpoch = feed.Epoch - 1 // accept this feed as the baseline
		}
		hex, err := FetchPublicKey(cfg, keyID)
		if err != nil {
			return nil, fmt.Errorf("sidecar: fetch MOSS public key: %w", err)
		}
		pkHex = hex
	}
	pk, err := DecodePublicKeyHex(pkHex)
	if err != nil {
		return nil, fmt.Errorf("sidecar: decode MOSS public key: %w", err)
	}
	w.publicKey = pk
	log.Printf("[sidecar] loaded MOSS public key (%d bytes)", len(pk))

	// Resolve the kill-path implementations. The signal killer is always
	// available (it no-ops if no cmdline match is configured); the pod
	// deleter is only constructed when the delete path is configured AND a
	// kubeconfig source is available. Construction failures are non-fatal:
	// the watcher falls back to whatever path works.
	w.signalKiller = newSignalKiller()

	if cfg.wantsDelete() && cfg.PodName != "" {
		deleter, err := NewPodDeleter(cfg)
		if err != nil {
			log.Printf("[sidecar] pod deleter unavailable (signal path only): %v", err)
		} else {
			w.podDeleter = deleter
			log.Printf("[sidecar] pod deleter ready (in-cluster=%v)", cfg.InClusterKubeConfig)
		}
	}

	return w, nil
}

// SetKillers allows tests to inject fake kill-path implementations.
func (w *Watcher) SetKillers(sk SignalKiller, pd PodDeleter) {
	w.signalKiller = sk
	w.podDeleter = pd
}

// Run starts the revocation watch loop. It blocks until ctx is cancelled or
// a fatal error occurs. On detecting revocation it executes the kill action
// and continues watching so restarts are suppressed (signal path) / the pod
// stays deleted (delete path).
func (w *Watcher) Run(ctx context.Context) error {
	interval := time.Duration(w.cfg.PollInterval) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	log.Printf("[sidecar] watching agent_id=%q subject=%q poll=%s kill_mode=%s",
		w.cfg.AgentID, w.cfg.AgentSubject, interval, w.cfg.KillMode)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// One immediate check on startup, then on every tick.
	if err := w.checkOnce(ctx); err != nil {
		log.Printf("[sidecar] check error: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.checkOnce(ctx); err != nil {
				log.Printf("[sidecar] check error: %v", err)
			}
		}
	}
}

// checkOnce performs one revocation-feed + heartbeat poll and triggers the
// kill action if the watched agent is revoked.
func (w *Watcher) checkOnce(ctx context.Context) error {
	revoked, reason, err := w.detectRevocation(ctx)
	if err != nil {
		// Transient API errors should not crash the sidecar; the dead-man's
		// switch (heartbeat lease expiry) is owned by the embedding SDK, not
		// the sidecar. Log and continue.
		return err
	}
	if !revoked {
		return nil
	}

	log.Printf("[sidecar] REVOCATION DETECTED (%s) -- executing kill", reason)
	if w.killed {
		// Already killed once; keep suppressing restarts without re-logging
		// the full action every cycle. Re-run the signal path silently to
		// kill any restarted agent process.
		if w.cfg.wantsSignal() && w.signalKiller != nil && w.cfg.AgentCmdlineMatch != "" {
			_, _ = w.signalKiller.KillByCmdline(ctx, w.cfg.AgentCmdlineMatch, w.cfg.termGrace())
		}
		return nil
	}
	act := w.cfg.Kill(ctx, w.signalKiller, w.podDeleter)
	log.Printf("[sidecar] kill action: %s", act.Summary())
	w.killed = true
	return nil
}

// detectRevocation checks the signed revocation feed (offline-verified) and
// the heartbeat endpoint. Returns true if the watched agent is revoked, plus
// a human-readable reason describing which path detected it.
func (w *Watcher) detectRevocation(ctx context.Context) (bool, string, error) {
	// 1. Signed revocation feed (primary).
	feed, err := FetchRevocationFeed(w.cfg, w.cachedEpoch)
	if err != nil {
		// Fall through to heartbeat if the feed is unreachable.
		log.Printf("[sidecar] revocation feed fetch failed: %v", err)
	} else {
		if feed.Epoch < w.cachedEpoch {
			// Anti-rollback: reject lower-epoch feeds.
			return false, "", fmt.Errorf("sidecar: rollback rejected (feed epoch %d < cached %d)", feed.Epoch, w.cachedEpoch)
		}
		if err := feed.Verify(w.publicKey); err != nil {
			return false, "", fmt.Errorf("sidecar: feed verification: %w", err)
		}
		// Accept the new (higher or equal) epoch.
		if feed.Epoch > w.cachedEpoch {
			w.cachedEpoch = feed.Epoch
		}
		if feed.IsRevoked(w.cfg.AgentID, w.cfg.AgentSubject) {
			return true, fmt.Sprintf("revocation feed epoch=%d lists agent", feed.Epoch), nil
		}
	}

	// 2. Heartbeat push fast-path (optional, secondary).
	if w.cfg.HeartbeatEnabled && w.cfg.AgentID != "" {
		hb, err := PostHeartbeat(w.cfg, w.cfg.AgentID)
		if err != nil {
			log.Printf("[sidecar] heartbeat failed: %v", err)
		} else if hb.Revoked {
			return true, fmt.Sprintf("heartbeat returned revoked=true (epoch=%d)", hb.RevocationEpoch), nil
		}
	}

	return false, "", nil
}
