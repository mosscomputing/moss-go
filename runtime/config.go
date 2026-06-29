package runtime

import (
	"os"
	"runtime"
	"strconv"
)

// Algorithm is the signature algorithm used by every signed event and the
// revocation feed.
const Algorithm = "ML-DSA-44"

// Default configuration constants. These mirror the Python + TS reference
// SDK defaults so all three SDKs exhibit the same lifecycle against the
// same backend.
const (
	defaultBaseURL              = "http://localhost:3100"
	defaultHeartbeatInterval    = 5.0 // seconds
	defaultLeaseTTL             = 20  // seconds (server clamps 15-25)
	defaultPolicyCacheTTL       = 30.0
	defaultRevocationRefresh    = 10.0
	defaultKillGraceSeconds     = 5.0
	defaultEventBatchInterval   = 0.5
)

// envFloat reads a float64 from the environment, falling back to def.
func envFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// envString reads a string from the environment, falling back to def.
func envString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// envInt reads an int from the environment, falling back to def.
func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// defaultBaseURLFromEnv resolves the API base URL from MOSS_BASE_URL or the
// built-in default.
func defaultBaseURLFromEnv() string {
	return envString("MOSS_BASE_URL", defaultBaseURL)
}

// defaultOfflineCacheDir resolves the on-disk cache directory for events
// and revocation feeds.
func defaultOfflineCacheDir() string {
	return envString("MOSS_OFFLINE_CACHE_DIR", os.Getenv("HOME")+"/.moss/agent-sdk-cache")
}

// defaultKeystoreDir resolves the keystore directory for ML-DSA-44 keys.
func defaultKeystoreDir() string {
	return envString("MOSS_KEYSTORE_DIR", os.Getenv("HOME")+"/.moss/keys")
}

// runtimeInfo returns runtime metadata reported in heartbeats
// (VAL-KILL-026). Mirrors the Python/TS runtime_info shape.
func runtimeInfo() map[string]any {
	return map[string]any{
		"go_version": runtime.Version(),
		"platform":   runtime.GOOS,
		"machine":    runtime.GOARCH,
		"processor":  runtime.GOARCH,
		"pid":        os.Getpid(),
	}
}
