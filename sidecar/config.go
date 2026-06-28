package sidecar

// Config holds all runtime configuration for the MOSS sidecar. It is
// populated from environment variables (see FromEnv) but may also be
// constructed directly in tests.
type Config struct {
	// APIURL is the MOSS signing-api base URL, e.g. http://localhost:3100.
	APIURL string
	// APIKey is the org API key used to authenticate revocation feed +
	// heartbeat calls (Bearer moss_live_*).
	APIKey string

	// AgentID is the MOSS agent id (UUID) the sidecar watches and kills on
	// revocation. Either AgentID or AgentSubject must be set; AgentID is
	// preferred (the revocation feed lists agent_id).
	AgentID string
	// AgentSubject is the agent subject. Used as a fallback to resolve the
	// agent id and to match revocations when only a subject is known.
	AgentSubject string

	// PodName is the name of the pod the sidecar runs in (used for the
	// authoritative client-go pod delete). Typically injected via the
	// Kubernetes downward API.
	PodName string
	// PodNamespace is the pod namespace.
	PodNamespace string

	// AgentCmdlineMatch is a substring matched against /proc/*/cmdline to
	// locate the sibling agent container's main process when
	// shareProcessNamespace is enabled. Required for the signal kill path.
	AgentCmdlineMatch string

	// KillMode controls which kill mechanisms are attempted. One of
	// "both" (default), "signal", "delete".
	KillMode string

	// PublicKeyHex is the hex-encoded MOSS public key used to verify the
	// revocation feed offline. If empty, the sidecar fetches it from the
	// API's well-known key endpoint using KeyID.
	PublicKeyHex string
	// KeyID identifies which MOSS signing key to use for verification. If
	// empty, the key_id from the revocation feed is used.
	KeyID string

	// PollInterval is the delay between revocation-feed / heartbeat polls.
	// Defaults to 2s if zero.
	PollInterval int
	// HeartbeatEnabled controls whether the sidecar polls the heartbeat
	// endpoint (which returns revoked:true on revocation) in addition to
	// the revocation feed. Defaults to true.
	HeartbeatEnabled bool

	// SignalTermGrace is how long the signal killer waits between SIGTERM
	// and escalating to SIGKILL. Defaults to 3s.
	SignalTermGrace int
	// KillDeadline is the overall budget for the kill action (signal +
	// verify). Defaults to 9s so the whole revoke->death path stays under
	// the 10s contract.
	KillDeadline int

	// InClusterKubeConfig controls whether the killer uses an in-cluster
	// Kubernetes config (service-account token). Set false in tests to
	// use an explicit kubeconfig path instead.
	InClusterKubeConfig bool
	// KubeconfigPath is an explicit kubeconfig path for out-of-cluster
	// testing (used when InClusterKubeConfig is false).
	KubeconfigPath string
}

// DefaultKillMode is the default kill mode (attempt both mechanisms).
const DefaultKillMode = "both"

// FromEnv builds a Config from environment variables. Required: MOSS_API_URL,
// MOSS_API_KEY, and (MOSS_AGENT_ID or MOSS_AGENT_SUBJECT). The signal path
// additionally needs MOSS_AGENT_CMDLINE_MATCH; the delete path needs
// MOSS_POD_NAME + MOSS_POD_NAMESPACE.
func FromEnv() Config {
	cfg := Config{
		APIURL:             envOr("MOSS_API_URL", "http://localhost:3100"),
		APIKey:             envOr("MOSS_API_KEY", ""),
		AgentID:            envOr("MOSS_AGENT_ID", ""),
		AgentSubject:       envOr("MOSS_AGENT_SUBJECT", ""),
		PodName:            envOr("MOSS_POD_NAME", ""),
		PodNamespace:       envOr("MOSS_POD_NAMESPACE", "default"),
		AgentCmdlineMatch:  envOr("MOSS_AGENT_CMDLINE_MATCH", ""),
		KillMode:           envOr("MOSS_KILL_MODE", DefaultKillMode),
		PublicKeyHex:       envOr("MOSS_PUBLIC_KEY_HEX", ""),
		KeyID:              envOr("MOSS_KEY_ID", ""),
		PollInterval:       envInt("MOSS_POLL_INTERVAL", 2),
		HeartbeatEnabled:   envBool("MOSS_HEARTBEAT_ENABLED", true),
		SignalTermGrace:    envInt("MOSS_SIGNAL_TERM_GRACE", 3),
		KillDeadline:       envInt("MOSS_KILL_DEADLINE", 9),
		InClusterKubeConfig: envBool("MOSS_IN_CLUSTER_KUBECONFIG", true),
		KubeconfigPath:     envOr("MOSS_KUBECONFIG_PATH", ""),
	}
	return cfg
}
