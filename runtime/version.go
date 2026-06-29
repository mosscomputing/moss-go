// Package runtime implements the MOSS Agent Runtime SDK in Go.
//
// It provides lifecycle parity with the Python reference SDK
// (moss-agent-sdk) and the TypeScript runtime SDK (moss-sdk-ts/runtime):
//
//   - init(apiKey, agentSubject, declaredBehavior, baseURL) auto-registers
//     the agent on the first governed action.
//   - HTTP egress interception via an http.RoundTripper: every outbound
//     call is policy-checked (block before the socket opens) and then
//     logged as a batched, signed ML-DSA-44 event.
//   - Explicit decision API: moss.Guard(ctx, action).
//   - Heartbeat loop (~5s) with lease + dead-man's switch (fail-closed).
//   - Offline signed revocation cache (anti-rollback, verified with
//     filippo.io/mldsa MLDSA44).
//   - kill(): flush events + final signed record + user hook + os.Exit,
//     with a watchdog escalation.
//
// The ML-DSA-44 convention is identical across all three SDKs: empty
// context, pure (non-prehash) ML-DSA, raw public-key bytes exchanged as
// hex, canonical JSON marshaling with sorted keys and compact separators
// (byte-identical to Python's json.dumps(sort_keys=True,
// separators=(',',':'))).
package runtime

// SDKVersion is the published version of the Go runtime SDK. It is sent
// in every heartbeat (VAL-KILL-026) and recorded in forensic markers.
const SDKVersion = "0.1.0"
