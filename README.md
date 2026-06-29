# moss-go

MOSS SDK for Go — cryptographic signing for AI agent actions using ML-DSA-44 (FIPS 204).

## Overview

MOSS provides cryptographic signing for AI agent outputs using **ML-DSA-44** (Module-Lattice Digital Signature Algorithm), a post-quantum digital signature algorithm standardized in **NIST FIPS 204**. Every agent action is signed with a real ML-DSA-44 signature to create non-repudiable execution records with audit-grade provenance. Unsigned agent output is broken output.

### ML-DSA-44 / FIPS 204 Parameter Sizes

| Parameter | Size |
|-----------|------|
| Public key | 1312 bytes |
| Secret key | 2560 bytes |
| Signature | 2420 bytes |

## Installation

```bash
go get github.com/mosscomputing/moss-go
```

## Quick Start

### Standalone ML-DSA-44 (no API key required)

```go
package main

import (
    "fmt"

    "github.com/mosscomputing/moss-go"
)

func main() {
    // Generate an ML-DSA-44 key pair
    kp, err := moss.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Sign a payload
    payload := []byte("agent action: transfer $500")
    sig, err := moss.Sign(payload, kp.SecretKey)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature: %d bytes (ML-DSA-44)\n", len(sig))

    // Verify the signature
    valid := moss.Verify(payload, kp.PublicKey, sig)
    fmt.Printf("Verified: %v\n", valid) // true
}
```

### Enterprise Client (with API key)

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/mosscomputing/moss-go"
)

func main() {
    client, err := moss.NewClient(moss.Config{
        APIKey: os.Getenv("MOSS_API_KEY"),
    })
    if err != nil {
        panic(err)
    }

    // Sign any agent output
    result, err := client.Sign(moss.SignRequest{
        Payload: map[string]any{
            "action": "transfer",
            "amount": 500,
        },
        AgentID: "agent-finance-01",
    })
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signed! Hash: %s\n", result.Envelope.PayloadHash)

    // Verify offline
    verifyResult, _ := client.Verify(
        map[string]any{"action": "transfer", "amount": 500},
        result.Envelope,
    )
    
    if verifyResult.Valid {
        fmt.Printf("Verified! Signed by: %s\n", verifyResult.Subject)
    }
}
```

## Features

- **Cryptographic signing (ML-DSA-44 / FIPS 204)** — Post-quantum secure signatures using `cloudflare/circl/sign/mldsa/mldsa44`
- **Standalone API** — `GenerateKeyPair()`, `Sign()`, `Verify()` without any network dependency
- **Policy evaluation** — Server-side policy checks with allow/block/hold decisions
- **Evidence chain linking** — Sequential signatures with payload hashes for audit trails
- **Offline verification** — Verify signatures locally without network calls

## API Reference

### Standalone Functions

```go
// Generate an ML-DSA-44 key pair (pk=1312 bytes, sk=2560 bytes)
kp, err := moss.GenerateKeyPair()

// Sign a payload (returns 2420-byte ML-DSA-44 signature)
sig, err := moss.Sign(payload, kp.SecretKey)

// Verify a signature against a payload and public key
valid := moss.Verify(payload, kp.PublicKey, sig)
```

### Client

```go
// Create client
client, err := moss.NewClient(moss.Config{
    APIKey:  os.Getenv("MOSS_API_KEY"),
    BaseURL: "https://api.mosscomputing.com", // optional
    Timeout: 30 * time.Second,                // optional
})
```

### Sign

```go
result, err := client.Sign(moss.SignRequest{
    Payload: payload,           // Any serializable data
    AgentID: "agent-id",       // Agent identifier
    Action:  "action-name",    // Optional action type
    Context: map[string]any{}, // Optional metadata
})
```

### Verify

```go
verifyResult, err := client.Verify(payload, envelope)
// verifyResult.Valid: true if signature valid
// verifyResult.Subject: signing agent ID
```

### Envelope

```go
type Envelope struct {
    Spec        string // "moss-0001"
    Version     int    // 1
    Alg         string // "ML-DSA-44"
    Subject     string // Agent ID
    KeyVersion  int    // Key version for rotation
    Seq         int64  // Sequence number
    IssuedAt    int64  // Unix timestamp
    PayloadHash string // SHA-256 of payload
    Signature   string // Base64-encoded ML-DSA-44 signature (2420 bytes)
}
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `MOSS_API_KEY` | API key for enterprise features | None |
| `MOSS_API_URL` | Custom API endpoint | `https://api.mosscomputing.com` |

## Links

- Documentation: [docs.mosscomputing.com/sdks/go](https://docs.mosscomputing.com/sdks/go)
- Dashboard: [app.mosscomputing.com](https://app.mosscomputing.com)
- Python SDK: [pypi.org/project/moss-sdk](https://pypi.org/project/moss-sdk/)

## Mission 19: Agent Runtime SDK + K8s Sidecar

Mission 19 extends moss-go with a full Go Runtime SDK (lifecycle parity with the Python reference SDK) and a native Kubernetes sidecar that kills revoked agent pods. Both use ML-DSA-44 (FIPS 204) via `filippo.io/mldsa` for signing and offline feed verification. The module requires Go 1.25.

### Go Runtime SDK (`runtime/` subpackage)

The `runtime` subpackage mirrors the Python `MossAgent` and the TS runtime SDK lifecycle so all three SDKs exhibit the same behavior against the same backend.

- **Auto-register** — `Init(apiKey, agentSubject, declaredBehavior, baseURL)` loads/creates an ML-DSA-44 keypair and starts the heartbeat, revocation, and event workers. The first governed action auto-registers via the backend; no explicit registration call is required.
- **HTTP egress interception** — a `GovernedTransport` (`http.RoundTripper`) intercepts outbound HTTP so governed calls are evaluated before they leave the process. An explicit `Guard` decision API is also available for non-HTTP actions.
- **Signed event logging** — every governed event is signed with ML-DSA-44 (`filippo.io/mldsa` `MLDSA44`) and batched (`events.go`, `crypto.go`).
- **Heartbeat** — a background goroutine posts `POST /v1/agents/{subject}/heartbeat` every ~5s (configurable). The response carries `lease_expires_at`, `revocation_epoch`, `revoked`, and `server_time` (`heartbeat.go`).
- **Offline revocation cache** — `RevocationWatcher` periodically fetches `GET /v1/revocations?since=epoch`, verifies the ML-DSA-44 signature offline with the embedded MOSS public key, persists the feed locally, and rejects lower-epoch feeds (anti-rollback). When the API is down the SDK enforces revocation from the cached feed (`revocation.go`).
- **Kill** — `kill(reason)` flushes events, writes a final signed record, invokes a user hook, then `os.Exit`, with a watchdog escalation.
- **Dead-man's switch** — if the API is unreachable past the cached lease TTL, the process self-terminates (fail-closed). A `revoked:true` heartbeat auto-invokes `kill()` (push revocation).

Key files: `agent.go`, `config.go`, `crypto.go`, `events.go`, `heartbeat.go`, `policy.go`, `revocation.go`, `transport.go`, `persistence.go`. Examples live under `examples/` (`go-agent`, `go-interop`, `go-revoke-timing`, `go-offline-failclosed`, `go-benchmark`).

### K8s Sidecar (`sidecar/` subpackage)

The `sidecar` subpackage is a native Kubernetes sidecar (`cmd/main.go`, the `moss-sidecar` binary) that watches the MOSS signed revocation feed on behalf of a non-embedding agent and terminates the agent pod when MOSS revokes that agent.

- **Two kill mechanisms** — (1) Primary in-pod: with `shareProcessNamespace: true`, send `SIGTERM` then `SIGKILL` to the agent PID in the sibling container (sub-second). (2) Authoritative: `client-go` pod delete (`gracePeriodSeconds: 0`), gated by a namespace-scoped RBAC `Role` + `RoleBinding` bound to the sidecar `ServiceAccount` (`killer.go`, `pod_delete.go`, `proc_linux.go`).
- **RBAC-denied fallback** — when the pod-delete RBAC is denied (`Forbidden`), the in-pod signal path still terminates the agent within the kill deadline. The signal path is attempted first; the pod delete is the authoritative backstop.
- **Offline feed verification** — `watcher.go` resolves the MOSS public key (embedded hex or fetched from the API well-known endpoint), verifies each feed's ML-DSA-44 signature, and rejects lower-epoch feeds (anti-rollback). `revocation.go` + `verify.go` handle fetch and verification.
- **Validated on kind** — manifests under `sidecar/manifests/` (`deployment.yaml`, `deployment-rbac-denied.yaml`, `rbac.yaml`, `rbac-denied.yaml`, `serviceaccount.yaml`, `namespace.yaml`) are validated on a `kind` cluster, including the RBAC-denied fallback path.

Configuration is via environment variables (see `sidecar.Config` / `FromEnv`). The sidecar requires `MOSS_API_KEY` and either `MOSS_AGENT_ID` or `MOSS_AGENT_SUBJECT`.

## License

Business Source License 1.1 - See LICENSE file.

Copyright (c) 2025-2026 IAMPASS Inc.
