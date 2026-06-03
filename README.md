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

## License

Business Source License 1.1 - See LICENSE file.

Copyright (c) 2025-2026 IAMPASS Inc.
