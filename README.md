# MOSS Go SDK

**Unsigned agent output is broken output.**

MOSS (Message-Origin Signing System) provides cryptographic signing for AI agents. Every output is signed with ML-DSA-44 (post-quantum), creating non-repudiable execution records with audit-grade provenance.

## Install

```bash
go get github.com/mosscomputing/moss-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/mosscomputing/moss-go"
)

func main() {
    // Create client (uses MOSS_API_KEY env var if set)
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
    fmt.Printf("Decision: %s\n", result.Decision)

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

## Enterprise Features

With an API key, you get policy evaluation, approval workflows, and audit logging:

```go
client, _ := moss.NewClient(moss.Config{
    APIKey: os.Getenv("MOSS_API_KEY"),
})

result, _ := client.Sign(moss.SignRequest{
    Payload: map[string]any{
        "action":    "high_risk_transfer",
        "amount":    1000000,
        "recipient": "external-account",
    },
    AgentID: "finance-bot",
    Action:  "transfer",
    Context: map[string]any{
        "user_id":    "u123",
        "department": "finance",
    },
})

switch result.Decision {
case "allow":
    fmt.Println("Action allowed")
case "block":
    fmt.Printf("Action blocked: %s\n", result.Reason)
case "hold":
    fmt.Printf("Action held for approval: %s\n", result.ActionID)
}
```

## Agent Lifecycle Management

```go
// Register a new agent
agent, _ := client.RegisterAgent(moss.RegisterAgentRequest{
    AgentID:     "my-new-agent",
    DisplayName: "My New Agent",
    Tags:        []string{"production", "finance"},
})
fmt.Printf("Signing secret (save this!): %s\n", agent.SigningSecret)

// Get agent details
agent, _ := client.GetAgent("my-new-agent")
fmt.Printf("Status: %s, Signatures: %d\n", agent.Status, agent.TotalSignatures)

// Rotate key (returns new signing secret)
rotateResult, _ := client.RotateAgentKey("my-new-agent", "quarterly rotation")
fmt.Printf("New signing secret: %s\n", rotateResult.SigningSecret)

// Suspend agent (can be reactivated)
client.SuspendAgent("my-new-agent", "suspicious activity")

// Reactivate agent
client.ReactivateAgent("my-new-agent")

// Permanently revoke agent
client.RevokeAgent("my-new-agent", "compromised credentials")
```

## Envelope Format

Every signed action produces a verifiable envelope:

```go
type Envelope struct {
    Spec        string `json:"spec"`         // "moss-0001"
    Version     int    `json:"version"`      // 1
    Alg         string `json:"alg"`          // "ML-DSA-44"
    Subject     string `json:"subject"`      // Agent ID
    KeyVersion  int    `json:"key_version"`  // Key version for rotation
    Seq         int64  `json:"seq"`          // Sequence number
    IssuedAt    int64  `json:"issued_at"`    // Unix timestamp
    PayloadHash string `json:"payload_hash"` // SHA-256 of payload
    Signature   string `json:"signature"`    // ML-DSA-44 signature
}
```

## Configuration

```go
client, _ := moss.NewClient(moss.Config{
    // API key for enterprise features (optional)
    APIKey: os.Getenv("MOSS_API_KEY"),
    
    // Custom API URL (optional)
    BaseURL: "https://moss-api.example.com",
    
    // Request timeout (optional, default 30s)
    Timeout: 10 * time.Second,
    
    // Custom HTTP client (optional)
    HTTPClient: &http.Client{...},
})
```

## Error Handling

```go
result, err := client.Sign(req)
if err != nil {
    switch {
    case errors.Is(err, moss.ErrNoAPIKey):
        // API key required for this operation
    case errors.Is(err, moss.ErrAgentSuspended):
        // Agent is suspended
    case errors.Is(err, moss.ErrAgentRevoked):
        // Agent has been revoked
    default:
        // Other error
    }
}
```

## Pricing Tiers

| Tier | Price | Agents | Signatures | Retention |
|------|-------|--------|------------|-----------|
| **Free** | $0 | 5 | 1,000/day | 7 days |
| **Pro** | $1,499/mo | Unlimited | Unlimited | 1 year |
| **Enterprise** | Custom | Unlimited | Unlimited | 7 years |

*Annual billing: $1,249/mo (save $3,000/year)*

All new signups get a **14-day free trial** of Pro.

## Links

- [mosscomputing.com](https://mosscomputing.com) — Project site
- [dev.mosscomputing.com](https://dev.mosscomputing.com) — Developer Console
- [audit.mosscomputing.com](https://audit.mosscomputing.com) — Authority Vault
- [Python SDK](https://github.com/mosscomputing/moss) — moss-sdk
- [TypeScript SDK](https://github.com/mosscomputing/moss-sdk-ts) — @moss/sdk

## License

Proprietary - See LICENSE for terms.

Copyright (c) 2025-2026 IAMPASS Inc. All Rights Reserved.
