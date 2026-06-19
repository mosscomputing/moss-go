package main

import (
	"fmt"
	"os"
	"github.com/mosscomputing/moss-go"
)

func main() {
	kp, err := moss.GenerateKeyPair()
	if err != nil { fmt.Fprintf(os.Stderr, "keygen: %v\n", err); os.Exit(1) }
	canonical := []byte(`{"event":"agent.action","agent_id":"aaaa5555-0000-0000-0000-000000000001","ts":"2026-06-05T05:00:00Z","payload":{"k":"v"}}`)
	sig, err := moss.Sign(canonical, kp.SecretKey)
	if err != nil { fmt.Fprintf(os.Stderr, "sign: %v\n", err); os.Exit(1) }
	valid := moss.Verify(canonical, kp.PublicKey, sig)
	os.WriteFile("/tmp/moss-crosslang/go.pk", kp.PublicKey, 0644)
	os.WriteFile("/tmp/moss-crosslang/go.sig", sig, 0644)
	os.WriteFile("/tmp/moss-crosslang/go.sk", kp.SecretKey, 0644)
	fmt.Printf("go: pk=%d sig=%d verified=%v\n", len(kp.PublicKey), len(sig), valid)
}
