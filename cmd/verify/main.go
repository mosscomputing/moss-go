package main

import (
	"fmt"
	"os"
	"github.com/mosscomputing/moss-go"
)

func main() {
	canonical := []byte(`{"event":"agent.action","agent_id":"aaaa5555-0000-0000-0000-000000000001","ts":"2026-06-05T05:00:00Z","payload":{"k":"v"}}`)
	signers := []string{"ts", "go", "java", "dotnet", "python"}
	for _, signer := range signers {
		pk, _ := os.ReadFile("/tmp/moss-crosslang/" + signer + ".pk")
		sig, _ := os.ReadFile("/tmp/moss-crosslang/" + signer + ".sig")
		valid := moss.Verify(canonical, pk, sig)
		status := "PASS"
		if !valid { status = "FAIL" }
		fmt.Printf("%s signed -> go verified: %s\n", signer, status)
	}
}
