package main

import (
	"fmt"
	"os"
)

func main() {
	dryRun := false
	for _, arg := range os.Args[1:] {
		if arg == "--dry-run" {
			dryRun = true
		}
	}
	fmt.Println("MOSS Uninstall Helper for moss-go")
	fmt.Println("----------------------------------------")
	if dryRun {
		fmt.Println("[DRY-RUN MODE]")
	}
	fmt.Print(`
MANUAL CLEANUP CHECKLIST

[ ] Revoke/rotate MOSS credentials in the MOSS console (API keys / agent capability tokens)
[ ] Remove the moss-go dependency:
      go mod edit -droprequire github.com/mosscomputing/moss-go && go mod tidy
[ ] Remove imports of "github.com/mosscomputing/moss-go" from your .go files
[ ] Remove config files: rm -f .moss.yml moss_config.json moss.config.js
[ ] Unset MOSS_* environment variables
[ ] CI/CD: remove MOSS_* secrets and setup steps from GitHub Actions / CI
[ ] Docs: update README / setup guides that reference MOSS
`)
	fmt.Println("\nChecklist printed. Complete the steps above manually.")
	os.Exit(0)
}
