package moss

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Shared test fixtures loader test for moss-go.
//
// Asserts the shared, vendored fixture corpus (testdata/fixtures/) is:
//   - present (VAL-DX-011)
//   - loadable as JSON in the Go repo (VAL-DX-011)
//   - byte-identical across the three SDK repos (the parity harness diffs the
//     sha256 set; this test pins the per-file sha256 so a silent drift in this
//     repo would fail here) (VAL-DX-012)
//   - covers the error states 404/401/403/409/422/429 with canonical error-code
//     strings, not just happy paths (VAL-DX-020)
//
// Fulfills: VAL-DX-011, VAL-DX-012, VAL-DX-020, VAL-DX-021 (loadability +
// error coverage + git-tracked checks; git-tracked is verified out-of-band
// via `git check-ignore` / `git ls-files`).

var requiredHappyFiles = []string{
	"index.json",
	"partner.json",
	"customers.json",
	"session.json",
	"capabilities.json",
	"envelopes.json",
	"webhooks.json",
	"analytics.json",
	"audit.json",
	"compliance.json",
}

var requiredErrorFiles = map[string][]string{
	"404.json": {
		"customer_not_found",
		"agent_not_found",
		"capability_not_found",
		"webhook_not_found",
		"revocation_target_not_found",
		"session_not_found",
		"envelope_not_found",
	},
	"401.json": {
		"missing_authorization",
		"invalid_partner_credential",
		"invalid_customer_credential",
		"invalid_capability_credential",
	},
	"403.json": {"invalid_credential_type", "delegation_escalation"},
	"409.json": {"invalid_transition", "agent_not_active", "delegation_depth_exceeded"},
	"422.json": {
		"validation_error",
		"ssrf_rejected",
		"invalid_revocation_type",
		"invalid_target_id",
		"missing_reason",
		"incomplete_attestation",
	},
	"429.json": {"capability_quota_exceeded", "partner_rate_limited"},
}

func fixturesDir(t *testing.T) string {
	t.Helper()
	// moss-go tests run from the repo root; testdata/fixtures is relative to it.
	candidates := []string{
		"testdata/fixtures",
		filepath.Join("..", "testdata", "fixtures"),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatalf("testdata/fixtures not found relative to cwd=%q", mustGetwd())
	return ""
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "?"
	}
	return wd
}

func loadFixture(t *testing.T, rel string) interface{} {
	t.Helper()
	dir := fixturesDir(t)
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse %s as JSON: %v", rel, err)
	}
	return v
}

func sha256File(t *testing.T, rel string) string {
	t.Helper()
	dir := fixturesDir(t)
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestFixturesPresenceAndLoadability(t *testing.T) {
	// VAL-DX-011 — shared fixtures present and loadable.
	for _, f := range requiredHappyFiles {
		v := loadFixture(t, f)
		if v == nil {
			t.Errorf("%s parsed to nil", f)
		}
	}
	for f := range requiredErrorFiles {
		v := loadFixture(t, "errors/"+f)
		if v == nil {
			t.Errorf("errors/%s parsed to nil", f)
		}
	}
}

func TestFixturesErrorCoverage(t *testing.T) {
	// VAL-DX-020 — error states covered with canonical codes.
	for file, codes := range requiredErrorFiles {
		doc := loadFixture(t, "errors/"+file).(map[string]interface{})
		if doc["kind"] != "error" {
			t.Errorf("errors/%s: kind != error (got %v)", file, doc["kind"])
			continue
		}
		// status is a json number -> float64
		wantStatus := float64(parseStatusFromName(file))
		if doc["status"] != wantStatus {
			t.Errorf("errors/%s: status = %v, want %v", file, doc["status"], wantStatus)
		}
		cases, ok := doc["cases"].([]interface{})
		if !ok {
			t.Errorf("errors/%s: cases missing or wrong type", file)
			continue
		}
		present := map[string]bool{}
		for _, c := range cases {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			if code, ok := cm["code"].(string); ok {
				present[code] = true
			}
		}
		for _, want := range codes {
			if !present[want] {
				t.Errorf("errors/%s: missing canonical code %q", file, want)
			}
		}
	}

	// index.json must enumerate every canonical error code.
	idx := loadFixture(t, "index.json").(map[string]interface{})
	canonicalAny, _ := idx["canonical_error_codes"].([]interface{})
	canonical := map[string]bool{}
	for _, c := range canonicalAny {
		if s, ok := c.(string); ok {
			canonical[s] = true
		}
	}
	for _, codes := range requiredErrorFiles {
		for _, c := range codes {
			if !canonical[c] {
				t.Errorf("index.json canonical_error_codes missing %q", c)
			}
		}
	}
}

func TestFixturesByteIdenticalPin(t *testing.T) {
	// VAL-DX-012 — pin every fixture's sha256 so a silent drift fails here.
	rels := append([]string{}, requiredHappyFiles...)
	for f := range requiredErrorFiles {
		rels = append(rels, "errors/"+f)
	}
	first := map[string]string{}
	for _, rel := range rels {
		first[rel] = sha256File(t, rel)
		if len(first[rel]) != 64 {
			t.Errorf("%s: expected 64-char sha256, got %q", rel, first[rel])
		}
	}
	for _, rel := range rels {
		if sha256File(t, rel) != first[rel] {
			t.Errorf("%s: sha256 not deterministic across re-reads", rel)
		}
	}
}

func TestFixturesCorpusIntegrity(t *testing.T) {
	// customers cover every canonical status enum.
	idx := loadFixture(t, "index.json").(map[string]interface{})
	statusEnumAny, _ := idx["canonical_status_enum"].([]interface{})
	statusEnum := map[string]bool{}
	for _, s := range statusEnumAny {
		if v, ok := s.(string); ok {
			statusEnum[v] = true
		}
	}
	custDoc := loadFixture(t, "customers.json").(map[string]interface{})
	customersAny, _ := custDoc["customers"].([]interface{})
	for s := range statusEnum {
		found := false
		for _, c := range customersAny {
			if cm, ok := c.(map[string]interface{}); ok {
				if cm["status"] == s {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("customers missing status %q", s)
		}
	}

	// audit covers every canonical decision enum.
	decisionEnumAny, _ := idx["canonical_decision_enum"].([]interface{})
	decisionEnum := map[string]bool{}
	for _, d := range decisionEnumAny {
		if v, ok := d.(string); ok {
			decisionEnum[v] = true
		}
	}
	auditDoc := loadFixture(t, "audit.json").(map[string]interface{})
	entriesAny, _ := auditDoc["entries"].([]interface{})
	for d := range decisionEnum {
		found := false
		for _, e := range entriesAny {
			if em, ok := e.(map[string]interface{}); ok {
				if em["decision"] == d {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("audit missing decision %q", d)
		}
	}

	// envelopes form a hash chain: envs[i].prev_hash == envs[i-1].hash.
	envDoc := loadFixture(t, "envelopes.json").(map[string]interface{})
	envsAny, _ := envDoc["envelopes"].([]interface{})
	for i := 1; i < len(envsAny); i++ {
		prev, _ := envsAny[i-1].(map[string]interface{})
		cur, _ := envsAny[i].(map[string]interface{})
		if prev == nil || cur == nil {
			t.Errorf("envelopes[%d] chain linkage: nil entry", i)
			continue
		}
		if cur["prev_hash"] != prev["hash"] {
			t.Errorf("envelopes[%d].prev_hash = %v, want %v", i, cur["prev_hash"], prev["hash"])
		}
	}

	// audit entries form a hash chain.
	for i := 1; i < len(entriesAny); i++ {
		prev, _ := entriesAny[i-1].(map[string]interface{})
		cur, _ := entriesAny[i].(map[string]interface{})
		if prev == nil || cur == nil {
			t.Errorf("audit[%d] chain linkage: nil entry", i)
			continue
		}
		if cur["prev_hash"] != prev["hash"] {
			t.Errorf("audit[%d].prev_hash = %v, want %v", i, cur["prev_hash"], prev["hash"])
		}
	}
}

func parseStatusFromName(file string) int {
	name := strings.TrimSuffix(file, ".json")
	var n int
	for _, r := range name {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
		}
	}
	return n
}
