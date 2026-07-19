package moss

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Mock-driven SDK unit test for moss-go (M3 devtools).
//
// Starts the Prism mock server (scripts/mock.sh) against the vendored spec
// (testdata/openapi.json) on :4010 in request-validation mode (--errors =>
// malformed bodies => 422) with a fixed seed (m3mock) so responses are
// byte-identical across moss-sdk-ts, moss-agent-sdk, and moss-go.
//
// Asserts the canonical mock contract in testdata/mock-contract.json:
//   - Prism serves /health, a customers endpoint, the new session/introspect
//     routes, and the compliance-report route (application/pdf) — VAL-DX-007,
//     008, 009, 010, 019.
//   - Prism VALIDATES request bodies: a malformed body => 422, not 200 — VAL-DX-018.
//   - The same vendored spec + Prism produce identical responses across repos
//     (pinned sha256 per case) — VAL-DX-013, 014.
//
// Fulfills: VAL-DX-007, VAL-DX-008, VAL-DX-009, VAL-DX-010, VAL-DX-013,
// VAL-DX-014, VAL-DX-018, VAL-DX-019.

const mockBaseURL = "http://localhost:4010"

type contractCase struct {
	Name                    string                 `json:"name"`
	Method                  string                 `json:"method"`
	Path                    string                 `json:"path"`
	PathParams              map[string]string      `json:"path_params,omitempty"`
	Headers                 map[string]string      `json:"headers,omitempty"`
	Body                    json.RawMessage        `json:"body,omitempty"`
	ExpectedStatus          int                    `json:"expected_status"`
	ExpectedContentTypePref string                 `json:"expected_content_type_prefix"`
	ExpectedSha256          *string                `json:"expected_sha256"`
	// internal helper: decoded contract preserves order via the cases slice.
}

type mockContract struct {
	BaseURL    string         `json:"base_url"`
	CustomerID string         `json:"customer_id"`
	Cases      []contractCase `json:"cases"`
}

func loadMockContract(t *testing.T) *mockContract {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	path := filepath.Join(root, "testdata", "mock-contract.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read mock-contract.json: %v", err)
	}
	var c mockContract
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("parse mock-contract.json: %v", err)
	}
	return &c
}

func repoRoot() (string, error) {
	// testdata/ sits at the repo root alongside the *_test.go files.
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(wd, "testdata", "openapi.json")); err == nil {
		return wd, nil
	}
	// Fallback: walk up a few levels.
	for i := 0; i < 4; i++ {
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
		if _, err := os.Stat(filepath.Join(wd, "testdata", "openapi.json")); err == nil {
			return wd, nil
		}
	}
	return "", fmt.Errorf("could not locate repo root with testdata/openapi.json from %s", wd)
}

// ---- Prism lifecycle: start once per process if not already running. ----

var (
	prismOnce    sync.Once
	prismUp      bool
	prismChild   *exec.Cmd
	prismStarted bool
)

// TestMain starts Prism lazily (only when a mock test calls ensurePrism),
// runs the whole package's tests, then kills the Prism process group iff
// this process started it. Keeps the mock test self-contained for CI while
// not leaking a process for local `go test ./...`.
func TestMain(m *testing.M) {
	code := m.Run()
	if prismStarted && prismChild != nil && prismChild.Process != nil {
		// Kill the whole process group (bash -> npx -> prism node) so the
		// grandchild prism process is not orphaned to init.
		_ = syscall.Kill(-prismChild.Process.Pid, syscall.SIGTERM)
		_, _ = prismChild.Process.Wait()
	}
	os.Exit(code)
}

func ensurePrism(t *testing.T) {
	t.Helper()
	prismOnce.Do(func() {
		if probeMockHealth() {
			prismUp = true
			return
		}
		root, err := repoRoot()
		if err != nil {
			t.Fatalf("repoRoot: %v", err)
		}
		mockScript := filepath.Join(root, "scripts", "mock.sh")
		if _, err := os.Stat(mockScript); err != nil {
			t.Fatalf("mock.sh not found at %s: %v", mockScript, err)
		}
		// Start Prism as a child of the test binary in its own process group;
		// TestMain kills the whole group on exit (npx spawns prism as a
		// grandchild, so killing only the bash PID would orphan prism).
		cmd := exec.Command("bash", mockScript)
		cmd.Dir = root
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		// Silence Prism's verbose request logging in test output.
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			t.Fatalf("start mock.sh: %v", err)
		}
		prismChild = cmd
		prismStarted = true
		// Wait for health (npx cold-fetch can take ~75s; allow 120s).
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			if probeMockHealth() {
				prismUp = true
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("Prism did not become healthy on %s within 120s. "+
			"Run 'make mock' in another terminal, or ensure npx can fetch @stoplight/prism-cli.",
			mockBaseURL)
	})
	if !prismUp {
		t.Fatalf("Prism is not up on %s", mockBaseURL)
	}
}

func probeMockHealth() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(mockBaseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// ---- HTTP helper ----

func buildMockPath(c contractCase) string {
	p := c.Path
	for k, v := range c.PathParams {
		p = strings.ReplaceAll(p, "{"+k+"}", v)
	}
	return p
}

func runMockCase(t *testing.T, c contractCase) (status int, contentType string, body []byte) {
	t.Helper()
	var bodyReader io.Reader
	if len(c.Body) > 0 {
		bodyReader = bytes.NewReader(c.Body)
	}
	req, err := http.NewRequest(c.Method, mockBaseURL+buildMockPath(c), bodyReader)
	if err != nil {
		t.Fatalf("%s: build request: %v", c.Name, err)
	}
	hasCT := false
	for k, v := range c.Headers {
		req.Header.Set(k, v)
		if strings.EqualFold(k, "Content-Type") {
			hasCT = true
		}
	}
	if len(c.Body) > 0 && !hasCT {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s: do request: %v", c.Name, err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read body: %v", c.Name, err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), body
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ---- Tests ----

func TestPrismMockContract(t *testing.T) {
	ensurePrism(t)
	contract := loadMockContract(t)

	for _, c := range contract.Cases {
		c := c // capture
		t.Run(c.Name+"_status_and_content_type", func(t *testing.T) {
			status, ct, _ := runMockCase(t, c)
			if status != c.ExpectedStatus {
				t.Errorf("%s: expected status %d, got %d", c.Name, c.ExpectedStatus, status)
			}
			if !strings.Contains(strings.ToLower(ct), strings.ToLower(c.ExpectedContentTypePref)) {
				t.Errorf("%s: expected content-type to contain %q, got %q", c.Name, c.ExpectedContentTypePref, ct)
			}
		})
		if c.ExpectedSha256 != nil && *c.ExpectedSha256 != "" {
			expected := *c.ExpectedSha256
			c := c
			t.Run(c.Name+"_sha256_pinned", func(t *testing.T) {
				_, _, body := runMockCase(t, c)
				got := sha256Hex(body)
				if got != expected {
					t.Errorf("%s: sha256 mismatch.\n  expected: %s\n  got:      %s", c.Name, expected, got)
				}
			})
		}
	}
}

func TestPrismMockRequestBodyValidation(t *testing.T) {
	ensurePrism(t)
	contract := loadMockContract(t)

	t.Run("customers_create_malformed_is_422", func(t *testing.T) {
		c := findCase(contract, "customers_create_malformed")
		status, _, _ := runMockCase(t, c)
		if status != 422 {
			t.Fatalf("expected 422 for malformed customers POST, got %d", status)
		}
	})

	t.Run("introspect_malformed_is_422", func(t *testing.T) {
		c := findCase(contract, "introspect_malformed")
		status, _, _ := runMockCase(t, c)
		if status != 422 {
			t.Fatalf("expected 422 for malformed introspect POST, got %d", status)
		}
	})
}

func TestPrismMockComplianceReportPDF(t *testing.T) {
	ensurePrism(t)
	contract := loadMockContract(t)
	c := findCase(contract, "compliance_report_pdf")
	status, ct, body := runMockCase(t, c)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if !strings.Contains(strings.ToLower(ct), "application/pdf") {
		t.Fatalf("expected application/pdf content-type, got %q", ct)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty pdf body")
	}
	if sha256Hex(body) != *c.ExpectedSha256 {
		t.Errorf("compliance_report_pdf: sha256 mismatch.\n  expected: %s\n  got:      %s",
			*c.ExpectedSha256, sha256Hex(body))
	}
}

func findCase(contract *mockContract, name string) contractCase {
	for _, c := range contract.Cases {
		if c.Name == name {
			return c
		}
	}
	panic(fmt.Sprintf("mock contract case %q not found", name))
}
