package partner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- Client construction, defaults, persona inference ----

func TestNewClientDefaults(t *testing.T) {
	c, err := NewClient(Config{Token: "prt_test"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.BaseURL() != DefaultBaseURL {
		t.Errorf("default base URL = %q, want %q", c.BaseURL(), DefaultBaseURL)
	}
	if c.Persona() != PersonaPartner {
		t.Errorf("persona = %q, want %q", c.Persona(), PersonaPartner)
	}
	if c.TokenPrefix() != "prt_" {
		t.Errorf("token prefix = %q, want prt_", c.TokenPrefix())
	}
	if c.MaxRetries() != DefaultMaxRetries {
		t.Errorf("max retries = %d, want %d", c.MaxRetries(), DefaultMaxRetries)
	}
	if c.Customers == nil || c.Compliance == nil {
		t.Errorf("resource namespaces not initialized")
	}
}

func TestNewClientBaseURLOverride(t *testing.T) {
	// VAL-SDKP-001 — base URL is overridable; trailing slash normalized.
	for _, in := range []string{"http://localhost:4010", "http://localhost:4010/"} {
		c, err := NewClient(Config{Token: "prt_test", BaseURL: in})
		if err != nil {
			t.Fatalf("NewClient(%q): %v", in, err)
		}
		if c.BaseURL() != "http://localhost:4010" {
			t.Errorf("base URL for %q = %q, want http://localhost:4010", in, c.BaseURL())
		}
	}
}

func TestNewClientPersonaInference(t *testing.T) {
	// VAL-SDKP-002 — persona inferred from token prefix.
	cases := []struct {
		token string
		want  Persona
	}{
		{"prt_abc", PersonaPartner},
		{"cust_xyz", PersonaCustomer},
		{"cap_123", PersonaCapability},
		{"moss_live_xx", PersonaUnknown},
		{"", PersonaUnknown},
	}
	for _, tc := range cases {
		if tc.token == "" {
			continue
		}
		c, err := NewClient(Config{Token: tc.token})
		if err != nil {
			t.Fatalf("NewClient(%q): %v", tc.token, err)
		}
		if c.Persona() != tc.want {
			t.Errorf("persona for %q = %q, want %q", tc.token, c.Persona(), tc.want)
		}
	}
	// Empty token is rejected.
	if _, err := NewClient(Config{Token: ""}); err == nil {
		t.Error("empty token should be rejected")
	}
}

func TestRequirePartner(t *testing.T) {
	// VAL-SDKP-002/024 — a cust_ token on a partner-only method surfaces a
	// typed AuthError (invalid_credential_type), failing fast client-side
	// with the same error the backend would produce — not a silent 401 deep
	// in a call.
	c, _ := NewClient(Config{Token: "cust_test"})
	err := c.Customers.createNoSend(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuth(err) {
		t.Fatalf("expected AuthError, got %T: %v", err, err)
	}
	if Code(err) != "invalid_credential_type" {
		t.Errorf("code = %q, want invalid_credential_type", Code(err))
	}
	if !strings.Contains(err.Error(), "partner (prt_) token") {
		t.Errorf("expected message naming the expected prefix, got: %v", err)
	}
}

// ---- Typed error hierarchy ----

func TestTypedErrorMapping(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		headers   http.Header
		wantCode  string
		checkFunc func(*testing.T, error)
	}{
		{"404 NotFound", 404, `{"error":"customer_not_found","message":"nope","request_id":"r1"}`, nil, "customer_not_found", func(t *testing.T, e error) {
			var nfe *NotFoundError
			if !errors.As(e, &nfe) {
				t.Fatalf("not NotFoundError: %T", e)
			}
			var ae *AuthError
			if errors.As(e, &ae) {
				t.Error("404 must not be AuthError")
			}
		}},
		{"404 uniform handler", 404, `{"error":"not_found","message":"Resource not found","request_id":"r2"}`, nil, "not_found", func(t *testing.T, e error) {
			var nfe *NotFoundError
			if !errors.As(e, &nfe) {
				t.Fatalf("uniform 404 not NotFoundError: %T", e)
			}
		}},
		{"401 Auth", 401, `{"error":"unauthorized","message":"bad","request_id":"r3"}`, nil, "unauthorized", func(t *testing.T, e error) {
			var ae *AuthError
			if !errors.As(e, &ae) {
				t.Fatalf("not AuthError: %T", e)
			}
		}},
		{"403 Auth invalid_credential_type", 403, `{"error":"invalid_credential_type","message":"A partner (prt_) credential is required","request_id":"r4"}`, nil, "invalid_credential_type", func(t *testing.T, e error) {
			var ae *AuthError
			if !errors.As(e, &ae) {
				t.Fatalf("403 not AuthError: %T", e)
			}
		}},
		{"409 Conflict invalid_transition", 409, `{"error":"invalid_transition","message":"Cannot promote","current_status":"suspended","request_id":"r5"}`, nil, "invalid_transition", func(t *testing.T, e error) {
			var ce *ConflictError
			if !errors.As(e, &ce) {
				t.Fatalf("409 not ConflictError: %T", e)
			}
			if CurrentStatus(e) != "suspended" {
				t.Errorf("current_status = %q, want suspended", CurrentStatus(e))
			}
		}},
		{"422 Validation", 422, `{"error":"validation_error","message":"bad","request_id":"r6","details":[{"loc":["body","name"],"msg":"field required"}]}`, nil, "validation_error", func(t *testing.T, e error) {
			var ve *ValidationError
			if !errors.As(e, &ve) {
				t.Fatalf("422 not ValidationError: %T", e)
			}
		}},
		{"429 RateLimit with Retry-After", 429, `{"error":"partner_rate_limited","message":"slow","request_id":"r7"}`, http.Header{"Retry-After": {"60"}}, "partner_rate_limited", func(t *testing.T, e error) {
			var rle *RateLimitError
			if !errors.As(e, &rle) {
				t.Fatalf("429 not RateLimitError: %T", e)
			}
			if rle.RetryAfter != 60*time.Second {
				t.Errorf("retry-after = %v, want 60s", rle.RetryAfter)
			}
		}},
		{"429 RateLimit without Retry-After", 429, `{"error":"webhooks_per_customer_exceeded","message":"cap","request_id":"r8"}`, nil, "webhooks_per_customer_exceeded", func(t *testing.T, e error) {
			var rle *RateLimitError
			if !errors.As(e, &rle) {
				t.Fatalf("429 not RateLimitError: %T", e)
			}
			if rle.RetryAfter != 0 {
				t.Errorf("retry-after = %v, want 0 (absent)", rle.RetryAfter)
			}
		}},
		{"500 Server", 500, `{"error":"internal","message":"boom","request_id":"r9"}`, nil, "internal", func(t *testing.T, e error) {
			var se *ServerError
			if !errors.As(e, &se) {
				t.Fatalf("500 not ServerError: %T", e)
			}
		}},
		{"503 Server", 503, `{"error":"internal","message":"down","request_id":"r10"}`, nil, "internal", func(t *testing.T, e error) {
			var se *ServerError
			if !errors.As(e, &se) {
				t.Fatalf("503 not ServerError: %T", e)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			_ = json.Unmarshal([]byte(tc.body), &body)
			err := asTypedError(tc.status, body, tc.headers, []byte(tc.body))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			tc.checkFunc(t, err)
			if Code(err) != tc.wantCode {
				t.Errorf("code = %q, want %q", Code(err), tc.wantCode)
			}
			if Status(err) != tc.status {
				t.Errorf("status = %d, want %d", Status(err), tc.status)
			}
		})
	}
}

func TestRetryAfterParsing(t *testing.T) {
	cases := []struct {
		hdr  http.Header
		want time.Duration
	}{
		{http.Header{"Retry-After": {"30"}}, 30 * time.Second},
		{http.Header{"Retry-After": {"0"}}, 0},
		{http.Header{"Retry-After": {""}}, 0},
		{nil, 0},
		{http.Header{"Retry-After": {"junk"}}, 0},
	}
	for i, tc := range cases {
		got := parseRetryAfter(tc.hdr)
		if got != tc.want {
			t.Errorf("case %d: parseRetryAfter = %v, want %v", i, got, tc.want)
		}
	}
}

// ---- Retry / backoff (httptest-driven) ----

func TestRetryOn5xxThenSuccess(t *testing.T) {
	// VAL-SDKP-028 — GET retries on 5xx with exponential backoff; eventually
	// succeeds when the server recovers.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"pending"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 3, Timeout: 5 * time.Second})
	got, err := c.Customers.Get(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CustomerID != "c1" {
		t.Errorf("customer_id = %q, want c1", got.CustomerID)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryOn5xxAllFailRaisesServerError(t *testing.T) {
	// VAL-SDKP-028 — persistent 5xx raises ServerError after max retries.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"internal","message":"boom"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 2, Timeout: 5 * time.Second})
	_, err := c.Customers.Get(context.Background(), "c1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var se *ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected ServerError, got %T: %v", err, err)
	}
	// 1 initial + 2 retries = 3 attempts.
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryOn429HonorsRetryAfter(t *testing.T) {
	// VAL-SDKP-027 — 429 then 200; the retry waits >= Retry-After.
	calls := 0
	var firstAttempt time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			firstAttempt = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"error":"partner_rate_limited","message":"slow"}`))
			return
		}
		gap := time.Since(firstAttempt)
		if gap < 900*time.Millisecond {
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"error":"too_soon"}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"pending"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 3, Timeout: 10 * time.Second})
	got, err := c.Customers.Get(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CustomerID != "c1" {
		t.Errorf("customer_id = %q, want c1", got.CustomerID)
	}
}

func TestMutationNotRetried(t *testing.T) {
	// VAL-SDKC-024 — a mutation without an Idempotency-Key is NOT retried.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"internal","message":"boom"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 3, Timeout: 5 * time.Second})
	_, err := c.Customers.Update(context.Background(), "c1", &UpdateCustomerRequest{Limits: map[string]any{"agents": 5}})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("mutation must not be retried without idempotency-key; calls = %d, want 1", calls)
	}
}

func TestMutationWithIdempotencyKeyRetried(t *testing.T) {
	// A mutation WITH an Idempotency-Key is safely replayable => retried.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 2 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"internal","message":"down"}`))
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"pending"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 3, Timeout: 5 * time.Second})
	_, err := c.Customers.Create(context.Background(), &CreateCustomerRequest{ExternalID: "e", Name: "n"}, "idem-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if calls != 2 {
		t.Errorf("idempotent mutation should retry; calls = %d, want 2", calls)
	}
}

func TestIdempotencyKeyHeaderPassthrough(t *testing.T) {
	// VAL-SDKP-004 — Idempotency-Key is passed through to the backend.
	var gotHdr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Get("Idempotency-Key")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"pending"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	_, _ = c.Customers.Create(context.Background(), &CreateCustomerRequest{ExternalID: "e", Name: "n"}, "idem-xyz")
	if gotHdr != "idem-xyz" {
		t.Errorf("Idempotency-Key hdr = %q, want idem-xyz", gotHdr)
	}
}

func TestAuthorizationBearerHeader(t *testing.T) {
	// The transport sends Authorization: Bearer <token>.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customers":[]}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_secret", BaseURL: srv.URL})
	_, _ = c.Customers.List(context.Background(), nil)
	if gotAuth != "Bearer prt_secret" {
		t.Errorf("Authorization = %q, want Bearer prt_secret", gotAuth)
	}
}

// ---- helpers ----

// createNoSend is a test-only stand-in that exercises requirePartner without
// making a network call. It mirrors the precondition check in Create.
func (s *CustomersService) createNoSend(ctx context.Context) error {
	return s.c.requirePartner("customers.create")
}

// Ensure imports used.
var _ = io.EOF
var _ = fmt.Sprintf
