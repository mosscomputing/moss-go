package partner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionMintShapeAndTTL(t *testing.T) {
	// VAL-SDKP-014/016 — session() mints a cust_ token, returns scoped client;
	// TTL ~15 minutes.
	before := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/session") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		expires := time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{
			"session_id":"55555555-5555-4555-8555-555555555501",
			"customer_id":"33333333-3333-4333-8333-333333333301",
			"token":"cust_SESSION_SECRET",
			"prefix":"cust_1",
			"expires_at":"` + expires + `"
		}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	res, err := c.Customers.Session(context.Background(), "33333333-3333-4333-8333-333333333301", &SessionOpts{IdempotencyKey: "idem-sess"})
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if res.Mint == nil || res.Client == nil {
		t.Fatalf("SessionResult incomplete: %+v", res)
	}
	if !strings.HasPrefix(res.Mint.Token, "cust_") {
		t.Errorf("mint token = %q, want cust_ prefix", res.Mint.Token)
	}
	if res.Mint.SessionID == "" || res.Mint.CustomerID != "33333333-3333-4333-8333-333333333301" {
		t.Errorf("mint shape wrong: %+v", res.Mint)
	}
	if res.Mint.Prefix != "cust_1" {
		t.Errorf("prefix = %q, want cust_1", res.Mint.Prefix)
	}
	// TTL ~15 minutes (900s ± 60s tolerance).
	ttl := res.Mint.TTLSeconds()
	if ttl < 840 || ttl > 960 {
		t.Errorf("ttl = %ds, want 840-960 (15min ±60s)", ttl)
	}
	_ = before
	// The scoped client is a cust_-persona client bound to the minted token.
	if res.Client.Persona() != PersonaCustomer {
		t.Errorf("scoped persona = %q, want customer", res.Client.Persona())
	}
	if res.Client.Token() != "cust_SESSION_SECRET" {
		t.Errorf("scoped token = %q, want the minted cust_ token", res.Client.Token())
	}
	if res.Client.BaseURL() != srv.URL {
		t.Errorf("scoped base URL = %q, want %s", res.Client.BaseURL(), srv.URL)
	}
}

func TestAsCustomerIsAliasForSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"session_id":"s1","customer_id":"c1","token":"cust_x","prefix":"cust_1","expires_at":"2026-07-19T12:15:00Z"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	res, err := c.Customers.AsCustomer(context.Background(), "c1", nil)
	if err != nil {
		t.Fatalf("AsCustomer: %v", err)
	}
	if res.Mint.Token != "cust_x" {
		t.Errorf("AsCustomer mint token = %q", res.Mint.Token)
	}
}

func TestSessionForeignCustomerNotFoundError(t *testing.T) {
	// VAL-SDKP-018 — session on foreign customer raises NotFoundError (404).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"Resource not found","request_id":"r1"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	_, err := c.Customers.Session(context.Background(), "foreign-id", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %T: %v", err, err)
	}
	if Status(err) != 404 {
		t.Errorf("status = %d, want 404", Status(err))
	}
}

func TestSessionConflictOnDeactivatedCustomer(t *testing.T) {
	// A deactivated customer is rejected with 409 customer_not_active.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"error":"customer_not_active","message":"Cannot mint for deactivated customer","current_status":"deactivated","request_id":"r1"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	_, err := c.Customers.Session(context.Background(), "c1", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsConflict(err) {
		t.Fatalf("expected ConflictError, got %T: %v", err, err)
	}
	if Code(err) != "customer_not_active" {
		t.Errorf("code = %q, want customer_not_active", Code(err))
	}
}

func TestRevokeSessionSuccess(t *testing.T) {
	// VAL-SDKP-017 — revoke returns success (204); sends DELETE.
	var method, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	err := c.Customers.RevokeSession(context.Background(), "c1", "sess-1")
	if err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", method)
	}
	if !strings.Contains(body, `"session_id":"sess-1"`) {
		t.Errorf("body = %q, want session_id sess-1 in body", body)
	}
}

func TestRevokeSessionAllWhenEmptyID(t *testing.T) {
	// Empty session_id => revoke ALL (empty body).
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	err := c.Customers.RevokeSession(context.Background(), "c1", "")
	if err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if strings.Contains(body, "session_id") {
		t.Errorf("body should omit session_id for revoke-all, got %q", body)
	}
}

func TestRevokeSessionForeignNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"Resource not found","request_id":"r1"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	err := c.Customers.RevokeSession(context.Background(), "foreign", "s1")
	if !IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}

func TestScopedClientSendsCustToken(t *testing.T) {
	// The minted scoped client uses the cust_ token on its requests, not prt_.
	// The scoped client is a customer-persona client; it cannot call
	// partner-only methods (customers.list) — that is asserted in
	// TestScopedClientRejectsPartnerRoute. Here we drive a raw transport
	// request through the scoped client to confirm it sends the cust_ token.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/session") {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"session_id":"s1","customer_id":"c1","token":"cust_scoped","prefix":"cust_1","expires_at":"2026-07-19T12:15:00Z"}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_partner", BaseURL: srv.URL})
	res, err := c.Customers.Session(context.Background(), "c1", nil)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	// Drive a raw GET through the scoped client's transport (no persona gate).
	_, _, _, err = res.Client.do(context.Background(), requestOptions{method: http.MethodGet, path: "/v1/anything"})
	if err != nil {
		t.Fatalf("scoped do: %v", err)
	}
	if gotAuth != "Bearer cust_scoped" {
		t.Errorf("scoped client Authorization = %q, want Bearer cust_scoped", gotAuth)
	}
}

func TestScopedClientRejectsPartnerRoute(t *testing.T) {
	// VAL-SDKP-015/024 — the scoped cust_ client is rejected on partner routes
	// (customers.list) with a typed AuthError (invalid_credential_type), not a
	// silent 401 deep in a call. The SDK fails fast client-side with the same
	// typed error the backend would produce.
	scoped, _ := NewClient(Config{Token: "cust_scoped", BaseURL: "http://x"})
	_, err := scoped.Customers.List(context.Background(), nil)
	if err == nil {
		t.Fatal("scoped cust_ client should reject partner-only customers.list")
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

func mustNew(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// ---- ensure imports used ----
var _ = errors.As
var _ = base64.StdEncoding
var _ = hex.EncodeToString
