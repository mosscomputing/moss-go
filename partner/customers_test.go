package partner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Shape tests for the customers resource namespace. These use a local
// httptest.Server returning canned JSON shaped like the real backend, so they
// assert the SDK deserializes the canonical field names/status strings
// deterministically (the Prism mock returns opaque {} objects for
// additionalProperties:true schemas, so it cannot assert shapes).
//
// The Prism mock (:4010) is exercised in mock_test.go for status/error/
// validation behaviors. The real backend (:3100) is exercised in
// e2e_test.go for end-to-end shapes + lifecycle transitions.

func TestCustomersCreateShape(t *testing.T) {
	// VAL-SDKP-003 — create returns id, status, cust_ token; echoes name/external_id.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/partner/customers" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{
			"customer_id":"33333333-3333-4333-8333-333333333303",
			"external_id":"ext-1","name":"Cust One",
			"status":"pending","partner_id":"11111111-1111-4111-8111-111111111111",
			"created_at":"2026-07-19T12:00:00Z",
			"credentials":{"customer_token":{"token":"cust_SECRET","prefix":"cust_1"}}
		}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Create(context.Background(), &CreateCustomerRequest{ExternalID: "ext-1", Name: "Cust One"}, "idem-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.CustomerID != "33333333-3333-4333-8333-333333333303" {
		t.Errorf("customer_id = %q", got.CustomerID)
	}
	if got.Status != StatusPending {
		t.Errorf("status = %q, want pending", got.Status)
	}
	if got.Name != "Cust One" || got.ExternalID != "ext-1" {
		t.Errorf("echo: name=%q external_id=%q", got.Name, got.ExternalID)
	}
	if got.Credentials == nil || !strings.HasPrefix(got.Credentials.CustomerToken.Token, "cust_") {
		t.Errorf("credentials.customer_token.token missing cust_ prefix: %+v", got.Credentials)
	}
	if got.Credentials.CustomerToken.Prefix != "cust_1" {
		t.Errorf("prefix = %q, want cust_1", got.Credentials.CustomerToken.Prefix)
	}
}

func TestCustomersGetShape(t *testing.T) {
	// VAL-SDKP-005 — get returns governance + limits + status.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{
			"customer_id":"33333333-3333-4333-8333-333333333301",
			"name":"Northwind AI","status":"sandbox_active",
			"governance":{"frameworks_active":["GDPR","EU_AI_ACT","DORA"],"policies_inherited":12,"compliance_score":742},
			"limits":{"agents":50,"capability_tokens_per_hour":1000,"webhooks":25}
		}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Get(context.Background(), "33333333-3333-4333-8333-333333333301")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusSandboxActive {
		t.Errorf("status = %q, want sandbox_active", got.Status)
	}
	if got.Governance == nil || got.Governance.ComplianceScore == nil || *got.Governance.ComplianceScore != 742 {
		t.Errorf("governance.compliance_score mismatch: %+v", got.Governance)
	}
	if got.Limits == nil || got.Limits.Agents != 50 {
		t.Errorf("limits.agents mismatch: %+v", got.Limits)
	}
}

func TestCustomersListShapeAndPagination(t *testing.T) {
	// VAL-SDKP-006/007 — list returns the partner's customers with status;
	// pagination via next_cursor.
	var lastCursor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		lastCursor = cursor
		if cursor == "" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{
				"customers":[
					{"customer_id":"c1","name":"n1","status":"sandbox_active"},
					{"customer_id":"c2","name":"n2","status":"production_active"}
				],
				"next_cursor":"bmV4dDpwYWdlOjI="
			}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{
			"customers":[{"customer_id":"c3","name":"n3","status":"pending"}]
		}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	page1, err := c.Customers.List(context.Background(), &ListCustomersOptions{Limit: 2})
	if err != nil {
		t.Fatalf("List page1: %v", err)
	}
	if len(page1.Customers) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1.Customers))
	}
	if page1.NextCursor == "" {
		t.Fatal("page1 next_cursor empty")
	}
	// Every entry carries a status.
	for _, cust := range page1.Customers {
		if cust.Status == "" {
			t.Errorf("customer %q missing status", cust.CustomerID)
		}
	}
	page2, err := c.Customers.List(context.Background(), &ListCustomersOptions{Cursor: page1.NextCursor})
	if err != nil {
		t.Fatalf("List page2: %v", err)
	}
	if len(page2.Customers) != 1 || page2.Customers[0].CustomerID != "c3" {
		t.Errorf("page2 mismatch: %+v", page2.Customers)
	}
	if page2.NextCursor != "" {
		t.Errorf("page2 next_cursor = %q, want empty (end)", page2.NextCursor)
	}
	if lastCursor != page1.NextCursor {
		t.Errorf("cursor not passed through: got %q want %q", lastCursor, page1.NextCursor)
	}
}

func TestCustomersUpdateShape(t *testing.T) {
	// VAL-SDKP-008 — update persists and reflects on next get.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("update method = %s, want PATCH", r.Method)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{
			"customer_id":"c1","name":"n","status":"sandbox_active",
			"limits":{"agents":99,"capability_tokens_per_hour":1000}
		}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Update(context.Background(), "c1", &UpdateCustomerRequest{Limits: map[string]any{"agents": 99}})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.Limits == nil || got.Limits.Agents != 99 {
		t.Errorf("post-update limits.agents = %+v, want 99", got.Limits)
	}
}

func TestCustomersDeactivateShape(t *testing.T) {
	// VAL-SDKP-009 — deactivate soft-deletes; status deactivated; still retrievable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("deactivate method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"deactivated"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Deactivate(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if got.Status != StatusDeactivated {
		t.Errorf("status = %q, want deactivated", got.Status)
	}
}

func TestCustomersPromoteShape(t *testing.T) {
	// VAL-SDKP-010 — promote surfaces sandbox_active -> production_active.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/promote") {
			t.Errorf("promote path = %s", r.URL.Path)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"production_active"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Promote(context.Background(), "c1", &PromoteCustomerRequest{
		Attestation: PromoteAttestation{KYCCompleted: true, TermsAccepted: true, ComplianceReviewed: true},
		Billing:     PromoteBilling{Tier: "production"},
	}, "idem-prom")
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if got.Status != StatusProductionActive {
		t.Errorf("status = %q, want production_active", got.Status)
	}
}

func TestCustomersSuspendShape(t *testing.T) {
	// VAL-SDKP-011 — suspend surfaces active -> suspended with reason persisted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/suspend") {
			t.Errorf("suspend path = %s", r.URL.Path)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"suspended","settings":{"suspension_reason":"billing_overdue"}}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Suspend(context.Background(), "c1", &SuspendCustomerRequest{Reason: "billing_overdue"})
	if err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if got.Status != StatusSuspended {
		t.Errorf("status = %q, want suspended", got.Status)
	}
	if got.Settings["suspension_reason"] != "billing_overdue" {
		t.Errorf("suspension_reason = %v, want billing_overdue", got.Settings["suspension_reason"])
	}
}

func TestCustomersReactivateShape(t *testing.T) {
	// VAL-SDKP-012 — reactivate surfaces suspended -> active.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"customer_id":"c1","name":"n","status":"sandbox_active"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	got, err := c.Customers.Reactivate(context.Background(), "c1", &ReactivateCustomerRequest{
		Resolution: &ReactivateResolution{IssueResolved: true, Details: "fixed"},
	})
	if err != nil {
		t.Fatalf("Reactivate: %v", err)
	}
	if got.Status != StatusSandboxActive && got.Status != StatusProductionActive {
		t.Errorf("status = %q, want an active value", got.Status)
	}
}

func TestCustomersInvalidTransitionTypedError(t *testing.T) {
	// VAL-SDKP-013 — invalid transition raises ConflictError with current_status.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"error":"invalid_transition","message":"Cannot promote a customer in status 'suspended'.","current_status":"suspended","action":"promote","request_id":"r1"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	_, err := c.Customers.Promote(context.Background(), "c1", &PromoteCustomerRequest{
		Attestation: PromoteAttestation{KYCCompleted: true, TermsAccepted: true, ComplianceReviewed: true},
		Billing:     PromoteBilling{Tier: "production"},
	}, "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsConflict(err) {
		t.Fatalf("expected ConflictError, got %T: %v", err, err)
	}
	if Code(err) != "invalid_transition" {
		t.Errorf("code = %q, want invalid_transition", Code(err))
	}
	if CurrentStatus(err) != "suspended" {
		t.Errorf("current_status = %q, want suspended", CurrentStatus(err))
	}
}

func TestCustomersForeignCustomerNotFoundError(t *testing.T) {
	// VAL-SDKP-019 — foreign customer raises NotFoundError (404, never 403).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"Resource not found","request_id":"r2"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	_, err := c.Customers.Get(context.Background(), "foreign-id")
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

func TestCustomersValidationErrorOnMissingReason(t *testing.T) {
	// VAL-SDKP-026 / VAL-SDKC — 422 surfaces as ValidationError.
	// Note: the SDK client-side guard rejects an empty reason before sending,
	// so we exercise the 422 path by constructing the request body directly
	// through a non-validating method. We use Suspend with a body that
	// bypasses the local guard via a helper server that asserts the SDK
	// surfaces 422 as ValidationError.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"error":"missing_reason","message":"A reason is required to suspend a customer.","request_id":"r3","field":"reason"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	// Send a suspend with a reason; the server is configured to reject
	// anyway (simulating the backend domain layer).
	_, err := c.Customers.Suspend(context.Background(), "c1", &SuspendCustomerRequest{Reason: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsValidation(err) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if Code(err) != "missing_reason" {
		t.Errorf("code = %q, want missing_reason", Code(err))
	}
}

func TestCustomersCreateLocalValidationRejectsEmpty(t *testing.T) {
	// The SDK rejects missing external_id/name before sending.
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: "http://x"})
	_, err := c.Customers.Create(context.Background(), &CreateCustomerRequest{}, "")
	if err == nil {
		t.Fatal("expected local validation error for empty create")
	}
}

func TestCustomersSuspendLocalValidationRejectsEmptyReason(t *testing.T) {
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: "http://x"})
	_, err := c.Customers.Suspend(context.Background(), "c1", &SuspendCustomerRequest{})
	if err == nil {
		t.Fatal("expected local validation error for empty reason")
	}
}
