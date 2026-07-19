package partner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// CustomerStatus is the canonical customer lifecycle status enum. The string
// values are byte-identical across TS/Python/Go (parity contract).
type CustomerStatus string

const (
	// StatusPending is the freshly-created customer status (no cust_ token
	// used yet; auto-activates to sandbox_active on first use).
	StatusPending CustomerStatus = "pending"
	// StatusSandboxActive is the sandbox customer status (auto-activated on
	// first cust_ token use).
	StatusSandboxActive CustomerStatus = "sandbox_active"
	// StatusProductionActive is the promoted-to-production customer status.
	StatusProductionActive CustomerStatus = "production_active"
	// StatusSuspended is the suspended customer status (reactivable).
	StatusSuspended CustomerStatus = "suspended"
	// StatusDeactivated is the terminal deactivated customer status (still
	// retrievable via GET, not hard-deleted).
	StatusDeactivated CustomerStatus = "deactivated"
)

// Governance is the customer governance/compliance summary block.
type Governance struct {
	FrameworksActive   []string `json:"frameworks_active"`
	PoliciesInherited  int      `json:"policies_inherited"`
	ComplianceScore    *int     `json:"compliance_score"` // pointer so null is preserved
}

// Limits is the customer capability-limits block.
type Limits struct {
	Agents                  int `json:"agents"`
	CapabilityTokensPerHour int `json:"capability_tokens_per_hour"`
	Webhooks                int `json:"webhooks,omitempty"`
	EnvelopesPerMonth       int `json:"envelopes_per_month,omitempty"`
}

// CustomerCredentials is the one-time customer token returned only on Create.
type CustomerCredentials struct {
	CustomerToken CustomerToken `json:"customer_token"`
}

// CustomerToken is the raw cust_ token returned once at creation time.
type CustomerToken struct {
	// Token is the raw cust_ token (returned once; never logged/persisted).
	Token  string `json:"token"`
	Prefix string `json:"prefix"`
}

// Customer is the MOSS customer (organization) resource.
type Customer struct {
	CustomerID   string                 `json:"customer_id"`
	ExternalID   string                 `json:"external_id,omitempty"`
	Name         string                 `json:"name"`
	Status       CustomerStatus         `json:"status"`
	PartnerID    string                 `json:"partner_id,omitempty"`
	Tier         string                 `json:"tier,omitempty"`
	CreatedAt    string                 `json:"created_at,omitempty"`
	UpdatedAt    string                 `json:"updated_at,omitempty"`
	Governance   *Governance            `json:"governance,omitempty"`
	Limits       *Limits                `json:"limits,omitempty"`
	Settings     map[string]any         `json:"settings,omitempty"`
	// Credentials is populated ONLY on Create (one-time raw cust_ token).
	Credentials *CustomerCredentials   `json:"credentials,omitempty"`
}

// CreateCustomerRequest is the body for customers.create.
type CreateCustomerRequest struct {
	ExternalID string         `json:"external_id"`
	Name       string         `json:"name"`
	Settings   map[string]any `json:"settings,omitempty"`
}

// UpdateCustomerRequest is the body for customers.update (PATCH).
type UpdateCustomerRequest struct {
	Limits   map[string]any `json:"limits,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

// PromoteAttestation is the attestation bundle required for promote.
type PromoteAttestation struct {
	KYCCompleted      bool   `json:"kyc_completed"`
	KYCProvider       string `json:"kyc_provider,omitempty"`
	KYCVerificationID string `json:"kyc_verification_id,omitempty"`
	TermsAccepted     bool   `json:"terms_accepted"`
	TermsVersion      string `json:"terms_version,omitempty"`
	TermsAcceptedBy   string `json:"terms_accepted_by,omitempty"`
	TermsAcceptedAt   string `json:"terms_accepted_at,omitempty"`
	ComplianceReviewed bool  `json:"compliance_reviewed"`
	ComplianceReviewer string `json:"compliance_reviewer,omitempty"`
	ComplianceNotes    string `json:"compliance_notes,omitempty"`
}

// PromoteBilling is the stubbed billing config recorded at promotion.
type PromoteBilling struct {
	Tier          string `json:"tier,omitempty"`
	BillingEmail  string `json:"billing_email,omitempty"`
	PaymentMethod string `json:"payment_method,omitempty"`
	BillingCycle  string `json:"billing_cycle,omitempty"`
}

// PromoteCustomerRequest is the body for customers.promote.
type PromoteCustomerRequest struct {
	Attestation      PromoteAttestation `json:"attestation"`
	Billing          PromoteBilling     `json:"billing"`
	GovernanceUpgrade map[string]any    `json:"governance_upgrade,omitempty"`
}

// SuspendCustomerRequest is the body for customers.suspend. Reason is
// required (non-empty) at the domain layer.
type SuspendCustomerRequest struct {
	Reason                 string `json:"reason"`
	SuspendAgentsImmediately *bool `json:"suspend_agents_immediately,omitempty"`
	GracePeriodDays        *int   `json:"grace_period_days,omitempty"`
	NotificationEmail      string `json:"notification_email,omitempty"`
}

// ReactivateResolution is the resolution record required for reactivate.
type ReactivateResolution struct {
	IssueResolved bool   `json:"issue_resolved"`
	Details       string `json:"details,omitempty"`
}

// ReactivateCustomerRequest is the body for customers.reactivate.
type ReactivateCustomerRequest struct {
	Resolution *ReactivateResolution `json:"resolution,omitempty"`
}

// ListCustomersOptions controls customers.list pagination/filtering.
type ListCustomersOptions struct {
	// Limit is the page size (default 20, max 100 on the backend).
	Limit int
	// Cursor is the opaque pagination cursor from a prior response.
	Cursor string
}

// CustomerListResponse is the customers.list response: a page of customers
// plus the opaque next-cursor (empty/absent when the end is reached).
type CustomerListResponse struct {
	Customers  []Customer `json:"customers"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// CustomersService is the customers.* resource namespace (partner persona).
type CustomersService struct {
	c *Client
}

func newCustomersService(c *Client) *CustomersService {
	return &CustomersService{c: c}
}

// Create creates a customer (organization) under the calling partner. The
// Idempotency-Key is partner-scoped: a same-key/same-body replay returns the
// same customer + cust_ token; a same-key/different-body replay is a 409
// idempotency_key_conflict. The raw cust_ token is returned exactly once in
// cust.Credentials.CustomerToken.Token.
func (s *CustomersService) Create(ctx context.Context, req *CreateCustomerRequest, idempotencyKey string) (*Customer, error) {
	if err := s.c.requirePartner("customers.create"); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("moss: customers.create: request is required")
	}
	if req.ExternalID == "" || req.Name == "" {
		return nil, fmt.Errorf("moss: customers.create: external_id and name are required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method:         http.MethodPost,
		path:           "/v1/partner/customers",
		body:           req,
		idempotencyKey: idempotencyKey,
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns the customer with the given id, including governance/limits
// summary. A foreign or unknown id returns NotFoundError (404, existence-
// non-leak convention — never 403).
func (s *CustomersService) Get(ctx context.Context, customerID string) (*Customer, error) {
	if err := s.c.requirePartner("customers.get"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.get: customer_id is required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method: http.MethodGet,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID),
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// List returns a page of customers owned by the calling partner. Each entry
// carries a status field with a value in the canonical status enum. Pass
// opts.Cursor from the response's NextCursor to fetch the next page.
func (s *CustomersService) List(ctx context.Context, opts *ListCustomersOptions) (*CustomerListResponse, error) {
	if err := s.c.requirePartner("customers.list"); err != nil {
		return nil, err
	}
	q := url.Values{}
	if opts != nil {
		if opts.Limit > 0 {
			q.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			q.Set("cursor", opts.Cursor)
		}
	}
	out := &CustomerListResponse{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method: http.MethodGet,
		path:   "/v1/partner/customers",
		query:  q,
	}, out)
	if err != nil {
		return nil, err
	}
	if out.Customers == nil {
		out.Customers = []Customer{}
	}
	return out, nil
}

// Update applies a partial update (limits/settings merge) to a customer. A
// subsequent Get reflects the updated values.
func (s *CustomersService) Update(ctx context.Context, customerID string, req *UpdateCustomerRequest) (*Customer, error) {
	if err := s.c.requirePartner("customers.update"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.update: customer_id is required")
	}
	if req == nil {
		return nil, fmt.Errorf("moss: customers.update: request is required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method: http.MethodPatch,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID),
		body:   req,
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Deactivate soft-deactivates a customer. The record remains retrievable via
// Get with status == "deactivated" (not a hard delete).
func (s *CustomersService) Deactivate(ctx context.Context, customerID string) (*Customer, error) {
	if err := s.c.requirePartner("customers.deactivate"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.deactivate: customer_id is required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method: http.MethodDelete,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID),
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Promote promotes a sandbox_active customer to production_active. Requires a
// complete attestation + billing bundle. An invalid from-state returns
// ConflictError (409, code "invalid_transition") with CurrentStatus echoed in
// the body. The Idempotency-Key replays the same response (including the
// one-time production cust_ token).
func (s *CustomersService) Promote(ctx context.Context, customerID string, req *PromoteCustomerRequest, idempotencyKey string) (*Customer, error) {
	if err := s.c.requirePartner("customers.promote"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.promote: customer_id is required")
	}
	if req == nil {
		return nil, fmt.Errorf("moss: customers.promote: request is required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method:         http.MethodPost,
		path:           "/v1/partner/customers/" + url.PathEscape(customerID) + "/promote",
		body:           req,
		idempotencyKey: idempotencyKey,
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Suspend suspends an active customer with a recorded reason. Reason is
// required (non-empty); a missing reason returns ValidationError (422, code
// "missing_reason"). An invalid from-state returns ConflictError (409, code
// "invalid_transition").
func (s *CustomersService) Suspend(ctx context.Context, customerID string, req *SuspendCustomerRequest) (*Customer, error) {
	if err := s.c.requirePartner("customers.suspend"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.suspend: customer_id is required")
	}
	if req == nil || req.Reason == "" {
		return nil, fmt.Errorf("moss: customers.suspend: reason is required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method: http.MethodPost,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID) + "/suspend",
		body:   req,
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Reactivate reactivates a suspended customer, restoring exactly the
// pre-suspension state. Requires a resolution record (issue_resolved == true,
// non-empty details). An invalid from-state returns ConflictError (409, code
// "invalid_transition").
func (s *CustomersService) Reactivate(ctx context.Context, customerID string, req *ReactivateCustomerRequest) (*Customer, error) {
	if err := s.c.requirePartner("customers.reactivate"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.reactivate: customer_id is required")
	}
	if req == nil || req.Resolution == nil {
		return nil, fmt.Errorf("moss: customers.reactivate: resolution is required")
	}
	out := &Customer{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method: http.MethodPost,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID) + "/reactivate",
		body:   req,
	}, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CurrentStatus extracts the current_status field echoed in a 409
// invalid_transition body, or "" if absent. Convenience for callers handling
// lifecycle conflict errors.
func CurrentStatus(err error) string {
	var api *APIError
	if !asAPIError(err, &api) || api == nil || api.Body == nil {
		return ""
	}
	if v, ok := api.Body["current_status"].(string); ok {
		return v
	}
	return ""
}

// ensure json import retained for future raw-body helpers.
var _ = json.Marshal
