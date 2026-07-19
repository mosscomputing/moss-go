package partner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SessionMint is the impersonation session mint response from POST
// /v1/partner/customers/{id}/session. Exactly the five backend fields plus
// the inferred TTLSeconds (derived from expires_at).
type SessionMint struct {
	SessionID  string `json:"session_id"`
	CustomerID string `json:"customer_id"`
	// Token is the raw cust_ session token (returned once; never
	// logged/persisted by the SDK).
	Token     string `json:"token"`
	Prefix    string `json:"prefix"`
	ExpiresAt string `json:"expires_at"`
}

// TTLSeconds returns the session TTL in seconds derived from ExpiresAt
// relative to now. Returns 0 if ExpiresAt cannot be parsed.
func (m *SessionMint) TTLSeconds() int {
	if m == nil || m.ExpiresAt == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if err != nil {
		t, err = time.Parse(time.RFC3339, m.ExpiresAt)
		if err != nil {
			return 0
		}
	}
	return int(time.Until(t).Seconds())
}

// SessionResult is the return value of Session()/AsCustomer(): the mint
// response and a customer-scoped Client bound to the minted cust_ token.
type SessionResult struct {
	Mint   *SessionMint
	Client *Client
}

// SessionOpts controls session minting. IdempotencyKey replays the same
// mint response (same session_id + same raw cust_ token).
type SessionOpts struct {
	// IdempotencyKey is the partner-scoped idempotency key (optional but
	// recommended for safe retry of the mint mutation).
	IdempotencyKey string
}

// Session mints a 15-minute full-access cust_ session token for a customer
// the partner owns and returns the mint response plus a customer-scoped
// Client bound to the raw cust_ token. The minted client's persona is
// "customer" and its token is the minted cust_ token (not the prt_ token).
//
// A foreign or unknown customer returns NotFoundError (404, existence-non-
// leak convention). A deactivated customer returns ConflictError (409, code
// "customer_not_active").
//
// AsCustomer is an alias for Session (same method, same return).
func (s *CustomersService) Session(ctx context.Context, customerID string, opts *SessionOpts) (*SessionResult, error) {
	if err := s.c.requirePartner("customers.session"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.session: customer_id is required")
	}
	idemKey := ""
	if opts != nil {
		idemKey = opts.IdempotencyKey
	}
	mint := &SessionMint{}
	_, err := s.c.doJSON(ctx, requestOptions{
		method:         http.MethodPost,
		path:           "/v1/partner/customers/" + url.PathEscape(customerID) + "/session",
		idempotencyKey: idemKey,
	}, mint)
	if err != nil {
		return nil, err
	}
	scoped, err := NewClient(Config{
		Token:     mint.Token,
		BaseURL:   s.c.baseURL,
		Timeout:   s.c.cfg.Timeout,
		MaxRetries: s.c.cfg.MaxRetries,
		HTTPClient: s.c.httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("moss: failed to build scoped customer client: %w", err)
	}
	return &SessionResult{Mint: mint, Client: scoped}, nil
}

// AsCustomer is an alias for Session. It mints a cust_ session and returns a
// customer-scoped Client plus the mint response.
func (s *CustomersService) AsCustomer(ctx context.Context, customerID string, opts *SessionOpts) (*SessionResult, error) {
	return s.Session(ctx, customerID, opts)
}

// RevokeSession revokes a minted session token. If sessionID is non-empty,
// only that session is revoked; if empty, ALL active partner-session tokens
// for the customer are revoked. Returns nil on success (204). A foreign or
// unknown customer returns NotFoundError (404). After revoke, calls made
// with the minted cust_ token raise AuthError (401).
//
// NOTE: the vendored OpenAPI spec defines only POST (mint); DELETE is a real
// backend route but is NOT served by the Prism mock. Mock-driven tests for
// revoke must use a real-backend e2e harness (:3100), not the mock (:4010).
func (s *CustomersService) RevokeSession(ctx context.Context, customerID, sessionID string) error {
	if err := s.c.requirePartner("customers.revokeSession"); err != nil {
		return err
	}
	if customerID == "" {
		return fmt.Errorf("moss: customers.revokeSession: customer_id is required")
	}
	body := map[string]any{}
	if sessionID != "" {
		body["session_id"] = sessionID
	}
	_, err := s.c.doNoContent(ctx, requestOptions{
		method: http.MethodDelete,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID) + "/session",
		body:   body,
	})
	return err
}
