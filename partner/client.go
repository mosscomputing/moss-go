package partner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the default MOSS backend URL for the management
	// surface. The SDK targets http://localhost:3100 by default (M3 local
	// backend); override with Config.BaseURL.
	DefaultBaseURL = "http://localhost:3100"
	// DefaultTimeout is the default per-request timeout (after retries).
	DefaultTimeout = 30 * time.Second
	// DefaultMaxRetries is the default max retry count for idempotent GETs
	// on 429/5xx. Mutations are never retried unless an Idempotency-Key is
	// present (which makes them safely retryable).
	DefaultMaxRetries = 2
	// initialBackoff is the base for exponential backoff (seconds).
	initialBackoff = 200 * time.Millisecond
	// maxBackoff caps the exponential backoff between retries.
	maxBackoff = 30 * time.Second

	// Token prefixes — the SDK infers persona from the prefix.
	prefixPartner    = "prt_"
	prefixCustomer   = "cust_"
	prefixCapability = "cap_"
)

// Persona is the SDK persona inferred from the token prefix.
type Persona string

const (
	// PersonaPartner is the partner persona (prt_ token).
	PersonaPartner Persona = "partner"
	// PersonaCustomer is the customer persona (cust_ token).
	PersonaCustomer Persona = "customer"
	// PersonaCapability is the capability persona (cap_ token).
	PersonaCapability Persona = "capability"
	// PersonaUnknown is returned when the token prefix is unrecognized.
	PersonaUnknown Persona = "unknown"
)

// InferPersona infers the persona from a token's prefix. Returns
// PersonaUnknown for an empty or unrecognized token.
func InferPersona(token string) Persona {
	switch {
	case strings.HasPrefix(token, prefixPartner):
		return PersonaPartner
	case strings.HasPrefix(token, prefixCustomer):
		return PersonaCustomer
	case strings.HasPrefix(token, prefixCapability):
		return PersonaCapability
	default:
		return PersonaUnknown
	}
}

// Config holds the Partner SDK client configuration.
type Config struct {
	// Token is the MOSS API token (prt_, cust_, or cap_). Required.
	Token string
	// BaseURL is the backend base URL. Defaults to http://localhost:3100.
	BaseURL string
	// Timeout is the per-request timeout. Defaults to 30s. Zero means no
	// timeout (use with care).
	Timeout time.Duration
	// MaxRetries is the max retry count for idempotent GETs on 429/5xx
	// (and for mutations carrying an Idempotency-Key). Defaults to 2.
	MaxRetries int
	// HTTPClient overrides the default *http.Client. Optional.
	HTTPClient *http.Client
	// Persona overrides persona inference. Optional; inferred from Token
	// when empty.
	Persona Persona
	// UserAgent overrides the default User-Agent header. Optional.
	UserAgent string
}

// Client is the MOSS Partner SDK client. It is safe for concurrent use by
// multiple goroutines (the underlying *http.Client is shared read-only after
// construction).
type Client struct {
	cfg        Config
	token      string
	baseURL    string
	persona    Persona
	httpClient *http.Client
	userAgent  string

	// Resource namespaces.
	Customers  *CustomersService
	Compliance *ComplianceService
}

// NewClient constructs a new Partner SDK client from cfg. The token is
// required; persona is inferred from the token prefix unless cfg.Persona is
// set. Defaults are applied for BaseURL, Timeout, and MaxRetries.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("moss: Config.Token is required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	} else {
		// Normalize: strip trailing slashes so path joining is predictable.
		cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	persona := cfg.Persona
	if persona == "" {
		persona = InferPersona(cfg.Token)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "moss-go-partner-sdk/1.0"
	}
	c := &Client{
		cfg:        cfg,
		token:      cfg.Token,
		baseURL:    cfg.BaseURL,
		persona:    persona,
		httpClient: hc,
		userAgent:  ua,
	}
	c.Customers = newCustomersService(c)
	c.Compliance = newComplianceService(c)
	return c, nil
}

// BaseURL returns the effective base URL the client targets.
func (c *Client) BaseURL() string { return c.baseURL }

// Persona returns the inferred (or configured) persona.
func (c *Client) Persona() Persona { return c.persona }

// Token returns the configured token (prefix-only access is encouraged; never
// log the raw token).
func (c *Client) Token() string { return c.token }

// TokenPrefix returns the token prefix (e.g. "prt_"), safe to log.
func (c *Client) TokenPrefix() string {
	switch c.persona {
	case PersonaPartner:
		return prefixPartner
	case PersonaCustomer:
		return prefixCustomer
	case PersonaCapability:
		return prefixCapability
	default:
		if len(c.token) >= 5 {
			return c.token[:5]
		}
		return c.token
	}
}

// MaxRetries returns the configured max-retry count.
func (c *Client) MaxRetries() int { return c.cfg.MaxRetries }

// ---- transport ----

// requestOptions are the per-request options applied by do().
type requestOptions struct {
	method          string
	path            string
	query           url.Values
	body            any
	idempotencyKey  string
	accept          string
	// retryable overrides the default retry policy. When false the request
	// is never retried regardless of method/idempotency-key.
	retryableOverride *bool
}

// do executes an HTTP request with retry/backoff. It sets the Authorization,
// Content-Type, Idempotency-Key, Accept, and User-Agent headers, serializes
// the JSON body, performs retries on 429/5xx for idempotent requests (GETs and
// mutations carrying an Idempotency-Key), and maps non-2xx responses to the
// typed error hierarchy.
func (c *Client) do(ctx context.Context, opts requestOptions) (int, http.Header, []byte, error) {
	// A request is retryable iff it is a GET, or it carries an
	// Idempotency-Key (which makes mutations safely replayable). Mutations
	// without an Idempotency-Key are NOT retried (VAL-SDKC-024).
	retryable := opts.method == http.MethodGet || opts.idempotencyKey != ""
	if opts.retryableOverride != nil {
		retryable = *opts.retryableOverride
	}
	maxRetries := 0
	if retryable {
		maxRetries = c.cfg.MaxRetries
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.backoffDelay(attempt, lastRespHeader(lastErr))
			if !c.sleep(ctx, wait) {
				return 0, nil, nil, ctx.Err()
			}
		}
		status, hdr, body, err := c.doOnce(ctx, opts)
		if err != nil {
			// Network/transport error: retryable on idempotent requests.
			lastErr = err
			if retryable && attempt < maxRetries {
				continue
			}
			return 0, nil, nil, fmt.Errorf("moss: request failed: %w", err)
		}
		if status >= 200 && status < 300 {
			return status, hdr, body, nil
		}
		// Map to typed error.
		parsed := parseJSONBody(body)
		typed := asTypedError(status, parsed, hdr, body)
		// Retry only on 429/5xx for retryable requests.
		if retryable && (status == http.StatusTooManyRequests || status >= 500) && attempt < maxRetries {
			lastErr = typed
			continue
		}
		return status, hdr, body, typed
	}
	// Should not reach here; the loop returns in every branch.
	return 0, nil, nil, lastErr
}

// lastRespHeader extracts the http.Header from a prior error if it is a typed
// SDK error (for Retry-After on 429).
func lastRespHeader(err error) http.Header {
	if err == nil {
		return nil
	}
	var api *APIError
	if asAPIError(err, &api) {
		return api.Headers
	}
	return nil
}

// asAPIError is a thin wrapper so we can reuse errors.As without importing
// the type twice in this file.
func asAPIError(err error, target **APIError) bool {
	return errors.As(err, target)
}

// doOnce performs a single HTTP attempt with no retry.
func (c *Client) doOnce(ctx context.Context, opts requestOptions) (int, http.Header, []byte, error) {
	fullURL := c.baseURL + opts.path
	if len(opts.query) > 0 {
		fullURL += "?" + opts.query.Encode()
	}
	var bodyReader io.Reader
	if opts.body != nil {
		bodyBytes, err := json.Marshal(opts.body)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("moss: failed to encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, opts.method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("moss: failed to build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	if opts.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if opts.accept != "" {
		req.Header.Set("Accept", opts.accept)
	}
	if opts.idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", opts.idempotencyKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, fmt.Errorf("moss: failed to read response body: %w", err)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// backoffDelay computes the delay before the next attempt. For 429 it honors
// the Retry-After header (parsed from the prior response headers when
// available); for 5xx (and 429 without Retry-After) it uses exponential
// backoff: initialBackoff * 2^(attempt-1), capped at maxBackoff.
func (c *Client) backoffDelay(attempt int, hdr http.Header) time.Duration {
	if ra := parseRetryAfter(hdr); ra > 0 {
		// Honor Retry-After, but cap at maxBackoff so a huge value does not
		// stall the SDK indefinitely.
		if ra > maxBackoff {
			return maxBackoff
		}
		return ra
	}
	// Exponential backoff: 200ms, 400ms, 800ms, ... capped at 30s.
	bo := initialBackoff * time.Duration(int64(math.Pow(2, float64(attempt-1))))
	if bo > maxBackoff || bo < 0 {
		return maxBackoff
	}
	return bo
}

// sleep blocks for d or until ctx is cancelled. Returns false if ctx was
// cancelled during the sleep.
func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// parseJSONBody best-effort parses a JSON object body into a map. Returns nil
// for empty/non-object bodies.
func parseJSONBody(body []byte) map[string]any {
	if len(body) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m
}

// ---- request helpers used by the resource namespaces ----

// doJSON executes a request expecting a JSON response body and unmarshals it
// into out. Returns the HTTP status. Non-2xx responses are returned as typed
// errors (out is left untouched).
func (c *Client) doJSON(ctx context.Context, opts requestOptions, out any) (int, error) {
	status, hdr, body, err := c.do(ctx, opts)
	if err != nil {
		return status, err
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return status, fmt.Errorf("moss: failed to parse response: %w", err)
		}
	}
	_ = hdr
	return status, nil
}

// doBytes executes a request expecting a binary response body (e.g. a PDF).
// Returns the status, Content-Type, and raw bytes. Non-2xx responses are
// returned as typed errors.
func (c *Client) doBytes(ctx context.Context, opts requestOptions) (string, []byte, error) {
	_, hdr, body, err := c.do(ctx, opts)
	if err != nil {
		return "", nil, err
	}
	ct := hdr.Get("Content-Type")
	return ct, body, nil
}

// doNoContent executes a request expecting an empty (204/200) response.
// Returns the HTTP status. Non-2xx responses are returned as typed errors.
func (c *Client) doNoContent(ctx context.Context, opts requestOptions) (int, error) {
	status, _, _, err := c.do(ctx, opts)
	if err != nil {
		return status, err
	}
	return status, nil
}

// requirePartner returns an error if the client persona is not partner. Used
// by partner-only resource methods (customers.create, session mint, etc.) to
// fail fast with a typed AuthError (matching the backend's 403
// invalid_credential_type response) rather than making a network call that
// would surface the same error. This satisfies both VAL-SDKP-002 (explicit
// configuration error, not a silent 401 deep in a call) and VAL-SDKP-024
// (wrong-prefix token on a persona-gated route surfaces AuthError).
//
// For PersonaUnknown (unrecognized prefix) the request is sent to the backend
// so the backend's own auth resolver produces the canonical 401/403 + code.
func (c *Client) requirePartner(action string) error {
	if c.persona == PersonaPartner {
		return nil
	}
	if c.persona == PersonaCustomer || c.persona == PersonaCapability {
		return &AuthError{APIError: &APIError{
			Status:  http.StatusForbidden,
			Code:    "invalid_credential_type",
			Message: fmt.Sprintf("moss: %s requires a partner (prt_) token; got persona %q", action, c.persona),
		}}
	}
	// PersonaUnknown: let the backend reject with its canonical 401/403.
	return nil
}
