package runtime

// HTTP egress transport wrapper.
//
// Implements http.RoundTripper so every outbound call is intercepted:
//  1. pre-call policy-check (cached or live) -> BLOCK (raise before the
//     socket opens) or allow.
//  2. execute the call via the wrapped transport.
//  3. async batched signed event logging.
//
// The wrapper returns a *BlockError BEFORE the socket opens when policy
// denies the call (VAL-RUNTIME-008, VAL-RUNTIME-014).

import (
	"net/http"
	"net/url"
	"time"
)

// GovernedTransport is an http.RoundTripper that intercepts every request.
type GovernedTransport struct {
	policy      *PolicyEngine
	eventLogger *EventLogger
	wrapped     http.RoundTripper
}

// NewGovernedTransport wraps an existing http.RoundTripper (or
// http.DefaultTransport if nil) with MOSS governance.
func NewGovernedTransport(policy *PolicyEngine, eventLogger *EventLogger, wrapped http.RoundTripper) *GovernedTransport {
	if wrapped == nil {
		wrapped = http.DefaultTransport
	}
	return &GovernedTransport{
		policy:      policy,
		eventLogger: eventLogger,
		wrapped:     wrapped,
	}
}

// RoundTrip implements http.RoundTripper. It policy-checks the request
// before delegating to the wrapped transport, and logs a signed event
// after the call (or a blocked event if denied).
func (t *GovernedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	method := req.Method
	dest := req.URL.String()
	action := "http_" + lower(method)
	decision := t.policy.Check(action, dest, "", nil)
	if decision.IsBlock() {
		t.logEvent(method, dest, 0, true)
		return nil, &BlockError{
			Reason:            decision.Reason,
			Action:            action,
			Destination:       dest,
			DeclaredViolation: decision.DeclaredViolation,
			PolicyVersion:     decision.PolicyVersion,
		}
	}
	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		t.logEvent(method, dest, 0, false)
		return nil, err
	}
	t.logEvent(method, dest, resp.StatusCode, false)
	return resp, nil
}

func (t *GovernedTransport) logEvent(method, dest string, status int, blocked bool) {
	host := ""
	if u, err := url.Parse(dest); err == nil {
		host = u.Host
	}
	action := "http_" + lower(method)
	payload := map[string]any{
		"action":      action,
		"method":      method,
		"destination": dest,
		"host":        host,
		"status_code": status,
		"blocked":     blocked,
	}
	t.eventLogger.Log(payload, action)
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// GuardedClient builds an *http.Client whose transport is governed by MOSS.
// The agent's egress through this client is intercepted + signed-logged.
func GuardedClient(t *GovernedTransport, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Transport: t,
		Timeout:   timeout,
	}
}
