package partner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// APIError is the common error type carried by every typed SDK error. It
// exposes the HTTP status, the backend error-code string, the human-readable
// message, the opaque request id, and the parsed response body. The typed
// error classes below embed *APIError so errors.As works for both the
// concrete class and the generic *APIError.
type APIError struct {
	// Status is the HTTP status code returned by the backend.
	Status int
	// Code is the backend error-code string (e.g. "customer_not_found",
	// "invalid_transition", "invalid_credential_type"). For the uniform 404
	// handler the value is "not_found". For 422 validation envelopes the
	// value is "validation_error".
	Code string
	// Message is the human-readable error message.
	Message string
	// RequestID is the opaque backend request id (echoed from the
	// "request_id" response field when present).
	RequestID string
	// Headers is the response HTTP headers (used by RateLimitError to read
	// Retry-After).
	Headers http.Header
	// Body is the parsed JSON response body (may be nil for non-JSON bodies).
	Body map[string]any
	// RawBody is the raw response bytes (always populated).
	RawBody []byte
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code != "" {
		return fmt.Sprintf("moss: %s (status %d): %s", e.Code, e.Status, e.Message)
	}
	return fmt.Sprintf("moss: status %d: %s", e.Status, e.Message)
}

// Unwrap returns nil; the typed classes embed *APIError so errors.As(err,
// &APIError{}) and errors.As(err, &NotFoundError{}) both succeed. We expose a
// non-nil target via the embedded pointer instead of Unwrap for clean As
// chains.
func (e *APIError) Unwrap() error { return nil }

// Field returns a top-level field from the parsed error body, or "" if absent.
func (e *APIError) Field(key string) any {
	if e == nil || e.Body == nil {
		return nil
	}
	return e.Body[key]
}

// String returns the raw response body as a string.
func (e *APIError) String() string {
	if e == nil {
		return ""
	}
	return string(e.RawBody)
}

// ---- Typed hierarchy ----

// AuthError is raised for HTTP 401/403 (missing/invalid/wrong-prefix token).
type AuthError struct{ *APIError }

// Unwrap exposes the embedded *APIError so errors.As(err, &APIError{}) and
// the helper functions Code/Status resolve through the typed classes.
func (e *AuthError) Unwrap() error { return e.APIError }

// NotFoundError is raised for HTTP 404 (existence-non-leak convention).
type NotFoundError struct{ *APIError }

// Unwrap exposes the embedded *APIError.
func (e *NotFoundError) Unwrap() error { return e.APIError }

// ConflictError is raised for HTTP 409 (invalid lifecycle transition,
// idempotency-key conflict, delegation depth/escalation).
type ConflictError struct{ *APIError }

// Unwrap exposes the embedded *APIError.
func (e *ConflictError) Unwrap() error { return e.APIError }

// RateLimitError is raised for HTTP 429. It carries the Retry-After value
// parsed from the response header (seconds or HTTP-date). RetryAfter is zero
// when the header is absent (the backend does not always send Retry-After).
type RateLimitError struct {
	*APIError
	// RetryAfter is the parsed Retry-After duration. Zero means the header
	// was absent or unparseable — the SDK still surfaces RateLimitError.
	RetryAfter time.Duration
}

// Unwrap exposes the embedded *APIError.
func (e *RateLimitError) Unwrap() error { return e.APIError }

// ValidationError is raised for HTTP 400/422 (request validation failure).
type ValidationError struct{ *APIError }

// Unwrap exposes the embedded *APIError.
func (e *ValidationError) Unwrap() error { return e.APIError }

// ServerError is raised for HTTP 5xx.
type ServerError struct{ *APIError }

// Unwrap exposes the embedded *APIError.
func (e *ServerError) Unwrap() error { return e.APIError }

// asTypedError maps an HTTP status + parsed body to the canonical typed error.
// status is the HTTP status code; body is the parsed JSON body (may be nil);
// hdr is the response headers (read for Retry-After on 429); raw is the raw
// response body bytes.
func asTypedError(status int, body map[string]any, hdr http.Header, raw []byte) error {
	apiErr := buildAPIError(status, body, hdr, raw)
	switch {
	case status == http.StatusTooManyRequests:
		return &RateLimitError{APIError: apiErr, RetryAfter: parseRetryAfter(hdr)}
	case status == http.StatusNotFound:
		return &NotFoundError{APIError: apiErr}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &AuthError{APIError: apiErr}
	case status == http.StatusConflict:
		return &ConflictError{APIError: apiErr}
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return &ValidationError{APIError: apiErr}
	case status >= 500:
		return &ServerError{APIError: apiErr}
	default:
		// Non-2xx, non-classified status. Return a generic *APIError so the
		// caller still gets a typed-ish error with status/code/message.
		return apiErr
	}
}

func buildAPIError(status int, body map[string]any, hdr http.Header, raw []byte) *APIError {
	e := &APIError{Status: status, Headers: hdr, Body: body, RawBody: raw}
	if body != nil {
		if v, ok := body["error"].(string); ok {
			e.Code = v
		}
		if v, ok := body["code"].(string); ok && e.Code == "" {
			e.Code = v
		}
		if v, ok := body["message"].(string); ok {
			e.Message = v
		}
		if v, ok := body["request_id"].(string); ok {
			e.RequestID = v
		}
	}
	if e.Code == "" && status == http.StatusNotFound {
		// Uniform 404 handler rewrites the body to {"error":"not_found",...};
		// the route-level code is lost. Surface "not_found" as the canonical
		// code for any 404 without an explicit error field.
		e.Code = "not_found"
	}
	if e.Message == "" {
		e.Message = fmt.Sprintf("HTTP %d", status)
	}
	return e
}

// parseRetryAfter parses the Retry-After response header per RFC 7231. It
// accepts either a delta-seconds value or an HTTP-date. Returns zero if the
// header is absent or unparseable.
func parseRetryAfter(hdr http.Header) time.Duration {
	v := hdr.Get("Retry-After")
	if v == "" {
		return 0
	}
	// Delta-seconds (most common).
	var secs int
	if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	// HTTP-date (RFC 7231 §7.1.3).
	for _, layout := range []string{
		"Mon, 02 Jan 2006 15:04:05 GMT",
		time.RFC1123,
		time.RFC850,
		time.ANSIC,
	} {
		if t, err := time.Parse(layout, v); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
			return 0
		}
	}
	return 0
}

// IsAuth reports whether err is an *AuthError.
func IsAuth(err error) bool {
	var target *AuthError
	return errors.As(err, &target)
}

// IsNotFound reports whether err is a *NotFoundError.
func IsNotFound(err error) bool {
	var target *NotFoundError
	return errors.As(err, &target)
}

// IsRateLimit reports whether err is a *RateLimitError.
func IsRateLimit(err error) bool {
	var target *RateLimitError
	return errors.As(err, &target)
}

// IsValidation reports whether err is a *ValidationError.
func IsValidation(err error) bool {
	var target *ValidationError
	return errors.As(err, &target)
}

// IsConflict reports whether err is a *ConflictError.
func IsConflict(err error) bool {
	var target *ConflictError
	return errors.As(err, &target)
}

// IsServer reports whether err is a *ServerError.
func IsServer(err error) bool {
	var target *ServerError
	return errors.As(err, &target)
}

// Code returns the backend error-code string from err, or "" if err is not an
// SDK error.
func Code(err error) string {
	var api *APIError
	if errors.As(err, &api) {
		return api.Code
	}
	return ""
}

// Status returns the HTTP status from err, or 0 if err is not an SDK error.
func Status(err error) int {
	var api *APIError
	if errors.As(err, &api) {
		return api.Status
	}
	return 0
}

// ensure errors and json are used (kept for future field-access helpers).
var _ = json.Marshal
