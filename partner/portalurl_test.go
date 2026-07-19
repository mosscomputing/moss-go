package partner

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPortalURLConstruction(t *testing.T) {
	// VAL-SDKP-portal — portalUrl constructs a signed deep-link; tamper-evident;
	// no network call; expired token still constructs.
	c, _ := NewClient(Config{Token: "prt_test"})
	u, err := c.PortalURL("cust-123", PortalURLOpts{
		Token: "cust_scoped_token",
		Theme: map[string]string{"primary": "#fff", "mode": "dark"},
	})
	if err != nil {
		t.Fatalf("PortalURL: %v", err)
	}
	if !strings.HasPrefix(u, DefaultPortalBaseURL+"/portal/customer/cust-123?") {
		t.Errorf("URL prefix mismatch: %q", u)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	if q.Get("t") != "cust_scoped_token" {
		t.Errorf("t = %q", q.Get("t"))
	}
	if q.Get("sig") == "" {
		t.Error("sig query param missing")
	}
	if q.Get("theme.primary") != "#fff" {
		t.Errorf("theme.primary = %q", q.Get("theme.primary"))
	}
	if q.Get("theme.mode") != "dark" {
		t.Errorf("theme.mode = %q", q.Get("theme.mode"))
	}
	// Tamper-evident: the signature verifies.
	if !PortalVerifySignature(u) {
		t.Error("PortalVerifySignature should return true for a freshly-constructed URL")
	}
}

func TestPortalURLTamperEvident(t *testing.T) {
	// Flip a query param => signature must fail.
	c, _ := NewClient(Config{Token: "prt_test"})
	u, _ := c.PortalURL("cust-1", PortalURLOpts{Token: "cust_tok", Theme: map[string]string{"mode": "dark"}})
	parsed, _ := url.Parse(u)
	q := parsed.Query()
	q.Set("theme.mode", "light") // tamper
	parsed.RawQuery = q.Encode()
	tampered := parsed.String()
	if PortalVerifySignature(tampered) {
		t.Error("tampered URL must fail signature verification")
	}
}

func TestPortalURLCustomBaseAndExpiry(t *testing.T) {
	c, _ := NewClient(Config{Token: "prt_test"})
	exp := time.Now().Add(1 * time.Hour)
	u, err := c.PortalURL("c1", PortalURLOpts{
		PortalBase: "https://white-label.example.com/",
		Token:      "cust_tok",
		Expires:    &exp,
	})
	if err != nil {
		t.Fatalf("PortalURL: %v", err)
	}
	if !strings.HasPrefix(u, "https://white-label.example.com/portal/customer/c1?") {
		t.Errorf("custom base URL prefix mismatch: %q", u)
	}
	parsed, _ := url.Parse(u)
	if parsed.Query().Get("exp") == "" {
		t.Error("exp query param missing")
	}
	if !PortalVerifySignature(u) {
		t.Error("expiry-bearing URL should still verify")
	}
}

func TestPortalURLExpiredTokenStillConstructs(t *testing.T) {
	// No network call; an expired/invalid token still constructs.
	c, _ := NewClient(Config{Token: "prt_test"})
	u, err := c.PortalURL("c1", PortalURLOpts{Token: "cust_expired_garbage"})
	if err != nil {
		t.Fatalf("PortalURL: %v", err)
	}
	if !strings.Contains(u, "t=cust_expired_garbage") {
		t.Errorf("expired token URL missing t param: %q", u)
	}
}

func TestPortalURLValidationErrors(t *testing.T) {
	c, _ := NewClient(Config{Token: "prt_test"})
	if _, err := c.PortalURL("", PortalURLOpts{Token: "cust_tok"}); err == nil {
		t.Error("empty customerID should error")
	}
	if _, err := c.PortalURL("c1", PortalURLOpts{}); err == nil {
		t.Error("empty token should error")
	}
}

func TestPortalURLDeterministicAndParity(t *testing.T) {
	// The same inputs must produce byte-identical URLs (parity contract).
	c, _ := NewClient(Config{Token: "prt_test"})
	u1, _ := c.PortalURL("c1", PortalURLOpts{Token: "cust_tok", Theme: map[string]string{"a": "1", "b": "2"}})
	u2, _ := c.PortalURL("c1", PortalURLOpts{Token: "cust_tok", Theme: map[string]string{"a": "1", "b": "2"}})
	if u1 != u2 {
		t.Errorf("PortalURL not deterministic:\n  %s\n  %s", u1, u2)
	}
}
