package partner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DefaultPortalBaseURL is the default white-label portal base URL.
const DefaultPortalBaseURL = "https://dev-console.mosscomputing.com"

// PortalURLOpts controls PortalURL construction.
type PortalURLOpts struct {
	// PortalBase is the white-label portal base URL. Defaults to
	// https://dev-console.mosscomputing.com.
	PortalBase string
	// Token is the scoped cust_ token to embed in the deep-link. The portal
	// validates this token on receipt (via BFF -> introspect). The SDK does
	// NOT validate the token here — construction is purely client-side and
	// tamper-evident (an expired token still constructs a URL).
	Token string
	// Theme is the optional branding/theme params (e.g. {"primary":"#fff",
	// "mode":"dark"}). Echoed in the URL and covered by the signature.
	Theme map[string]string
	// Expires is an optional deep-link expiry (the portal may reject the
	// link after this time). Covered by the signature. Nil means no expiry.
	Expires *time.Time
}

// PortalURL constructs a signed white-label deep-link from the portal base +
// the scoped cust_ token + theme params. The link is tamper-evident: the
// query string carries an HMAC-SHA256 signature over the canonical parameter
// set, keyed by a key derived from the token. The portal validates the
// signature on receipt (Stripe-Checkout pattern). No network call is made —
// construction is purely client-side, and an expired/invalid token still
// constructs a URL (validation is the portal's job).
//
// The URL shape is:
//
//	<portalBase>/portal/customer/<customerID>?t=<token>&theme[...]=...&exp=<unix>&sig=<base64url-hmac>
//
// The signature covers the canonical sorted key=value pair string of all
// query params except `sig`, HMAC-SHA256 keyed by sha256(token).
func (c *Client) PortalURL(customerID string, opts PortalURLOpts) (string, error) {
	if customerID == "" {
		return "", fmt.Errorf("moss: PortalURL: customer_id is required")
	}
	if opts.Token == "" {
		return "", fmt.Errorf("moss: PortalURL: Token is required")
	}
	base := opts.PortalBase
	if base == "" {
		base = DefaultPortalBaseURL
	}
	base = strings.TrimRight(base, "/")

	params := url.Values{}
	params.Set("t", opts.Token)
	for k, v := range opts.Theme {
		params.Set("theme."+k, v)
	}
	if opts.Expires != nil {
		params.Set("exp", fmt.Sprintf("%d", opts.Expires.Unix()))
	}

	sig := portalSign(opts.Token, params)
	params.Set("sig", sig)

	u := base + "/portal/customer/" + url.PathEscape(customerID) + "?" + portalEncode(params)
	return u, nil
}

// portalSign computes the HMAC-SHA256 signature over the canonical sorted
// key=value pair string of all params (excluding `sig`), keyed by sha256(token).
// The signature is base64url-encoded (no padding).
func portalSign(token string, params url.Values) string {
	key := sha256.Sum256([]byte(token))
	pairs := canonicalPairs(params, "sig")
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(pairs))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// PortalVerifySignature verifies a PortalURL signature client-side. Returns
// true iff the `sig` query param matches the HMAC-SHA256 over the canonical
// pair string of all other params, keyed by sha256(token). This is a pure
// client-side check (no network) used by the portal to detect tampering
// before the BFF introspection call.
func PortalVerifySignature(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	q := u.Query()
	sig := q.Get("sig")
	if sig == "" {
		return false
	}
	token := q.Get("t")
	if token == "" {
		return false
	}
	want := portalSign(token, q)
	return hmac.Equal([]byte(sig), []byte(want))
}

// canonicalPairs returns the canonical "k=v&k2=v2..." string of params
// (sorted by key, URL-encoded values), excluding the named skip key. This is
// the signed payload — byte-identical for the same inputs across TS/Python/Go.
func canonicalPairs(params url.Values, skip string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == skip {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	first := true
	for _, k := range keys {
		for _, v := range params[k] {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// portalEncode encodes params in canonical sorted order so the URL string is
// deterministic across runs (byte-identical for the same inputs). The Go
// stdlib's url.Values.Encode is already sorted, but we use our own to keep
// the encoding aligned with canonicalPairs for parity.
func portalEncode(params url.Values) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	first := true
	for _, k := range keys {
		for _, v := range params[k] {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// ensure json import retained for future param serialization helpers.
var _ = json.Marshal
