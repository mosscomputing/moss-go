package partner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ComplianceReport is the signed PDF bytes returned by
// customers.complianceReport. The bytes carry the %%MOSS-SIGNATURE-V1 marker
// and an embedded QR pointing at the offline verify page.
type ComplianceReport struct {
	// PDF is the raw signed PDF bytes (%PDF- magic header).
	PDF []byte
	// ContentType is the response Content-Type (application/pdf).
	ContentType string
}

// Save writes the PDF bytes to the given path. The written file's first 4
// bytes are %PDF. Returns the number of bytes written.
func (r *ComplianceReport) Save(path string) (int, error) {
	if r == nil || r.PDF == nil {
		return 0, fmt.Errorf("moss: compliance report has no PDF bytes")
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("moss: failed to open %s: %w", path, err)
	}
	defer f.Close()
	n, err := f.Write(r.PDF)
	if err != nil {
		return n, fmt.Errorf("moss: failed to write %s: %w", path, err)
	}
	return n, nil
}

// WriteTo writes the PDF bytes to the given io.Writer (io.WriterTo
// implementation).
func (r *ComplianceReport) WriteTo(w io.Writer) (int64, error) {
	if r == nil || r.PDF == nil {
		return 0, fmt.Errorf("moss: compliance report has no PDF bytes")
	}
	n, err := w.Write(r.PDF)
	return int64(n), err
}

// HasSignatureMarker reports whether the PDF bytes contain the
// %%MOSS-SIGNATURE-V1 marker block.
func (r *ComplianceReport) HasSignatureMarker() bool {
	if r == nil || r.PDF == nil {
		return false
	}
	return bytesContains(r.PDF, []byte("%%MOSS-SIGNATURE-V1"))
}

// ComplianceReport fetches the signed compliance PDF for a customer the
// partner owns. Returns the raw PDF bytes (application/pdf, %PDF- magic
// header) plus a Save helper. A foreign/unknown customer returns
// NotFoundError (404). When the ML-DSA-44 signer is unconfigured the backend
// fails closed (500) and the SDK surfaces ServerError — it never returns an
// unsigned "compliance" artifact.
func (s *CustomersService) ComplianceReport(ctx context.Context, customerID string) (*ComplianceReport, error) {
	if err := s.c.requirePartner("customers.complianceReport"); err != nil {
		return nil, err
	}
	if customerID == "" {
		return nil, fmt.Errorf("moss: customers.complianceReport: customer_id is required")
	}
	ct, body, err := s.c.doBytes(ctx, requestOptions{
		method: http.MethodGet,
		path:   "/v1/partner/customers/" + url.PathEscape(customerID) + "/compliance-report",
		accept: "application/pdf",
	})
	if err != nil {
		return nil, err
	}
	return &ComplianceReport{PDF: body, ContentType: ct}, nil
}

// ComplianceService is the compliance.* resource namespace. It exposes the
// client-side verifyReport helper (offline ML-DSA-44 signature-marker
// verification).
type ComplianceService struct {
	c *Client
}

func newComplianceService(c *Client) *ComplianceService {
	return &ComplianceService{c: c}
}

// VerifyResult is the client-side compliance.verifyReport result.
type VerifyResult struct {
	Valid    bool   `json:"valid"`
	KeyID    string `json:"key_id,omitempty"`
	SignedAt string `json:"signed_at,omitempty"`
	// Reason is a short diagnostic when valid is false (e.g. "no marker",
	// "tampered", "public key fetch failed").
	Reason string `json:"reason,omitempty"`
}

// VerifyReport is a client-side helper that locates the %%MOSS-SIGNATURE-V1
// marker in the PDF bytes, fetches the signer's public key from
// /.well-known/moss-keys/{key_id}, and verifies the embedded ML-DSA-44
// signature. Returns {valid:true, key_id, signed_at?} for a freshly fetched,
// untampered report. A tampered copy (any byte flipped in the signed block)
// returns {valid:false}. A PDF without the marker returns {valid:false} (not
// an exception). No backend verify route is called — only the public keyset
// endpoint.
//
// The helper is network-light: one GET to /.well-known/moss-keys/{key_id}.
// It never sends the partner token (the keyset is public).
func (s *ComplianceService) VerifyReport(ctx context.Context, pdf []byte) (*VerifyResult, error) {
	if len(pdf) == 0 {
		return &VerifyResult{Valid: false, Reason: "empty pdf"}, nil
	}
	block, err := extractSignatureBlock(pdf)
	if err != nil {
		return &VerifyResult{Valid: false, Reason: err.Error()}, nil
	}
	// Fetch the public key (public endpoint — no Authorization header).
	pub, err := s.c.fetchWellKnownKey(ctx, block.KeyID)
	if err != nil {
		return &VerifyResult{Valid: false, KeyID: block.KeyID, Reason: "public key fetch failed: " + err.Error()}, nil
	}
	// Recompute the signed digest and verify.
	ok := block.verify(pub)
	if !ok {
		return &VerifyResult{Valid: false, KeyID: block.KeyID, Reason: "signature mismatch (tampered)"}, nil
	}
	return &VerifyResult{Valid: true, KeyID: block.KeyID, SignedAt: block.SignedAt}, nil
}

// signatureBlock is the parsed %%MOSS-SIGNATURE-V1 marker block.
//
// The marker format (appended after %%EOF by embed_pdf_signature) is:
//
//	%%MOSS-SIGNATURE-V1-BEGIN
//	key_id: <hex>
//	signed_at: <iso-8601>
//	alg: ML-DSA-44
//	digest: <hex sha256 of the signed region (PDF bytes up to the BEGIN marker)>
//	signature: <base64 ML-DSA-44 signature over the digest>
//	%%MOSS-SIGNATURE-V1-END
//
// Verification is offline: recompute sha256(signedRegion), fetch the public
// key for key_id, and ML-DSA-44 verify the signature over the digest.
type signatureBlock struct {
	KeyID     string
	SignedAt  string
	Alg       string
	Digest    string
	Signature string
	// signedRegion is the PDF bytes up to (not including) the BEGIN marker.
	signedRegion []byte
}

const (
	sigMarkerBegin = "%%MOSS-SIGNATURE-V1-BEGIN"
	sigMarkerEnd   = "%%MOSS-SIGNATURE-V1-END"
)

func extractSignatureBlock(pdf []byte) (*signatureBlock, error) {
	beginIdx := bytesIndex(pdf, []byte(sigMarkerBegin))
	if beginIdx < 0 {
		return nil, fmt.Errorf("no signature marker")
	}
	endIdx := bytesIndex(pdf, []byte(sigMarkerEnd))
	if endIdx < 0 || endIdx < beginIdx {
		return nil, fmt.Errorf("malformed signature marker (no end)")
	}
	blockBytes := pdf[beginIdx+len(sigMarkerBegin) : endIdx]
	sb := &signatureBlock{signedRegion: pdf[:beginIdx]}
	for _, line := range strings.Split(string(blockBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "key_id":
			sb.KeyID = v
		case "signed_at":
			sb.SignedAt = v
		case "alg":
			sb.Alg = v
		case "digest":
			sb.Digest = v
		case "signature":
			sb.Signature = v
		}
	}
	if sb.KeyID == "" || sb.Digest == "" || sb.Signature == "" {
		return nil, fmt.Errorf("incomplete signature marker")
	}
	return sb, nil
}

// verify recomputes the sha256 digest of the signed region and verifies the
// ML-DSA-44 signature against the public key bytes.
func (sb *signatureBlock) verify(publicKey []byte) bool {
	if sb == nil || len(publicKey) == 0 {
		return false
	}
	// Recompute the digest of the signed region (PDF bytes before BEGIN).
	sum := sha256.Sum256(sb.signedRegion)
	computed := fmt.Sprintf("%x", sum[:])
	if !strings.EqualFold(computed, sb.Digest) {
		return false
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sb.Signature)
	if err != nil {
		return false
	}
	// ML-DSA-44 verify via the root moss package (vetted cloudflare/circl).
	return verifyMLDSA44(sb.signedRegion, publicKey, sigBytes)
}

// fetchWellKnownKey fetches the public key material for keyID from the
// well-known keyset endpoint. No Authorization header is sent (public).
func (c *Client) fetchWellKnownKey(ctx context.Context, keyID string) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("empty key_id")
	}
	// The keyset endpoint returns JSON: {"keys":[{"key_id","alg","public_key_b64",...}]}.
	fullURL := c.baseURL + "/.well-known/moss-keys/" + url.PathEscape(keyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var doc struct {
		KeyID       string `json:"key_id"`
		Alg         string `json:"alg"`
		PublicKeyB64 string `json:"public_key_b64"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse keyset: %w", err)
	}
	if doc.PublicKeyB64 != "" {
		return base64.StdEncoding.DecodeString(doc.PublicKeyB64)
	}
	if doc.PublicKeyHex != "" {
		return hexDecode(doc.PublicKeyHex)
	}
	return nil, fmt.Errorf("no public key material in keyset response")
}

// ---- internal byte helpers (avoid pulling bytes import for two fns) ----

func bytesContains(haystack, needle []byte) bool {
	return bytesIndex(haystack, needle) >= 0
}

func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexNibble(s[i*2])
		lo, ok2 := hexNibble(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex char")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// verifyMLDSA44 is provided by mldsa_verify.go (uses github.com/cloudflare/circl).
// It is a thin wrapper so this file stays free of crypto imports.

// ensure time import retained (used by future signed_at parsing helpers).
var _ = time.RFC3339
