package partner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// buildSignedPDF builds a PDF body with a real %%MOSS-SIGNATURE-V1 marker
// block carrying a real ML-DSA-44 signature over the signed region, plus the
// public key served at /.well-known/moss-keys/{key_id}. Used to test
// ComplianceService.VerifyReport end-to-end (offline verification).
func buildSignedPDF(t *testing.T) (pdf []byte, pubKeyB64 string, keyID string) {
	t.Helper()
	pk, sk, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	sec, err := sk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal sec: %v", err)
	}
	// "PDF body" before the marker (the signed region).
	signedRegion := []byte("%PDF-1.4\nfake pdf content for compliance report\n%%EOF\n")
	sum := sha256.Sum256(signedRegion)
	digest := hexEncode(sum[:])
	sig, err := mldsa44Sign(sec, signedRegion)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	keyID = "k-test-001"
	pdf = append([]byte{}, signedRegion...)
	pdf = append(pdf, []byte("%%MOSS-SIGNATURE-V1-BEGIN\n")...)
	pdf = append(pdf, []byte("key_id: "+keyID+"\n")...)
	pdf = append(pdf, []byte("signed_at: 2026-07-19T12:00:00Z\n")...)
	pdf = append(pdf, []byte("alg: ML-DSA-44\n")...)
	pdf = append(pdf, []byte("digest: "+digest+"\n")...)
	pdf = append(pdf, []byte("signature: "+sigB64+"\n")...)
	pdf = append(pdf, []byte("%%MOSS-SIGNATURE-V1-END\n")...)
	return pdf, base64.StdEncoding.EncodeToString(pub), keyID
}

// mldsa44Sign wraps the circl signer so the test file stays focused.
func mldsa44Sign(skBytes []byte, msg []byte) ([]byte, error) {
	var sk mldsa44.PrivateKey
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, err
	}
	return sk.Sign(nil, msg, nil)
}
func hexEncode(b []byte) string {
	const hexc = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexc[v>>4]
		out[i*2+1] = hexc[v&0xf]
	}
	return string(out)
}

func TestComplianceReportShapeAndSave(t *testing.T) {
	// VAL-SDKP-020 — complianceReport returns PDF bytes + save helper.
	pdfBytes := []byte("%PDF-1.4\n%%MOSS-SIGNATURE-V1-BEGIN\n%%MOSS-SIGNATURE-V1-END\n%%EOF\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/pdf" {
			t.Errorf("Accept = %q, want application/pdf", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(200)
		_, _ = w.Write(pdfBytes)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})
	rep, err := c.Customers.ComplianceReport(context.Background(), "c1")
	if err != nil {
		t.Fatalf("ComplianceReport: %v", err)
	}
	if rep.ContentType != "application/pdf" {
		t.Errorf("content-type = %q", rep.ContentType)
	}
	if len(rep.PDF) != len(pdfBytes) {
		t.Errorf("pdf len = %d, want %d", len(rep.PDF), len(pdfBytes))
	}
	if string(rep.PDF[:5]) != "%PDF-" {
		t.Errorf("magic = %q, want %%PDF-", string(rep.PDF[:5]))
	}
	if !rep.HasSignatureMarker() {
		t.Error("HasSignatureMarker should be true")
	}
	// Save helper writes the bytes to disk.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "report.pdf")
	n, err := rep.Save(path)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if n != len(pdfBytes) {
		t.Errorf("Save wrote %d bytes, want %d", n, len(pdfBytes))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(pdfBytes) {
		t.Error("saved file content mismatch")
	}
	if string(got[:5]) != "%PDF-" {
		t.Errorf("saved magic = %q", string(got[:5]))
	}
}

func TestComplianceReportForeignNotFound(t *testing.T) {
	// VAL-SDKP-022 — complianceReport on a foreign customer raises NotFoundError.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"Resource not found","request_id":"r1"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	_, err := c.Customers.ComplianceReport(context.Background(), "foreign")
	if !IsNotFound(err) {
		t.Fatalf("expected NotFoundError, got %v", err)
	}
}

func TestComplianceReportFailClosedServer500(t *testing.T) {
	// VAL-SDKC-016 — unconfigured signer => 500 ServerError, never unsigned bytes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL, MaxRetries: 0})
	_, err := c.Customers.ComplianceReport(context.Background(), "c1")
	if !IsServer(err) {
		t.Fatalf("expected ServerError, got %T: %v", err, err)
	}
}

func TestVerifyReportGoodAndTampered(t *testing.T) {
	// VAL-SDKP-021 — verifyReport(good) => valid; verifyReport(tampered) => invalid.
	pdf, pubB64, keyID := buildSignedPDF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/moss-keys/"+keyID {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"key_id":"` + keyID + `","alg":"ML-DSA-44","public_key_b64":"` + pubB64 + `"}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: srv.URL})

	good, err := c.Compliance.VerifyReport(context.Background(), pdf)
	if err != nil {
		t.Fatalf("VerifyReport(good): %v", err)
	}
	if !good.Valid {
		t.Errorf("good pdf should verify: %+v", good)
	}
	if good.KeyID != keyID {
		t.Errorf("key_id = %q, want %q", good.KeyID, keyID)
	}

	// Tamper: flip a byte in the signed region (before the BEGIN marker).
	tampered := append([]byte{}, pdf...)
	tampered[10] ^= 0x01
	bad, err := c.Compliance.VerifyReport(context.Background(), tampered)
	if err != nil {
		t.Fatalf("VerifyReport(tampered): %v", err)
	}
	if bad.Valid {
		t.Error("tampered pdf should NOT verify")
	}
}

func TestVerifyReportNoMarker(t *testing.T) {
	// A PDF without the marker returns {valid:false}, not an exception.
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: "http://x"})
	plain := []byte("%PDF-1.4 plain unsigned pdf %%EOF\n")
	res, err := c.Compliance.VerifyReport(context.Background(), plain)
	if err != nil {
		t.Fatalf("VerifyReport(plain): %v", err)
	}
	if res.Valid {
		t.Error("plain pdf without marker should not verify")
	}
	if res.Reason != "no signature marker" {
		t.Errorf("reason = %q, want 'no signature marker'", res.Reason)
	}
}

func TestVerifyReportEmptyPDF(t *testing.T) {
	c, _ := NewClient(Config{Token: "prt_test", BaseURL: "http://x"})
	res, err := c.Compliance.VerifyReport(context.Background(), nil)
	if err != nil {
		t.Fatalf("VerifyReport(nil): %v", err)
	}
	if res.Valid {
		t.Error("empty pdf should not verify")
	}
}

func TestExtractSignatureBlockMalformed(t *testing.T) {
	// BEGIN but no END.
	_, err := extractSignatureBlock([]byte("%%MOSS-SIGNATURE-V1-BEGIN\nkey_id: k\n"))
	if err == nil {
		t.Error("expected malformed error")
	}
	// BEGIN+END but missing key_id/digest/signature.
	_, err = extractSignatureBlock([]byte("%%MOSS-SIGNATURE-V1-BEGIN\nfoo: bar\n%%MOSS-SIGNATURE-V1-END\n"))
	if err == nil {
		t.Error("expected incomplete error")
	}
}

// ensure imports used
var _ = errors.As
var _ = strings.Contains
