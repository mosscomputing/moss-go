// Package partner implements the MOSS Partner SDK management surface.
//
// This is the M3 Partner SDK surface (reference implementation — TS and Python
// mirror this package's method names, resource layout, enum/status string
// values, error shapes, and retry/backoff semantics).
//
// A Client is constructed with a partner (prt_), customer (cust_), or
// capability (cap_) token. The persona is inferred from the token prefix.
// The default base URL is http://localhost:3100 (overridable).
//
// Partner persona (prt_) exposes the customers.* resource namespace:
//
//	client, _ := partner.NewClient(partner.Config{Token: os.Getenv("MOSS_PRT_TOKEN")})
//	cust, _ := client.Customers.Create(ctx, &partner.CreateCustomerRequest{
//	    ExternalID: "ext-1", Name: "Acme",
//	}, "idem-key-1")
//	fmt.Println(cust.CustomerID, cust.Status)
//
// Resource namespaces:
//
//   - Customers: create / get / list / update / deactivate / promote / suspend
//     / reactivate / Session / AsCustomer / RevokeSession / ComplianceReport
//
// Client-side helpers (no network validation):
//
//   - PortalURL: signed white-label deep-link construction (tamper-evident)
//   - Compliance.VerifyReport: offline ML-DSA-44 signature-marker verification
//
// Typed error hierarchy (parity contract — identical HTTP-status→class mapping
// across TS/Python/Go):
//
//   - 401/403 → AuthError
//   - 404     → NotFoundError
//   - 409     → ConflictError
//   - 429     → RateLimitError (carries RetryAfter)
//   - 400/422 → ValidationError
//   - 5xx     → ServerError
//
// All errors wrap an *APIError carrying Status, Code, Message, RequestID and the
// raw response body, accessible via errors.As.
package partner
