# MOSS Shared Test Fixtures

Shared, language-agnostic test fixtures (seed data + error-state envelopes)
vendored into every MOSS SDK repo so cross-language parity tests assert
against **byte-identical** data in TypeScript (`moss-sdk-ts`), Python
(`moss-agent-sdk`), and Go (`moss-go`).

## Layout

```
testdata/fixtures/
  README.md            this file
  index.json           manifest of every fixture file + a stable digest
  partner.json         sample partner (PARTNER_A, PARTNER_B)
  customers.json       sample customers under each partner (all lifecycle states)
  session.json         sample impersonation session mint response (cust_, 15m TTL)
  capabilities.json    sample capability tokens (parent + attenuated child)
  envelopes.json       sample execution envelopes forming a hash chain
  webhooks.json        sample webhook registrations + one-time secrets
  analytics.json       sample analytics aggregates + usage blocks
  audit.json           sample audit-log entries forming a hash chain
  compliance.json      sample compliance score + report metadata
  errors/
    404.json           NotFoundError corpus (canonical error-code strings)
    401.json           AuthError corpus (invalid_*_credential)
    403.json           AuthError corpus (invalid_credential_type, delegation_escalation)
    409.json           ConflictError corpus (invalid_transition, agent_not_active, ...)
    422.json           ValidationError corpus (validation_error, ssrf_rejected, ...)
    429.json           RateLimitError corpus (capability_quota_exceeded, ...) + Retry-After
```

## Design rules

1. **JSON only.** Every fixture is plain JSON so it loads natively in TS, Python, and Go.
2. **No raw token material in the corpus.** Sample tokens use obvious placeholder
   suffixes (`prt_A_SEED`, `cust_1_SEED`, `cap_parent_SEED`) so they are never
   mistaken for live credentials and never leak real secret material. Real e2e
   tests mint fresh throwaway tokens from the live backend on :3100.
3. **Stable UUIDs and ISO-8601 timestamps.** All `*_id` values are fixed UUIDs
   and all timestamps are fixed ISO-8601 strings so parity diffs are
   deterministic. (`*_at` fields use the `2026-07-19T12:00:00Z` anchor.)
4. **Enum/status strings are byte-identical across repos** (see `library/parity.md`):
   `pending`, `sandbox_active`, `production_active`, `suspended`, `deactivated`;
   decision values `allow`, `block`, `hold`.
5. **Error envelopes mirror the backend wire shape:** an `error` code string,
   a human-readable `message`, an opaque `request_id`, and any status-specific
   extra fields (`retry_after`, `current_status`, `agent_status`, `limit`, ...).
   The canonical error-code strings are listed in `index.json` and asserted by
   the parity harness in all three SDKs.

## Drift / byte-identical contract

The fixtures MUST be byte-identical across `moss-sdk-ts`, `moss-agent-sdk`, and
`moss-go` (VAL-DX-012). The canonical copy lives in this directory; the other
two repos hold exact copies. A drift-check is provided by the per-repo
loader test, which asserts every fixture parses as JSON and prints a sha256
of each file; the parity harness diffs the sha256 sets across repos.
