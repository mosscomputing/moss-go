#!/usr/bin/env bash
# gen-openapi.sh — regenerate the vendored MOSS OpenAPI spec from the live backend.
#
# The vendored spec (testdata/openapi.json) is the canonical OpenAPI document
# shared across the SDK repos (moss-sdk-ts, moss-agent-sdk, moss-go) and the
# Prism mock server. It is fetched verbatim from the live backend's
# GET /openapi.json so the vendored copy is byte-identical to the live spec
# (VAL-DX-016) and byte-stable across re-runs on a fixed backend (VAL-DX-004,
# idempotent — no re-serialization, no timestamp injection).
#
# Usage:
#   scripts/gen-openapi.sh                # fetch live spec -> testdata/openapi.json
#   scripts/gen-openapi.sh --check        # CI drift-check: exit 0 if fresh, 1 if stale
#   scripts/gen-openapi.sh --output PATH  # override vendored path
#   scripts/gen-openapi.sh --backend URL  # override backend (default $MOSS_BACKEND_URL
#                                         #   or http://localhost:3100)
#
# Exit codes:
#   0  success (spec written, or drift-check found NO drift)
#   1  drift detected (--check), or vendored spec missing in --check mode
#   2  backend unreachable / fetch failed / not a valid OpenAPI 3.x document
#
# This script is identical (byte-for-byte) across moss-signing-api and the
# three SDK repos so every repo can self-regenerate and self-check its own
# vendored copy against the same live backend.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_OUTPUT="${SCRIPT_DIR}/../testdata/openapi.json"

BACKEND="${MOSS_BACKEND_URL:-http://localhost:3100}"
OUTPUT=""
CHECK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1; shift;;
    --output) OUTPUT="$2"; shift 2;;
    --backend) BACKEND="$2"; shift 2;;
    -h|--help)
      sed -n '2,25p' "${BASH_SOURCE[0]}"
      exit 0;;
    *) echo "gen-openapi: unknown arg: $1" >&2; exit 1;;
  esac
done

[[ -n "$OUTPUT" ]] || OUTPUT="$DEFAULT_OUTPUT"

fetch_spec() {
  # Fetch the live OpenAPI spec to a target path. Return 2 on failure.
  local target="$1"
  if ! curl -sf --max-time 30 "${BACKEND}/openapi.json" -o "$target"; then
    echo "gen-openapi: ERROR: could not fetch ${BACKEND}/openapi.json" >&2
    echo "gen-openapi: is the backend healthy on ${BACKEND}?" >&2
    return 2
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "gen-openapi: WARNING: jq not found; skipping OpenAPI 3.x validation" >&2
  else
    if ! jq -e '(.openapi | startswith("3.")) and (.paths | length > 0)' "$target" >/dev/null 2>&1; then
      echo "gen-openapi: ERROR: fetched document is not a valid OpenAPI 3.x spec" >&2
      return 2
    fi
  fi
  return 0
}

if [[ "$CHECK" -eq 1 ]]; then
  # CI drift-check mode (VAL-DX-017): regenerate to a temp file, diff against
  # the vendored spec, exit NON-ZERO on any drift.
  if [[ ! -f "$OUTPUT" ]]; then
    echo "gen-openapi: DRIFT: vendored spec missing at ${OUTPUT}" >&2
    exit 1
  fi
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  fetch_spec "$tmp" || exit $?
  if diff -q "$tmp" "$OUTPUT" >/dev/null 2>&1; then
    echo "gen-openapi: OK - vendored spec matches live ${BACKEND}/openapi.json"
    exit 0
  else
    echo "gen-openapi: DRIFT: vendored spec at ${OUTPUT} differs from live ${BACKEND}/openapi.json" >&2
    diff "$OUTPUT" "$tmp" >&2 | head -40 || true
    exit 1
  fi
fi

# Default mode: fetch and write the vendored spec (byte-identical to live).
mkdir -p "$(dirname "$OUTPUT")"
fetch_spec "$OUTPUT" || exit $?
echo "gen-openapi: wrote ${OUTPUT} ($(wc -c < "$OUTPUT") bytes) from ${BACKEND}/openapi.json"
