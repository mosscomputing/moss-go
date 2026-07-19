#!/usr/bin/env bash
# mock.sh — start the Prism mock server for SDK unit/CI tests (M3 devtools).
#
# Runs @stoplight/prism-cli in request-validation mode against the vendored
# OpenAPI spec (testdata/openapi.json) on port 4010:
#   --errors   request-body validation violations produce HTTP 422 (NOT a
#              canned 200) — VAL-DX-018.
#   --dynamic  generate mock responses from the spec schemas (the live
#              backend spec ships no examples for most routes).
#   --seed     fixed seed (m3mock) so the dynamically-generated responses are
#              byte-identical across moss-sdk-ts, moss-agent-sdk, and moss-go
#              (same spec + same prism version + same seed => same output) —
#              VAL-DX-014.
#
# The compliance-report route's 200 response advertises both application/json
# (a benign FastAPI default-merge empty schema) and application/pdf. Prism
# picks the content type via Accept negotiation, so callers MUST send
# `Accept: application/pdf` to get the binary PDF response — VAL-DX-019.
#
# Usage:
#   scripts/mock.sh                       # foreground (Ctrl-C to stop)
#   scripts/mock.sh &                     # background
#   MOSS_MOCK_PORT=4010 scripts/mock.sh   # override port
#
# Requires npx + network on first run (npx fetches prism-cli). moss-sdk-ts
# has @stoplight/prism-cli as a devDependency so no network fetch is needed
# there; moss-agent-sdk and moss-go use `npx --yes @stoplight/prism-cli@5.14.2`
# with a pinned version.
#
# This script is byte-identical across moss-sdk-ts, moss-agent-sdk, and
# moss-go so every repo starts the same mock against the same spec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEC="${SCRIPT_DIR}/../testdata/openapi.json"
PORT="${MOSS_MOCK_PORT:-4010}"
HOST="${MOSS_MOCK_HOST:-0.0.0.0}"
SEED="${MOSS_MOCK_SEED:-m3mock}"
PRISM_VERSION="5.14.2"

if [[ ! -f "${SPEC}" ]]; then
  echo "mock: ERROR: vendored spec not found at ${SPEC}" >&2
  echo "mock: run 'scripts/gen-openapi.sh' first (requires the backend on :3100)" >&2
  exit 2
fi

# Prefer a locally-installed prism (moss-sdk-ts devDependency); fall back to npx.
LOCAL_PRISM="${SCRIPT_DIR}/../node_modules/.bin/prism"
if [[ -x "${LOCAL_PRISM}" ]]; then
  PRISM_CMD=("${LOCAL_PRISM}")
else
  PRISM_CMD=(npx --yes "@stoplight/prism-cli@${PRISM_VERSION}")
fi

echo "mock: starting Prism on :${PORT} (spec=${SPEC}, seed=${SEED}, errors=on, dynamic=on)"
exec "${PRISM_CMD[@]}" mock "${SPEC}" -p "${PORT}" -h "${HOST}" --errors --dynamic --seed "${SEED}"
