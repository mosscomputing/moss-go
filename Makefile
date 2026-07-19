# moss-go — developer tooling targets.
#
# OpenAPI vendor/drift targets (M3 devtools). The vendored spec at
# testdata/openapi.json is byte-identical across moss-sdk-ts, moss-agent-sdk,
# and moss-go and matches the live backend /openapi.json (VAL-DX-005/006/016).

OPENAPI_SCRIPT := scripts/gen-openapi.sh

.PHONY: gen-openapi check-openapi

gen-openapi: ## Regenerate the vendored OpenAPI spec from the live backend (:3100).
	bash $(OPENAPI_SCRIPT)

check-openapi: ## CI drift-check: fail (non-zero) if the vendored spec is stale.
	bash $(OPENAPI_SCRIPT) --check
