#!/usr/bin/env bash
# Run the three required business scenarios against a canonical deployment.
# integration-up.sh --business owns startup, provisioning, and cleanup.
# Missing services/material are hard failures; this entry has no skip mode.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COTEST_ROOT="${REPO_ROOT}/../cotest"
for variable in COTEST_TOPOLOGY_PATH COTEST_WIRE_BIN COTEST_OIDC_CLIENT_ID COTEST_COAUTH_BASE_URL COTEST_COLAND_BASE_URL; do
    if [[ -z "${!variable:-}" ]]; then
        echo "[e2e] missing ${variable}; use integration-up.sh --business" >&2
        exit 2
    fi
done
COAUTH_INTEGRATION_OUTPUT_DIR="${COAUTH_INTEGRATION_OUTPUT_DIR:-${COTEST_JOINT_RUN_DIR:?}/coauth-integration}"
export COAUTH_INTEGRATION_OUTPUT_DIR
mkdir -p "${COAUTH_INTEGRATION_OUTPUT_DIR}"
# A failed rerun must never retain a previous run's passing summary.
rm -f "${COAUTH_INTEGRATION_OUTPUT_DIR}/business-summary.json" \
    "${COAUTH_INTEGRATION_OUTPUT_DIR}/business-results.json" \
    "${COAUTH_INTEGRATION_OUTPUT_DIR}/business-junit.xml"
if [[ -z "${COAUTH_INTEGRATION_COAUTH_BIN:-}" || -z "${COAUTH_INTEGRATION_APPROVAL_BIN:-}" ]]; then
    cargo_target="$(cargo metadata --manifest-path "${REPO_ROOT}/Cargo.toml" --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
    export COAUTH_INTEGRATION_COAUTH_BIN="${COAUTH_INTEGRATION_COAUTH_BIN:-${cargo_target}/debug/coauth}"
    export COAUTH_INTEGRATION_APPROVAL_BIN="${COAUTH_INTEGRATION_APPROVAL_BIN:-${cargo_target}/debug/examples/integration-approval}"
fi
export COAUTH_INTEGRATION_COAUTH_CONFIG="${COAUTH_INTEGRATION_COAUTH_CONFIG:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["servers"][0]["coauth"]["config_path"])' "${COTEST_TOPOLOGY_PATH}")}"
for binary in "${COAUTH_INTEGRATION_COAUTH_BIN}" "${COAUTH_INTEGRATION_APPROVAL_BIN}" "${COTEST_WIRE_BIN}"; do
    if [[ ! -x "${binary}" ]]; then
        echo "[e2e] missing executable ${binary}" >&2
        exit 2
    fi
done
bash "${REPO_ROOT}/scripts/integration-smoke.sh" --canonical
node "${COTEST_ROOT}/e2e/node_modules/@playwright/test/cli.js" test \
    --config "${REPO_ROOT}/scripts/integration/playwright.config.ts"
node "${REPO_ROOT}/scripts/integration/verify-results.mjs" \
    "${COAUTH_INTEGRATION_OUTPUT_DIR}/business-results.json"
