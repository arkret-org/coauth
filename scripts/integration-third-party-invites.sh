#!/usr/bin/env bash
# Standard IVS lifecycle against the canonical managed deployment.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COTEST_ROOT="${REPO_ROOT}/../cotest"
for variable in COTEST_TOPOLOGY_PATH COTEST_WIRE_BIN COTEST_PROVISION_BIN COTEST_OIDC_CLIENT_ID COTEST_COAUTH_BASE_URL COTEST_COLAND_BASE_URL COTEST_MOCK_EMAIL_BASE_URL COTEST_PROVISION_CUSTODY_ROOT; do
    if [[ -z "${!variable:-}" ]]; then
        echo "[ivs] canonical deployment missing ${variable}" >&2
        exit 2
    fi
done
export COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR="${COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR:-${COTEST_JOINT_RUN_DIR:?}/third-party-invites}"
mkdir -p "${COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR}"
rm -f "${COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR}/summary.json" \
    "${COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR}/results.json" \
    "${COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR}/junit.xml"
node "${COTEST_ROOT}/e2e/node_modules/@playwright/test/cli.js" test \
    --config "${REPO_ROOT}/scripts/integration/third-party-invites.config.ts" "$@"
node "${REPO_ROOT}/scripts/integration/verify-third-party-invite-results.mjs" \
    "${COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR}/results.json"
