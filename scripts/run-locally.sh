#!/usr/bin/env bash
# One-shot local bring-up + verify for the coauth integration stack.
#
# What this does, in order:
#
#   1. preflight-check.sh       (fail-fast on docker / port / config issues)
#   2. integration-up.sh        (build coauth image + bring up postgres + coauth)
#   3. wait for /health to be 200
#   4. mounted-config check     (`coauth healthcheck --config /etc/coauth/config.yaml`)
#   5. discovery URL probe      (curl /.well-known/openid-configuration + jq)
#   6. integration-smoke.sh
#   7. integration-e2e.sh       (S1 + S2 + S3)
#   8. (optional) oidc-conformance.sh --plan basic-op
#
# Designed so a developer can iterate end-to-end with a single command.
# Each step prints its own headline so failures are easy to attribute.
#
# Usage:
#
#   ./scripts/run-locally.sh                          # core stack
#   ./scripts/run-locally.sh --with-conformance       # + plan-basic-op
#   ./scripts/run-locally.sh --keep                   # don't tear down on success
#   ./scripts/run-locally.sh --down                   # just tear down + exit
#
# Exit codes:
#   0 — every selected step passed
#   2 — usage error / missing dep
#   3 — at least one step failed (the failing step's exit code propagates)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="${REPO_ROOT}/scripts"

WITH_CONFORMANCE=0
KEEP=0
ACTION="up"

for arg in "$@"; do
    case "${arg}" in
        --with-conformance) WITH_CONFORMANCE=1 ;;
        --keep)             KEEP=1 ;;
        --down)             ACTION="down" ;;
        -h|--help)
            sed -n '2,30p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "[run-locally] unknown flag: ${arg}" >&2
            exit 2
            ;;
    esac
done

if [[ "${ACTION}" == "down" ]]; then
    bash "${SCRIPTS}/integration-up.sh" --down
    exit $?
fi

step() { echo; echo "[run-locally] ============================================================"; echo "[run-locally]   ${*}"; echo "[run-locally] ============================================================"; }

# 1. preflight
step "step 1/8 — preflight-check"
bash "${SCRIPTS}/preflight-check.sh" || {
    echo "[run-locally] preflight failed (errors); aborting" >&2
    exit 3
}

# 2. integration-up
step "step 2/8 — integration-up (build + bring up postgres + coauth)"
bash "${SCRIPTS}/integration-up.sh" || {
    echo "[run-locally] integration-up failed; check docker compose logs" >&2
    exit 3
}

cleanup() {
    if (( KEEP == 1 )); then
        echo "[run-locally] --keep set; leaving stack up. Tear down with:"
        echo "  ./scripts/run-locally.sh --down"
        return
    fi
    echo
    echo "[run-locally] tearing down stack"
    bash "${SCRIPTS}/integration-up.sh" --down || true
}
trap cleanup EXIT

# 3. wait for /health
step "step 3/8 — wait for /health 200 on host port 57080"
ATTEMPTS="${HEALTH_ATTEMPTS:-60}"
for attempt in $(seq 1 "${ATTEMPTS}"); do
    code="$(curl -fsS -o /dev/null -m 2 -w '%{http_code}' http://127.0.0.1:57080/health || echo "000")"
    if [[ "${code}" == "200" ]]; then
        echo "[run-locally] coauth /health 200 after ${attempt}s"
        break
    fi
    if (( attempt == ATTEMPTS )); then
        echo "[run-locally] coauth /health never returned 200; logs:" >&2
        docker compose -f "${REPO_ROOT}/docker-compose.integration.yaml" logs --tail=120 coauth >&2 || true
        exit 3
    fi
    sleep 1
done

# 4. mounted YAML check
step "step 4/8 — mounted YAML config check"
if docker compose -f "${REPO_ROOT}/docker-compose.integration.yaml" exec -T coauth \
        /usr/local/bin/coauth healthcheck --config /etc/coauth/config.yaml; then
    echo "[run-locally] in-container healthcheck OK"
else
    echo "[run-locally] in-container healthcheck FAILED" >&2
    exit 3
fi

# 5. discovery
step "step 5/8 — fetch /.well-known/openid-configuration"
DISCOVERY_BODY="$(curl -fsS http://127.0.0.1:57080/.well-known/openid-configuration)" || {
    echo "[run-locally] discovery fetch failed" >&2
    exit 3
}
echo "${DISCOVERY_BODY}" | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint}' || {
    echo "[run-locally] discovery body not valid JSON: ${DISCOVERY_BODY}" >&2
    exit 3
}

# 6. smoke
step "step 6/8 — integration-smoke"
COAUTH_BASE="${COAUTH_BASE:-http://127.0.0.1:57080}" \
    bash "${SCRIPTS}/integration-smoke.sh" || {
    echo "[run-locally] integration-smoke failed" >&2
    exit 3
}

# 7. e2e
step "step 7/8 — integration-e2e (S1 + S2 + S3)"
COAUTH_BASE="${COAUTH_BASE:-http://127.0.0.1:57080}" \
    bash "${SCRIPTS}/integration-e2e.sh" || {
    echo "[run-locally] integration-e2e failed" >&2
    exit 3
}

# 8. conformance (optional)
if (( WITH_CONFORMANCE == 1 )); then
    step "step 8/8 — oidc-conformance plan-basic-op"
    COAUTH_SKIP_BOOT=1 \
        COAUTH_BIND=127.0.0.1:57080 \
        COAUTH_RUN_FULL_CONFORMANCE=1 \
        bash "${SCRIPTS}/oidc-conformance.sh" --plan basic-op || {
        echo "[run-locally] oidc-conformance plan-basic-op failed" >&2
        exit 3
    }
else
    step "step 8/8 — oidc-conformance (skipped; pass --with-conformance to run)"
fi

echo
echo "[run-locally] ============================================================"
echo "[run-locally]   all steps passed"
echo "[run-locally] ============================================================"
