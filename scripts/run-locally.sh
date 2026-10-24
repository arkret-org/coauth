#!/usr/bin/env bash
# Local verification entry. The default runs all three canonical business
# scenarios with runner-owned PostgreSQL, Station, Account Authority and TLS.
#
# Usage:
#   ./scripts/run-locally.sh                    # canonical S1/S2/S3 + cleanup
#   ./scripts/run-locally.sh -JointDir /path    # pass options to Cotest runner
#   ./scripts/run-locally.sh --keep             # retain canonical services
#   ./scripts/run-locally.sh --oidc             # Compose health + OIDC discovery
#   ./scripts/run-locally.sh --with-conformance # Compose + basic-OP certification
#   ./scripts/run-locally.sh --oidc --down      # remove Compose utility volumes
#
# Business integration fails if any required scenario cannot execute. OIDC
# utility checks report only their selected health/discovery/certification work.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="${REPO_ROOT}/scripts"

WITH_CONFORMANCE=0
KEEP=0
ACTION="up"
MODE="business"
RUNNER_ARGS=()

for arg in "$@"; do
    case "${arg}" in
        --with-conformance) WITH_CONFORMANCE=1; MODE="oidc" ;;
        --oidc)             MODE="oidc" ;;
        --keep)             KEEP=1 ;;
        --down)             ACTION="down" ;;
        -h|--help)
            sed -n '2,15p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            RUNNER_ARGS+=("${arg}")
            ;;
    esac
done

if [[ "${MODE}" == "business" ]]; then
    if [[ "${ACTION}" == "down" ]]; then
        echo "[run-locally] --down manages the Compose utility; use --oidc --down" >&2
        exit 2
    fi
    if (( KEEP == 1 )); then RUNNER_ARGS+=("-KeepServices"); fi
    exec bash "${SCRIPTS}/integration-up.sh" --business ${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}
fi
if (( ${#RUNNER_ARGS[@]} != 0 )); then
    echo "[run-locally] runner options apply only to the canonical business run" >&2
    exit 2
fi

if [[ "${ACTION}" == "down" ]]; then
    bash "${SCRIPTS}/integration-up.sh" --down
    exit $?
fi

step() { echo; echo "[run-locally] ============================================================"; echo "[run-locally]   ${*}"; echo "[run-locally] ============================================================"; }

# 1. integration-up
step "step 1/6 — integration-up (build + bring up postgres + coauth)"
bash "${SCRIPTS}/integration-up.sh" || {
    echo "[run-locally] integration-up failed; check docker compose logs" >&2
    exit 3
}

cleanup() {
    if (( KEEP == 1 )); then
        echo "[run-locally] --keep set; leaving stack up. Tear down with:"
        echo "  ./scripts/run-locally.sh --oidc --down"
        return
    fi
    echo
    echo "[run-locally] tearing down stack"
    bash "${SCRIPTS}/integration-up.sh" --down || true
}
trap cleanup EXIT

# 2. wait for /health
step "step 2/6 — wait for /health 200 on host port 57080"
ATTEMPTS="${HEALTH_ATTEMPTS:-60}"
for attempt in $(sequence 1 "${ATTEMPTS}"); do
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

# 3. mounted YAML check
step "step 3/6 — mounted YAML config check"
if docker compose -f "${REPO_ROOT}/docker-compose.integration.yaml" exec -T coauth \
        /usr/local/bin/coauth healthcheck --config /etc/coauth/config.yaml; then
    echo "[run-locally] in-container healthcheck OK"
else
    echo "[run-locally] in-container healthcheck FAILED" >&2
    exit 3
fi

# 4. discovery
step "step 4/6 — fetch /.well-known/openid-configuration"
DISCOVERY_BODY="$(curl -fsS http://127.0.0.1:57080/.well-known/openid-configuration)" || {
    echo "[run-locally] discovery fetch failed" >&2
    exit 3
}
echo "${DISCOVERY_BODY}" | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint}' || {
    echo "[run-locally] discovery body not valid JSON: ${DISCOVERY_BODY}" >&2
    exit 3
}

# 5. smoke
step "step 5/6 — integration-smoke"
COAUTH_BASE="${COAUTH_BASE:-http://127.0.0.1:57080}" \
    bash "${SCRIPTS}/integration-smoke.sh" || {
    echo "[run-locally] integration-smoke failed" >&2
    exit 3
}

# 6. conformance (optional)
if (( WITH_CONFORMANCE == 1 )); then
    step "step 6/6 — oidc-conformance plan-basic-op"
    COAUTH_SKIP_BOOT=1 \
        COAUTH_BIND=127.0.0.1:57080 \
        COAUTH_RUN_FULL_CONFORMANCE=1 \
        bash "${SCRIPTS}/oidc-conformance.sh" --plan basic-op || {
        echo "[run-locally] oidc-conformance plan-basic-op failed" >&2
        exit 3
    }
else
    step "OIDC health and discovery checks complete"
fi

echo
echo "[run-locally] ============================================================"
echo "[run-locally]   all steps passed"
echo "[run-locally] ============================================================"
