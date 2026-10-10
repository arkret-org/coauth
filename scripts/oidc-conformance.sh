#!/usr/bin/env bash
# OIDC conformance against the official OIDF Java/Mongo API server.
# `discovery` runs the complete OIDCC Config profile; it is not OP/FAPI/mTLS
# certification. `all` retains the full-profile request and fails if the
# protected real-client/login/certificate plan fixtures are unavailable.
# Local fixture bootstrap: conformance/run-local-official-suite.sh.
# Existing running servers: set COAUTH_SKIP_BOOT=1, COAUTH_CONFORMANCE_SOURCE,
# CONFORMANCE_SERVER and COAUTH_CONFORMANCE_DISCOVERY_CONFIG.
# Full profiles additionally require COAUTH_CONFORMANCE_FULL_PLAN_DIR with
# basic-op.json, fapi2-baseline.json and mtls-baseline.json. Each file records
# its actual upstream plan name in _official_plan and uses real client ids.

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# CLI parsing
# ─────────────────────────────────────────────────────────────────────
PLAN_SELECTION="${CONFORMANCE_PLAN:-all}"
while (( $# > 0 )); do
    case "$1" in
        --plan)
            shift
            if [[ $# -eq 0 ]]; then
                echo "[oidc-conformance] --plan requires an argument" >&2
                exit 2
            fi
            PLAN_SELECTION="$1"
            shift
            ;;
        --plan=*)
            PLAN_SELECTION="${1#--plan=}"
            shift
            ;;
        -h|--help)
            sed -n '2,40p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "[oidc-conformance] unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

readonly COAUTH_BIND="${COAUTH_BIND:-127.0.0.1:8080}"
readonly COAUTH_BINARY="${COAUTH_BINARY:-target/release/coauth}"
readonly DISCOVERY_URL="${COAUTH_CONFORMANCE_ISSUER:-http://${COAUTH_BIND}}/.well-known/openid-configuration"
readonly HEALTH_URL="${COAUTH_CONFORMANCE_ISSUER:-http://${COAUTH_BIND}}/health"
readonly COAUTH_SKIP_BOOT="${COAUTH_SKIP_BOOT:-0}"

# ─────────────────────────────────────────────────────────────────────
# Layer 1: boot coauth (skipped when CI already brought it up)
# ─────────────────────────────────────────────────────────────────────
COAUTH_PID=""
COAUTH_LOG=""
WORK_DIR=""
# Single cleanup hook responsible for *every* teardown action. Layer 2
# previously installed its own `trap … EXIT` for the WORK_DIR which
# silently overwrote this trap and left orphaned coauth processes; we
# consolidate both responsibilities here so the hook is composable.
cleanup() {
    if [[ -n "${COAUTH_PID}" ]] && kill -0 "${COAUTH_PID}" 2>/dev/null; then
        kill -INT "${COAUTH_PID}" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "${COAUTH_PID}" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "${COAUTH_PID}" 2>/dev/null || true
    fi
    if [[ -n "${COAUTH_LOG}" && -s "${COAUTH_LOG}" ]]; then
        echo "[oidc-conformance] coauth log:"
        cat "${COAUTH_LOG}"
    fi
    [[ -n "${COAUTH_LOG}" ]] && rm -f "${COAUTH_LOG}"
    [[ -n "${WORK_DIR}" ]] && rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

if [[ "${COAUTH_SKIP_BOOT}" != "1" ]]; then
    if [[ ! -x "${COAUTH_BINARY}" ]]; then
        echo "[oidc-conformance] expected coauth binary at ${COAUTH_BINARY}; build it first with:" >&2
        echo "    cargo build --release -p coauth-cli --bin coauth" >&2
        exit 2
    fi
    if [[ -z "${COAUTH_CONFIG:-}" ]]; then
        echo "[oidc-conformance] COAUTH_CONFIG is unset; coauth needs a config file with valid signing keys." >&2
        echo "    Generate one with: ${COAUTH_BINARY} config generate -o /tmp/coauth-conformance.yaml" >&2
        echo "    Then re-run with: COAUTH_CONFIG=/tmp/coauth-conformance.yaml $0" >&2
        exit 2
    fi
    COAUTH_LOG="$(mktemp)"
    # The server reads its config from $COAUTH_CONFIG (or the default
    # `config.yaml`); pass `--config <path>` if you want a specific file
    # outside that lookup chain.
    "${COAUTH_BINARY}" server --config "${COAUTH_CONFIG}" >"${COAUTH_LOG}" 2>&1 &
    COAUTH_PID=$!
else
    echo "[oidc-conformance] COAUTH_SKIP_BOOT=1 — assuming coauth is already running at ${COAUTH_BIND}"
fi

# Wait up to 30s for /health.
echo "[oidc-conformance] waiting for ${HEALTH_URL}…"
for attempt in $(seq 1 30); do
    if curl -fsS -o /dev/null -m 2 "${HEALTH_URL}"; then
        echo "[oidc-conformance] coauth healthy after ${attempt}s"
        break
    fi
    if [[ "${attempt}" -eq 30 ]]; then
        echo "[oidc-conformance] coauth never reached healthy state" >&2
        exit 3
    fi
    sleep 1
done

echo "[oidc-conformance] fetching ${DISCOVERY_URL}"
DISCOVERY_BODY="$(curl -fsS "${DISCOVERY_URL}")"
echo "${DISCOVERY_BODY}" | (command -v jq >/dev/null && jq . || cat)

# ─────────────────────────────────────────────────────────────────────
# Layer 2: invoke the official Java/Mongo service through its Python API runner
# ─────────────────────────────────────────────────────────────────────
readonly CONFORMANCE_DIR="${CONFORMANCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/conformance}"
readonly RESULTS_DIR="${RESULTS_DIR:-target/conformance-results}"

# Resolve the selected plan(s) into a list of config paths to run.
declare -a PLAN_FILES=()
case "${PLAN_SELECTION}" in
    all)
        for cfg in "${CONFORMANCE_DIR}"/plan-*.json; do
            [[ -e "${cfg}" ]] || continue
            PLAN_FILES+=("${cfg}")
        done
        ;;
    discovery)
        ;;
    *)
        candidate="${CONFORMANCE_DIR}/plan-${PLAN_SELECTION}.json"
        if [[ ! -e "${candidate}" ]]; then
            echo "[oidc-conformance] unknown --plan '${PLAN_SELECTION}'; expected one of:" >&2
            for cfg in "${CONFORMANCE_DIR}"/plan-*.json; do
                [[ -e "${cfg}" ]] || continue
                name="$(basename "${cfg}" .json)"
                echo "    ${name#plan-}" >&2
            done
            echo "    all" >&2
            exit 2
        fi
        PLAN_FILES+=("${candidate}")
        ;;
esac

echo
echo "[oidc-conformance] plan inventory at ${CONFORMANCE_DIR} (selection=${PLAN_SELECTION}):"
if [[ -d "${CONFORMANCE_DIR}" ]]; then
    for cfg in "${CONFORMANCE_DIR}"/plan-*.json; do
        [[ -e "${cfg}" ]] || continue
        local_alias="$(jq -r '.alias // "<no-alias>"' "${cfg}" 2>/dev/null || echo '<unparseable>')"
        marker=" "
        for picked in "${PLAN_FILES[@]}"; do
            if [[ "${picked}" == "${cfg}" ]]; then
                marker="*"
                break
            fi
        done
        echo "  ${marker} $(basename "${cfg}") (alias=${local_alias})"
    done
else
    echo "  [no conformance/ directory; expected ${CONFORMANCE_DIR}]"
fi

if [[ "${COAUTH_RUN_FULL_CONFORMANCE:-}" != "1" ]]; then
    echo
    echo "[oidc-conformance] skipping full conformance run."
    echo "  set COAUTH_RUN_FULL_CONFORMANCE=1 with the official source/API/config fixtures."
    exit 0
fi

# The OIDF suite is a persistent Java/Mongo service. Its official Python
# runner calls the service API; it is not a docker --config CLI.
: "${COAUTH_CONFORMANCE_SOURCE:?checkout the pinned official suite source}"
: "${CONFORMANCE_SERVER:?start the official conformance API server}"
: "${COAUTH_CONFORMANCE_DISCOVERY_CONFIG:?provide the local HTTPS discovery fixture}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "${repo_root}/conformance/run-official-plan.py" \
    --source "${COAUTH_CONFORMANCE_SOURCE}" \
    --config "${COAUTH_CONFORMANCE_DISCOVERY_CONFIG}" \
    --plan oidcc-config-certification-test-plan \
    --results "${RESULTS_DIR}/discovery"

if [[ "${PLAN_SELECTION}" == "discovery" ]]; then
    echo "[oidc-conformance] OIDCC Config discovery profile passed (not full OP/FAPI/mTLS certification)."
    exit 0
fi

# Full authorization profiles additionally need registered clients and an
# automated real-user login/consent configuration. The old committed files
# contain placeholder client ids and are not runnable official suite plans.
# Keep all/full requests fail-closed until these protected fixtures are supplied.
: "${COAUTH_CONFORMANCE_FULL_PLAN_DIR:?full OP/FAPI/mTLS profiles require real registered clients, automated login/consent and matching certificate/key fixtures; set COAUTH_CONFORMANCE_FULL_PLAN_DIR}"
profiles=("${PLAN_SELECTION}")
if [[ "${PLAN_SELECTION}" == "all" ]]; then
    profiles=(basic-op fapi2-baseline mtls-baseline)
fi
for profile in "${profiles[@]}"; do
    config="${COAUTH_CONFORMANCE_FULL_PLAN_DIR}/${profile}.json"
    test -f "${config}"
    plan=$(jq -er '._official_plan' "${config}")
    python3 "${repo_root}/conformance/run-official-plan.py" \
        --source "${COAUTH_CONFORMANCE_SOURCE}" --config "${config}" \
        --plan "${plan}" --results "${RESULTS_DIR}/${profile}"
done
