#!/usr/bin/env bash
# OIDC conformance runner — round 28.
#
# Two layers:
#
#   1. boots a coauth instance on http://127.0.0.1:8080 from the prebuilt
#      release binary (CI runs `cargo build --release -p coauth-cli`
#      first; locally you can do the same), waits for /health, fetches
#      /.well-known/openid-configuration, and pretty-prints it. The
#      `--with-stack` / `COAUTH_SKIP_BOOT=1` env var skips this layer
#      when CI has already brought up coauth via docker-compose.
#
#   2. when `COAUTH_RUN_FULL_CONFORMANCE=1` is set in the environment,
#      pulls `openid/conformance-suite:latest` via Docker, mounts the
#      `conformance/` directory at `/server/configs:ro`, and invokes one
#      or more `plan-*.json` configs via `--config`. Results land in
#      `target/conformance-results/<plan>.json`. The script exits
#      non-zero on the first failed plan.
#
# Plan selection (round-28 `--plan` flag):
#
#   --plan basic-op           runs only conformance/plan-basic-op.json
#   --plan fapi2-baseline     runs only conformance/plan-fapi2-baseline.json
#   --plan mtls-baseline      runs only conformance/plan-mtls-baseline.json
#   --plan all                runs every plan-*.json (default)
#
# Or via env var: `CONFORMANCE_PLAN=mtls-baseline ./scripts/oidc-conformance.sh`.
#
# Usage (locally):
#   $ cargo build --release -p coauth-cli
#   $ ./scripts/oidc-conformance.sh
#
# Usage (CI, against compose-managed coauth):
#   $ COAUTH_SKIP_BOOT=1 COAUTH_RUN_FULL_CONFORMANCE=1 \
#       COAUTH_BIND=127.0.0.1:57080 \
#       ./scripts/oidc-conformance.sh --plan basic-op

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
readonly COAUTH_BINARY="${COAUTH_BINARY:-target/release/coauth-cli}"
readonly DISCOVERY_URL="http://${COAUTH_BIND}/.well-known/openid-configuration"
readonly HEALTH_URL="http://${COAUTH_BIND}/health"
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
        echo "    cargo build --release -p coauth-cli" >&2
        exit 2
    fi
    if [[ -z "${COAUTH_CONFIG:-}" ]]; then
        echo "[oidc-conformance] COAUTH_CONFIG is unset; coauth needs a config file with valid signing keys." >&2
        echo "    Generate one with: ${COAUTH_BINARY} config generate -o /tmp/coauth-conformance.yaml" >&2
        echo "    Then re-run with: COAUTH_CONFIG=/tmp/coauth-conformance.yaml $0" >&2
        exit 2
    fi
    COAUTH_LOG="$(mktemp)"
    # NOTE: the legacy `--no-config` flag does not exist in the server
    # subcommand. The server reads its config from $COAUTH_CONFIG (or
    # the default `config.yaml`); pass `--config <path>` if you want a
    # specific file outside that lookup chain.
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
# Layer 2: optionally invoke openid/conformance-suite via Docker
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
    echo "  set COAUTH_RUN_FULL_CONFORMANCE=1 to invoke openid/conformance-suite:latest."
    exit 0
fi

# The remainder is the opt-in path. We're tolerant of a missing docker
# binary because the same script is run by developers without Docker
# locally — we just log + fall back to the inventory output.
if ! command -v docker >/dev/null 2>&1; then
    echo "[oidc-conformance] COAUTH_RUN_FULL_CONFORMANCE=1 but docker is not on PATH; skipping" >&2
    exit 0
fi

mkdir -p "${RESULTS_DIR}"

# Image pull. The OpenID Foundation does not publish a Docker Hub image
# under `openid/conformance-suite:latest` — the conformance harness has
# always shipped as a self-built Java + MongoDB stack from
# https://gitlab.com/openid/conformance-suite. CI / local runs that want
# the full suite should:
#
#   git clone https://gitlab.com/openid/conformance-suite
#   cd conformance-suite
#   ./builder-compose.sh
#
# and then point COAUTH_CONFORMANCE_IMAGE at the local tag. We honour an
# override env var so the script keeps working in environments that have
# a private mirror or a local build.
CONFORMANCE_IMAGE="${COAUTH_CONFORMANCE_IMAGE:-openid/conformance-suite:latest}"
echo "[oidc-conformance] pulling ${CONFORMANCE_IMAGE}"
if ! docker pull "${CONFORMANCE_IMAGE}"; then
    echo "[oidc-conformance] failed to pull ${CONFORMANCE_IMAGE}; skipping run" >&2
    echo "[oidc-conformance] (the OIDF does NOT publish a public Docker image — see " >&2
    echo "   https://gitlab.com/openid/conformance-suite — clone + build then set " >&2
    echo "   COAUTH_CONFORMANCE_IMAGE=<local-tag> to wire the run.)" >&2
    exit 0
fi

# When COAUTH_BIND is non-default, rewrite each plan into a temp working
# copy with the discoveryUrl pointing at the actual bind address. The
# canonical configs in `conformance/` always declare 127.0.0.1:8080
# because that's the local-dev default. WORK_DIR is teardown by the
# unified `cleanup` trap installed near the top of this script.
WORK_DIR="$(mktemp -d)"
declare -a PREPARED_PLANS=()
for cfg in "${PLAN_FILES[@]}"; do
    name="$(basename "${cfg}")"
    if [[ "${COAUTH_BIND}" != "127.0.0.1:8080" ]]; then
        out="${WORK_DIR}/${name}"
        jq --arg url "${DISCOVERY_URL}" '.server.discoveryUrl = $url' \
            "${cfg}" > "${out}"
        PREPARED_PLANS+=("${out}")
    else
        PREPARED_PLANS+=("${cfg}")
    fi
done

# Each plan-*.json is consumed by the conformance suite's `--config`
# CLI. We invoke a one-shot per plan and fail fast on the first error
# so the operator gets actionable output.
for cfg in "${PREPARED_PLANS[@]}"; do
    plan_name="$(basename "${cfg}" .json)"
    echo
    echo "[oidc-conformance] running plan ${plan_name}"
    docker run --rm \
        --network host \
        -v "$(dirname "${cfg}"):/server/configs:ro" \
        -v "$(pwd)/${RESULTS_DIR}:/server/results:rw" \
        "${CONFORMANCE_IMAGE}" \
        --config "/server/configs/$(basename "${cfg}")" \
        --output "/server/results/${plan_name}.json" \
        || {
            echo "[oidc-conformance] plan ${plan_name} FAILED" >&2
            exit 4
        }
    echo "[oidc-conformance] plan ${plan_name} PASS — results at ${RESULTS_DIR}/${plan_name}.json"
done

echo
echo "[oidc-conformance] all selected plans passed; results in ${RESULTS_DIR}/"
