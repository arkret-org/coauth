#!/usr/bin/env bash
# Drive the OpenID Connect Core (OIDCC) certification test plans
# defined in conformance/configs/test-plans.json against a coauth
# instance.
#
# Relationship to scripts/oidc-conformance.sh:
#   scripts/oidc-conformance.sh runs the FAPI 2.0 / mTLS / basic-OP
#   smoke and full plans from conformance/plan-*.json. THIS script
#   drives the strictly OIDC-Core certification matrix from
#   conformance/configs/test-plans.json and is the one operators wire
#   into the OIDF certification submission. Both scripts share the
#   Java + MongoDB harness from https://gitlab.com/openid/conformance-suite
#   but address different profile families.
#
# OIDCC test plans driven by this script (see configs/test-plans.json):
#   - oidcc-basic-certification-test-plan
#   - oidcc-hybrid-certification-test-plan
#   - oidcc-device-code-certification-test-plan
#
# Boot model:
#   1. Operator brings up a coauth instance reachable at COAUTH_BIND
#      (default 127.0.0.1:8080). Either:
#          cargo run --release -p coauth-cli -- server --config ...
#      or via docker compose (`scripts/integration-up.sh`).
#      Set COAUTH_SKIP_BOOT=1 when coauth is already running and this
#      script must not try to spawn one.
#   2. Operator clones + builds the conformance harness once (the OIDF
#      does NOT publish a public Docker image — same caveat as
#      scripts/oidc-conformance.sh):
#          git clone https://gitlab.com/openid/conformance-suite
#          cd conformance-suite
#          ./builder-compose.sh
#      Tag the resulting image and export
#          export COAUTH_CONFORMANCE_IMAGE=openid/conformance-suite:local
#   3. Run this script. Per-plan JSON reports land in
#      target/conformance-results/oidcc-<alias>.json
#
# Usage:
#   ./conformance/scripts/run-oidcc-suite.sh                       # all plans
#   ./conformance/scripts/run-oidcc-suite.sh --plan basic          # one plan
#   ./conformance/scripts/run-oidcc-suite.sh --plan hybrid
#   ./conformance/scripts/run-oidcc-suite.sh --plan device-code
#   ./conformance/scripts/run-oidcc-suite.sh --list                # show matrix
#   ./conformance/scripts/run-oidcc-suite.sh --dry-run             # render configs, skip docker
#
# Environment:
#   COAUTH_BIND                  Host:port coauth listens on (default 127.0.0.1:8080).
#   COAUTH_SKIP_BOOT             If "1", skip the local-binary boot check.
#                                Pre-existing instance is assumed reachable.
#   COAUTH_CONFORMANCE_IMAGE     Docker image tag for the conformance suite.
#                                Default openid/conformance-suite:latest. There
#                                is no public Docker Hub image; operators MUST
#                                build the harness locally and override this.
#   CONFORMANCE_OIDCC_PLAN       Same effect as --plan.
#   RESULTS_DIR                  Where per-plan JSON reports land
#                                (default target/conformance-results).
#   COAUTH_OIDCC_DRY_RUN         If "1", render configs to a temp dir and exit
#                                without invoking docker.
#
# Exit codes:
#   0  every selected plan passed (or --list / --dry-run completed).
#   2  CLI / config error.
#   3  coauth was not reachable.
#   4  one or more plans FAILED (full results in $RESULTS_DIR).

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${CONFORMANCE_DIR}/.." && pwd)"
PLAN_MATRIX="${CONFORMANCE_DIR}/configs/test-plans.json"

readonly COAUTH_BIND="${COAUTH_BIND:-127.0.0.1:8080}"
readonly DISCOVERY_URL="http://${COAUTH_BIND}/.well-known/openid-configuration"
readonly HEALTH_URL="http://${COAUTH_BIND}/health"
readonly COAUTH_SKIP_BOOT="${COAUTH_SKIP_BOOT:-0}"
readonly RESULTS_DIR="${RESULTS_DIR:-${REPO_ROOT}/target/conformance-results}"
readonly DRY_RUN="${COAUTH_OIDCC_DRY_RUN:-0}"
readonly CONFORMANCE_IMAGE="${COAUTH_CONFORMANCE_IMAGE:-openid/conformance-suite:latest}"

# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────
PLAN_SELECTION="${CONFORMANCE_OIDCC_PLAN:-all}"
LIST_ONLY=0

usage() {
    sed -n '2,55p' "${BASH_SOURCE[0]}"
}

while (( $# > 0 )); do
    case "$1" in
        --plan)
            shift
            if [[ $# -eq 0 ]]; then
                echo "[oidcc-suite] --plan requires an argument" >&2
                exit 2
            fi
            PLAN_SELECTION="$1"
            shift
            ;;
        --plan=*)
            PLAN_SELECTION="${1#--plan=}"
            shift
            ;;
        --list)
            LIST_ONLY=1
            shift
            ;;
        --dry-run)
            # Same effect as setting COAUTH_OIDCC_DRY_RUN=1.
            export COAUTH_OIDCC_DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[oidcc-suite] unknown flag: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────
# Dependency checks
# ─────────────────────────────────────────────────────────────────────
if ! command -v jq >/dev/null 2>&1; then
    echo "[oidcc-suite] jq is required to parse ${PLAN_MATRIX}" >&2
    exit 2
fi

if [[ ! -f "${PLAN_MATRIX}" ]]; then
    echo "[oidcc-suite] missing plan matrix at ${PLAN_MATRIX}" >&2
    exit 2
fi

# Validate JSON early so a typo in the matrix surfaces with a clear
# pointer rather than a downstream jq-in-loop failure.
if ! jq -e '.plans | type == "array"' "${PLAN_MATRIX}" >/dev/null; then
    echo "[oidcc-suite] ${PLAN_MATRIX} is not valid; .plans must be an array" >&2
    exit 2
fi

# ─────────────────────────────────────────────────────────────────────
# Plan selection
# ─────────────────────────────────────────────────────────────────────
mapfile -t ALL_ALIASES < <(jq -r '.plans[].alias' "${PLAN_MATRIX}")
mapfile -t ALL_IDS     < <(jq -r '.plans[].id'    "${PLAN_MATRIX}")

short_for_alias() {
    # coauth-oidcc-basic -> basic
    # coauth-oidcc-device-code -> device-code
    local alias="$1"
    printf '%s\n' "${alias#coauth-oidcc-}"
}

declare -a SELECTED_INDEXES=()
case "${PLAN_SELECTION}" in
    all)
        for i in "${!ALL_ALIASES[@]}"; do
            SELECTED_INDEXES+=("$i")
        done
        ;;
    *)
        # Allow the user to pass either the short form (`basic`,
        # `hybrid`, `device-code`) or the full plan id /alias.
        found=0
        for i in "${!ALL_ALIASES[@]}"; do
            short="$(short_for_alias "${ALL_ALIASES[$i]}")"
            if [[ "${PLAN_SELECTION}" == "${short}" \
                || "${PLAN_SELECTION}" == "${ALL_ALIASES[$i]}" \
                || "${PLAN_SELECTION}" == "${ALL_IDS[$i]}" ]]; then
                SELECTED_INDEXES+=("$i")
                found=1
                break
            fi
        done
        if [[ "${found}" -eq 0 ]]; then
            echo "[oidcc-suite] unknown --plan '${PLAN_SELECTION}'; valid short names:" >&2
            for alias in "${ALL_ALIASES[@]}"; do
                echo "    $(short_for_alias "${alias}")" >&2
            done
            echo "    all" >&2
            exit 2
        fi
        ;;
esac

# ─────────────────────────────────────────────────────────────────────
# --list short-circuit
# ─────────────────────────────────────────────────────────────────────
if [[ "${LIST_ONLY}" -eq 1 ]]; then
    echo "[oidcc-suite] OIDCC test plan matrix (${PLAN_MATRIX}):"
    for i in "${!ALL_ALIASES[@]}"; do
        marker=" "
        for selected in "${SELECTED_INDEXES[@]}"; do
            if [[ "${selected}" == "${i}" ]]; then
                marker="*"
                break
            fi
        done
        printf '  %s %s (alias=%s)\n' \
            "${marker}" \
            "${ALL_IDS[$i]}" \
            "${ALL_ALIASES[$i]}"
    done
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────
# Coauth reachability
# ─────────────────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" != "1" ]]; then
    if [[ "${COAUTH_SKIP_BOOT}" != "1" ]]; then
        echo "[oidcc-suite] expecting an operator-managed coauth at ${COAUTH_BIND}."
        echo "    set COAUTH_SKIP_BOOT=1 to silence this notice."
    fi
    echo "[oidcc-suite] waiting up to 30s for ${HEALTH_URL}…"
    healthy=0
    for attempt in $(seq 1 30); do
        if curl -fsS -o /dev/null -m 2 "${HEALTH_URL}"; then
            echo "[oidcc-suite] coauth healthy after ${attempt}s"
            healthy=1
            break
        fi
        sleep 1
    done
    if [[ "${healthy}" -ne 1 ]]; then
        echo "[oidcc-suite] coauth never reached healthy state at ${HEALTH_URL}" >&2
        echo "    bring it up locally with:" >&2
        echo "      cargo run --release -p coauth-cli -- server --config <config.yaml>" >&2
        echo "    or via docker compose:" >&2
        echo "      bash scripts/integration-up.sh" >&2
        exit 3
    fi

    echo "[oidcc-suite] fetching ${DISCOVERY_URL}"
    curl -fsS "${DISCOVERY_URL}" | jq . >/dev/null \
        || { echo "[oidcc-suite] discovery document is not valid JSON" >&2; exit 3; }
fi

# ─────────────────────────────────────────────────────────────────────
# Render per-plan configs
# ─────────────────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

mkdir -p "${RESULTS_DIR}"

render_plan_config() {
    local index="$1"
    local out="$2"

    jq --arg url "${DISCOVERY_URL}" \
       --argjson i "${index}" \
       '.plans[$i]
            | {
                _comment: "Rendered from conformance/configs/test-plans.json by run-oidcc-suite.sh. Do not edit by hand; re-run the script.",
                alias: .alias,
                description: .description,
                publish: "summary",
                server: { discoveryUrl: $url },
                client: .client,
                client2: .client2,
                profile: .profile,
                variant: .variant
              }' \
        "${PLAN_MATRIX}" > "${out}"
}

declare -a PREPARED=()
for i in "${SELECTED_INDEXES[@]}"; do
    alias="${ALL_ALIASES[$i]}"
    out="${WORK_DIR}/${alias}.json"
    render_plan_config "${i}" "${out}"
    PREPARED+=("${out}")
done

echo
echo "[oidcc-suite] selected plans:"
for cfg in "${PREPARED[@]}"; do
    plan_id="$(jq -r '.alias' "${cfg}")"
    echo "  * ${plan_id}  (${cfg})"
done

if [[ "${DRY_RUN}" == "1" ]]; then
    echo
    echo "[oidcc-suite] dry run requested — leaving rendered configs in ${WORK_DIR}"
    # Disable the cleanup trap so the operator can inspect the files.
    trap - EXIT
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────
# Docker invocation per plan
# ─────────────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    echo "[oidcc-suite] docker is not on PATH — cannot invoke the harness." >&2
    echo "    Either install docker or re-run with --dry-run." >&2
    exit 2
fi

echo
echo "[oidcc-suite] pulling ${CONFORMANCE_IMAGE}"
if ! docker pull "${CONFORMANCE_IMAGE}" >/dev/null; then
    echo "[oidcc-suite] failed to pull ${CONFORMANCE_IMAGE}." >&2
    echo "    The OpenID Foundation does NOT publish a public Docker image." >&2
    echo "    Build the harness locally and override COAUTH_CONFORMANCE_IMAGE:" >&2
    echo "      git clone https://gitlab.com/openid/conformance-suite" >&2
    echo "      cd conformance-suite && ./builder-compose.sh" >&2
    echo "      export COAUTH_CONFORMANCE_IMAGE=openid/conformance-suite:local" >&2
    exit 2
fi

declare -a FAILED_PLANS=()
for cfg in "${PREPARED[@]}"; do
    alias="$(jq -r '.alias' "${cfg}")"
    echo
    echo "[oidcc-suite] running ${alias}"
    if docker run --rm \
            --network host \
            -v "$(dirname "${cfg}"):/server/configs:ro" \
            -v "${RESULTS_DIR}:/server/results:rw" \
            "${CONFORMANCE_IMAGE}" \
            --config "/server/configs/$(basename "${cfg}")" \
            --output "/server/results/${alias}.json"; then
        echo "[oidcc-suite] ${alias} PASS — results at ${RESULTS_DIR}/${alias}.json"
    else
        echo "[oidcc-suite] ${alias} FAIL — see ${RESULTS_DIR}/${alias}.json" >&2
        FAILED_PLANS+=("${alias}")
    fi
done

echo
if (( ${#FAILED_PLANS[@]} > 0 )); then
    echo "[oidcc-suite] ${#FAILED_PLANS[@]} plan(s) failed:" >&2
    for f in "${FAILED_PLANS[@]}"; do
        echo "    - ${f}" >&2
    done
    exit 4
fi

echo "[oidcc-suite] all selected plans passed; reports in ${RESULTS_DIR}/"
