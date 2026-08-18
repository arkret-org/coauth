#!/usr/bin/env bash
# Integration smoke: hit each service's `/health` endpoint and confirm 200.
#
# Intentionally tiny: this is a bring-up smoke, not an e2e harness. The
# scope is "the docker-compose.integration.yaml stack actually came up and
# the probed services are reachable on their published ports".
#
# Exit codes:
#   0 — every probed endpoint returned HTTP 200
#   3 — at least one endpoint failed or never responded within the budget
#
# Usage:
#   ./scripts/integration-smoke.sh                     # core stack
#   ./scripts/integration-smoke.sh --with-downstream   # + soland + sodmin

set -euo pipefail

ATTEMPT_BUDGET="${SMOKE_ATTEMPT_BUDGET:-30}"

probe() {
    local name="$1"
    local url="$2"
    for attempt in $(seq 1 "${ATTEMPT_BUDGET}"); do
        local code
        code="$(curl -fsS -o /dev/null -m 2 -w '%{http_code}' "${url}" || echo "000")"
        if [[ "${code}" == "200" ]]; then
            echo "[smoke] ${name}: 200 OK (after ${attempt} attempt(s))"
            return 0
        fi
        sleep 1
    done
    echo "[smoke] ${name}: never returned 200 (${url})" >&2
    return 1
}

# Bases are env-overridable so the same smoke runs against either the
# docker-compose-mapped ports (default: 57080 etc.) or a coauth bound
# locally on its native port (e.g. COAUTH_BASE=http://127.0.0.1:7080).
COAUTH_BASE="${COAUTH_BASE:-http://127.0.0.1:57080}"
SOLAND_BASE="${SOLAND_BASE:-http://127.0.0.1:58008}"
SODMIN_BASE="${SODMIN_BASE:-http://127.0.0.1:59090}"

probes=(
    "coauth ${COAUTH_BASE}/health"
)

# Add downstream probes based on flags. The default profile
# only brings up postgres + coauth, so probing soland/sodmin would fail
# even on a healthy stack — they're gated behind --with-downstream now
# to match the integration-up.sh profile semantics.
for arg in "$@"; do
    case "${arg}" in
        --with-downstream)
            probes+=(
                "soland ${SOLAND_BASE}/health"
                "sodmin ${SODMIN_BASE}/health"
            )
            ;;
    esac
done

failures=0
for entry in "${probes[@]}"; do
    name="${entry%% *}"
    url="${entry#* }"
    if ! probe "${name}" "${url}"; then
        failures=$((failures + 1))
    fi
done

if (( failures > 0 )); then
    echo "[smoke] ${failures} probe(s) failed" >&2
    exit 3
fi

echo "[smoke] all probes returned 200"
