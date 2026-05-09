#!/usr/bin/env bash
# Integration smoke: hit each service's `/health` endpoint and confirm 200.
#
# Intentionally tiny: this is a bring-up smoke, not an e2e harness. The
# scope is "the docker-compose.integration.yaml stack actually came up and
# the four (or five) services are reachable on their published ports".
#
# Exit codes:
#   0 — every probed endpoint returned HTTP 200
#   3 — at least one endpoint failed or never responded within the budget
#
# Usage:
#   ./scripts/integration-smoke.sh                 # core stack
#   ./scripts/integration-smoke.sh --with-starid   # core stack + starid

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

probes=(
    "coauth http://127.0.0.1:57080/health"
    "soland http://127.0.0.1:58008/health"
    "sodmin http://127.0.0.1:59090/health"
)

if [[ "${1:-}" == "--with-starid" ]]; then
    probes+=("starid http://127.0.0.1:57180/health")
fi

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
