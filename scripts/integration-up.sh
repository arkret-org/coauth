#!/usr/bin/env bash
# Bring up the coauth integration stack (Postgres + coauth + soland + sodmin
# and optionally starid).
#
# Usage:
#   ./scripts/integration-up.sh                 # core stack
#   ./scripts/integration-up.sh --with-starid   # core stack + starid (did:webvh)
#   ./scripts/integration-up.sh --down          # tear down + remove volumes
#
# Image overrides (env vars consumed by docker-compose.integration.yaml):
#   COAUTH_IMAGE  SOLAND_IMAGE  SODMIN_IMAGE  STARID_IMAGE
#
# The compose file lives at the repo root; this script just wraps the common
# flag combinations so the smoke harness has a single entry point.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.integration.yaml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "[integration-up] missing ${COMPOSE_FILE}" >&2
    exit 2
fi

profile_args=()
action="up"

for arg in "$@"; do
    case "${arg}" in
        --with-starid)
            profile_args+=("--profile" "did-webvh")
            ;;
        --down)
            action="down"
            ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "[integration-up] unknown flag: ${arg}" >&2
            exit 2
            ;;
    esac
done

if [[ "${action}" == "down" ]]; then
    docker compose -f "${COMPOSE_FILE}" "${profile_args[@]}" down -v
    exit 0
fi

# Detached up; the smoke script polls /health afterwards.
docker compose -f "${COMPOSE_FILE}" "${profile_args[@]}" up -d --wait

echo "[integration-up] stack is up. Endpoints:"
echo "  coauth   http://127.0.0.1:57080/health"
echo "  soland   http://127.0.0.1:58008/health"
echo "  sodmin   http://127.0.0.1:59090/health"
if [[ " $* " == *" --with-starid "* ]]; then
    echo "  starid   http://127.0.0.1:57180/health"
fi
echo
echo "Run ./scripts/integration-smoke.sh to verify each /health returns 200."
