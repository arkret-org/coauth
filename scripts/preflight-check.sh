#!/usr/bin/env bash
# Preflight check for the integration / OIDC-conformance docker-compose stack.
#
# Catches the misconfiguration classes that have repeatedly bitten round-28
# CI work *before* you spend 5+ minutes on a docker compose build:
#
#   1. docker / docker compose presence + daemon reachability
#   2. compose-file syntactic validity
#   3. port collisions on the host (55432, 57080, 58008, 59090, 57180)
#   4. distroless-incompatible healthchecks (`wget` / `curl` / `CMD-SHELL`)
#      against any service whose image is documented as distroless
#   5. presence of `coauth healthcheck` subcommand referenced by the
#      compose healthcheck (parses cli/src/commands/mod.rs)
#   6. presence of dependent images (postgres pulled, soland/sodmin tags
#      reachable or compose has `build:` clause)
#   7. plan-*.json validity + discoveryUrl bind alignment
#
# Exit codes:
#   0 — every check passed
#   1 — at least one warning (best-effort fixable)
#   2 — at least one hard error (would break compose up)
#
# Usage:
#   ./scripts/preflight-check.sh
#   ./scripts/preflight-check.sh --strict     # warnings become errors
#
# This is not a substitute for actually running the stack — but every
# class of failure caught here is one that historically left a CI run
# red after a 5-10 minute build.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.integration.yaml"
CONFORMANCE_DIR="${REPO_ROOT}/conformance"
CLI_MOD_RS="${REPO_ROOT}/crates/cli/src/commands/mod.rs"

STRICT=0
for arg in "$@"; do
    case "${arg}" in
        --strict) STRICT=1 ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "[preflight] unknown flag: ${arg}" >&2; exit 2 ;;
    esac
done

WARNINGS=0
ERRORS=0

ok()    { echo "[preflight]   OK   $*"; }
warn()  { echo "[preflight]   WARN $*" >&2; WARNINGS=$((WARNINGS + 1)); }
err()   { echo "[preflight]   ERR  $*" >&2; ERRORS=$((ERRORS + 1)); }
heading() { echo; echo "[preflight] === $* ==="; }

# ─────────────────────────────────────────────────────────────────────
# 1. docker availability
# ─────────────────────────────────────────────────────────────────────
heading "docker"
if ! command -v docker >/dev/null 2>&1; then
    err "docker not found on PATH"
else
    ok "docker $(docker --version | awk '{print $3}' | tr -d ',')"
    if ! docker info >/dev/null 2>&1; then
        err "docker daemon not reachable (is Docker Desktop / dockerd running?)"
    else
        ok "docker daemon reachable"
    fi
fi
if ! docker compose version >/dev/null 2>&1; then
    err "docker compose plugin not installed"
else
    ok "docker compose $(docker compose version --short 2>/dev/null || echo unknown)"
fi

# scripts/integration-up.sh leans on python3 to rewrite the
# `coauth config generate` output deterministically (the legacy sed
# pipeline was brittle against multi-listener YAML). jq powers
# conformance plan parsing + the e2e harness.
heading "host tools"
if command -v python3 >/dev/null 2>&1; then
    ok "python3 $(python3 --version 2>&1 | awk '{print $2}')"
else
    err "python3 not on PATH; integration-up.sh config rewrite will fail"
fi
if command -v curl >/dev/null 2>&1; then
    ok "curl present"
else
    err "curl not on PATH; smoke + e2e + conformance probes will fail"
fi
if command -v jq >/dev/null 2>&1; then
    ok "jq $(jq --version 2>&1)"
else
    warn "jq not on PATH; conformance plan parse + e2e bodies will fail"
fi

# Sibling-repo path-deps. The workspace `Cargo.toml` references
# `../cokret-rust-sdk/...` so the docker build context (now the
# parent dir per docker-compose.integration.yaml) needs to find it.
heading "sibling repos"
SDK_DIR="$(cd "${REPO_ROOT}/.." && pwd)/cokret-rust-sdk"
if [[ -f "${SDK_DIR}/Cargo.toml" ]]; then
    ok "cokret-rust-sdk present at ${SDK_DIR}"
else
    err "cokret-rust-sdk missing at ${SDK_DIR}; docker build will fail at chef cook"
fi

# ─────────────────────────────────────────────────────────────────────
# 2. compose file validity
# ─────────────────────────────────────────────────────────────────────
heading "compose file"
if [[ ! -f "${COMPOSE_FILE}" ]]; then
    err "missing ${COMPOSE_FILE}"
else
    if docker compose -f "${COMPOSE_FILE}" config --quiet 2>compose.err; then
        ok "compose file parses"
    else
        err "compose file invalid:"
        cat compose.err >&2
    fi
    rm -f compose.err
fi

# ─────────────────────────────────────────────────────────────────────
# 3. port collisions
# ─────────────────────────────────────────────────────────────────────
heading "host port collisions"
# Pull declared host ports out of the compose file. We could parse YAML
# properly, but the line-oriented `- "<host>:<container>"` form is
# stable enough for grep.
declare -a HOST_PORTS=()
# Extract the host-side port from compose `- "<host>:<container>"` entries.
# Strip the leading `- "` and everything from the first `:` onward.
while IFS= read -r port; do
    [[ -n "${port}" ]] && HOST_PORTS+=("${port}")
done < <(grep -oE '"[0-9]+:[0-9]+"' "${COMPOSE_FILE}" | tr -d '"' | cut -d: -f1 | sort -u)

for port in "${HOST_PORTS[@]}"; do
    # `ss` and `lsof` aren't portable on Windows-Bash; fall back to
    # asking the OS via netstat. We just need a true/false.
    bound=0
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}\$" && bound=1
    elif command -v netstat >/dev/null 2>&1; then
        netstat -an 2>/dev/null | grep -E "[:.]${port}[[:space:]].*LISTEN" >/dev/null && bound=1
    fi
    if [[ "${bound}" == "1" ]]; then
        warn "host port ${port} already bound; compose up will fail"
    else
        ok "host port ${port} is free"
    fi
done

# ─────────────────────────────────────────────────────────────────────
# 4. distroless-incompatible healthchecks
# ─────────────────────────────────────────────────────────────────────
heading "healthcheck portability"
# Distroless images (gcr.io/distroless/...) have no shell, no wget, no
# curl. A `CMD-SHELL` healthcheck or a `wget`/`curl` invocation against
# them silently degrades to "always unhealthy". The coauth runtime is
# distroless cc-debian12 per Dockerfile.
if grep -nE 'CMD-SHELL.*(wget|curl)' "${COMPOSE_FILE}" >/dev/null; then
    err "compose file has CMD-SHELL wget/curl healthcheck — incompatible with distroless"
    grep -nE 'CMD-SHELL.*(wget|curl)' "${COMPOSE_FILE}" | sed 's/^/      /' >&2
else
    ok "no CMD-SHELL wget/curl healthchecks (distroless-safe)"
fi

# ─────────────────────────────────────────────────────────────────────
# 5. coauth healthcheck subcommand exists
# ─────────────────────────────────────────────────────────────────────
heading "coauth subcommands"
if [[ -f "${CLI_MOD_RS}" ]]; then
    if grep -q 'Healthcheck' "${CLI_MOD_RS}"; then
        ok "coauth healthcheck subcommand wired"
    else
        err "coauth healthcheck subcommand missing from ${CLI_MOD_RS}"
    fi
    if grep -q 'Server' "${CLI_MOD_RS}" && grep -q 'Config' "${CLI_MOD_RS}"; then
        ok "coauth server + config subcommands present"
    else
        err "coauth server / config subcommands missing"
    fi
else
    warn "${CLI_MOD_RS} not found (running outside repo?)"
fi

# Nobody should reference --no-config; it doesn't exist.
if grep -rn 'coauth.*server.*--no-config\|coauth.*server.*--no_config' \
        "${REPO_ROOT}/scripts" "${REPO_ROOT}/.github" 2>/dev/null | grep -v 'preflight-check.sh' >/dev/null; then
    err "found references to bogus --no-config flag:"
    grep -rn 'coauth.*server.*--no-config\|coauth.*server.*--no_config' \
        "${REPO_ROOT}/scripts" "${REPO_ROOT}/.github" 2>/dev/null \
        | grep -v 'preflight-check.sh' | sed 's/^/      /' >&2
else
    ok "no --no-config flag references"
fi

# ─────────────────────────────────────────────────────────────────────
# 6. dependent images
# ─────────────────────────────────────────────────────────────────────
heading "dependent images"
if docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    ok "postgres:16-alpine present locally"
else
    warn "postgres:16-alpine not pulled (compose up will pull it)"
fi
# soland / sodmin are profile-gated; only flag if the user is asking for
# them and the tag isn't pullable. We just warn unconditionally.
for img in soland:dev sodmin:dev; do
    if docker image inspect "${img}" >/dev/null 2>&1; then
        ok "${img} present locally"
    else
        warn "${img} not present locally; --with-downstream will fail unless built"
    fi
done

# ─────────────────────────────────────────────────────────────────────
# 7. conformance plan validity + bind alignment
# ─────────────────────────────────────────────────────────────────────
heading "conformance plans"
if [[ ! -d "${CONFORMANCE_DIR}" ]]; then
    err "${CONFORMANCE_DIR} missing"
else
    plan_count=0
    for plan in "${CONFORMANCE_DIR}"/plan-*.json; do
        [[ -e "${plan}" ]] || continue
        plan_count=$((plan_count + 1))
        if command -v jq >/dev/null 2>&1; then
            if jq empty "${plan}" 2>/dev/null; then
                alias="$(jq -r '.alias // "<no-alias>"' "${plan}")"
                ok "$(basename "${plan}") parses (alias=${alias})"
            else
                err "$(basename "${plan}") is not valid JSON"
            fi
            disc="$(jq -r '.server.discoveryUrl // ""' "${plan}")"
            if [[ -z "${disc}" ]]; then
                err "$(basename "${plan}") missing .server.discoveryUrl"
            fi
        else
            warn "jq not installed; skipping plan parse"
        fi
    done
    if (( plan_count == 0 )); then
        err "no plan-*.json files in ${CONFORMANCE_DIR}"
    fi
fi

# ─────────────────────────────────────────────────────────────────────
# Verdict
# ─────────────────────────────────────────────────────────────────────
echo
echo "[preflight] ─── summary ─── errors=${ERRORS} warnings=${WARNINGS}"

if (( ERRORS > 0 )); then
    exit 2
fi
if (( WARNINGS > 0 )) && (( STRICT == 1 )); then
    exit 1
fi
exit 0
