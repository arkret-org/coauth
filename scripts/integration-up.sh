#!/usr/bin/env bash
# Bring up the coauth integration stack (Postgres + coauth and optionally
# coland + codmin via profiles).
#
# Usage:
#   ./scripts/integration-up.sh --business           # canonical S1/S2/S3, automatic cleanup
#   ./scripts/integration-up.sh                      # core health/OIDC utilities only
#   ./scripts/integration-up.sh --with-downstream    # + coland + codmin (need :dev tags)
#   ./scripts/integration-up.sh --down               # tear down + remove volumes
#
# Image overrides (env vars consumed by docker-compose.integration.yaml):
#   COAUTH_IMAGE  COLAND_IMAGE  CODMIN_IMAGE
#
# The compose file lives at the repo root; this script wraps the common
# flag combinations so the smoke harness has a single entry point.
#
# Pre-bringup, this script generates a fresh `conformance/test-config.yaml`
# by running `coauth config generate` inside an ephemeral copy of the
# coauth image. Runtime keys are provisioned into the compose encrypted-file
# KeyStore volume; generated YAML contains no private key material.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.integration.yaml"
GENERATED_CONFIG="${REPO_ROOT}/conformance/test-config.yaml"
COAUTH_IMAGE_REF="${COAUTH_IMAGE:-coauth:dev}"

# Business integration uses Cotest's canonical Station/Account Authority/CA
# provisioning. The small Compose stack below remains a health/OIDC utility.
# It cannot supply accepted principal material or claim business coverage.
if [[ "${1:-}" == "--business" ]]; then
    shift
    for dependency in pwsh cargo node python3; do
        command -v "${dependency}" >/dev/null || { echo "missing ${dependency}" >&2; exit 2; }
    done
    requested_jobs="${CARGO_BUILD_JOBS:-4}"
    [[ "${requested_jobs}" =~ ^[1-9][0-9]*$ ]] || { echo "CARGO_BUILD_JOBS must be a positive integer" >&2; exit 2; }
    case "${requested_jobs}" in
        1|2|3) export CARGO_BUILD_JOBS="${requested_jobs}" ;;
        *) export CARGO_BUILD_JOBS=4 ;;
    esac
    selection_args=()
    binary_args=()
    custom_grep=0
    custom_required=0
    custom_coauth=0
    coauth_argument_pending=0
    selected_coauth_bin=""
    for argument in "$@"; do
        if (( coauth_argument_pending )); then
            selected_coauth_bin="${argument}"
            coauth_argument_pending=0
            continue
        fi
        case "$(printf '%s' "${argument}" | tr '[:upper:]' '[:lower:]')" in
            -grep|-grep:*) custom_grep=1 ;;
            -requirescenario|-requirescenario:*) custom_required=1 ;;
            -coauthbin) custom_coauth=1; coauth_argument_pending=1 ;;
            -coauthbin:*) custom_coauth=1; selected_coauth_bin="${argument#*:}" ;;
        esac
    done
    if (( custom_grep == 0 )); then
        selection_args+=("-Grep" "provisioning bridge")
        if (( custom_required == 0 )); then
            selection_args+=("-RequireScenario" "harness/provisioning-bridge.spec.ts")
        fi
    fi
    if (( custom_coauth )); then
        [[ -n "${selected_coauth_bin}" && "${coauth_argument_pending}" == 0 ]] || { echo "-CoauthBin requires a binary path" >&2; exit 2; }
        export COAUTH_INTEGRATION_COAUTH_BIN="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "${selected_coauth_bin}")"
    fi
    cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" -p coauth-backend --example integration-approval -j "${CARGO_BUILD_JOBS}"
    if (( custom_coauth == 0 )); then
        pwsh -NoProfile -File "${REPO_ROOT}/../cotest/scripts/prepare-cargo-artifact.ps1" \
            -ManifestPath "${REPO_ROOT}/Cargo.toml" -BinaryName coauth -Jobs "${CARGO_BUILD_JOBS}"
        cargo_target="$(cargo metadata --manifest-path "${REPO_ROOT}/Cargo.toml" --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
        export COAUTH_INTEGRATION_COAUTH_BIN="${cargo_target}/debug/coauth"
        binary_args+=("-CoauthBin" "${COAUTH_INTEGRATION_COAUTH_BIN}")
    fi
    # The hook executes inside the canonical runner's exported deployment and
    # must finish successfully before the selected joint checks.
    exec pwsh -NoProfile -File "${REPO_ROOT}/../cotest/scripts/run-joint-e2e.ps1" \
        -RunProfile joint-api -StartCoauth -StartMockEmail -ClientKind garth \
        ${selection_args[@]+"${selection_args[@]}"} \
        ${binary_args[@]+"${binary_args[@]}"} \
        -ForbidSkippedTests \
        -PostProvisionCommand "bash '../coauth/scripts/integration-e2e.sh'" "$@"
fi

if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "[integration-up] missing ${COMPOSE_FILE}" >&2
    exit 2
fi

profile_args=()
action="up"

for arg in "$@"; do
    case "${arg}" in
        --with-downstream)
            profile_args+=("--profile" "downstream")
            ;;
        --down)
            action="down"
            ;;
        -h|--help)
            sed -n '2,19p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "[integration-up] unknown flag: ${arg}" >&2
            exit 2
            ;;
    esac
done

if [[ "${action}" == "down" ]]; then
    docker compose -f "${COMPOSE_FILE}" --profile downstream down -v
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────
# Step 1: build the coauth image so we can use it for config-generation.
# ─────────────────────────────────────────────────────────────────────
echo "[integration-up] building coauth image (${COAUTH_IMAGE_REF})"
COAUTH_IMAGE="${COAUTH_IMAGE_REF}" \
    docker compose -f "${COMPOSE_FILE}" build coauth

# ─────────────────────────────────────────────────────────────────────
# Step 2: generate a key-free config file, mount it later.
# ─────────────────────────────────────────────────────────────────────
if [[ ! -f "${GENERATED_CONFIG}" ]] || [[ "${REGENERATE_CONFIG:-0}" == "1" ]]; then
    echo "[integration-up] generating ${GENERATED_CONFIG} via ephemeral coauth container"
    mkdir -p "$(dirname "${GENERATED_CONFIG}")"
    # `coauth config generate` writes only deployment configuration. The
    # server's explicit --first-provisioning creates the durable key bundle.
    docker run --rm "${COAUTH_IMAGE_REF}" config generate > "${GENERATED_CONFIG}.raw"

    # Patch the generated config so it points at the compose-internal
    # postgres, binds the http listener to 0.0.0.0:7080, exposes /health
    # on the SAME listener (so host-side `127.0.0.1:57080/health` works),
    # and uses the in-cluster service name for issuer/public_base_url.
# The KeyStore backend is supplied by compose environment overrides.
    #
    # The default config-generate output produces TWO listeners — `web`
    # (no health) on `[::]:7080` + `internal` (health-only) on
    # `localhost:8091`. The compose only exposes 7080 to the host, so
    # the host /health probe would 404 against the web listener and the
    # internal listener would never be reachable. We collapse the two
    # listeners into one `web+health` listener at `[::]:7080`.
    #
    # Python is the dependency we lean on: it's already in every CI
    # runner and most dev boxes; sed/awk YAML rewrites have bitten this
    # bring-up enough times that we'd rather pay the python tax.
    python3 - "${GENERATED_CONFIG}.raw" "${GENERATED_CONFIG}" <<'PY'
import sys, re, pathlib

src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
out_path = pathlib.Path(sys.argv[2])

# 1. database.uri → compose internal postgres
src = re.sub(
    r'^(\s*uri:).*$',
    r'\1 postgresql://arkret:arkret@postgres:5432/arkret',
    src, count=1, flags=re.MULTILINE,
)

# 2. http.public_base_url + http.issuer → host-visible loopback URL.
#    We use the host-published port (57080) so the issuer claim in the
#    discovery doc matches what host-side OIDC conformance + e2e see;
#    if we used `http://coauth:7080/` instead, conformance would reject
#    the discovery doc because the issuer wouldn't match the URL it
#    fetched. Compose's container-to-container DNS still works for the
#    `database.uri` field below.
src = re.sub(
    r'^(\s*public_base_url:).*$',
    r'\1 http://127.0.0.1:57080/',
    src, count=1, flags=re.MULTILINE,
)
src = re.sub(
    r'^(\s*issuer:).*$',
    r'\1 http://127.0.0.1:57080/',
    src, count=1, flags=re.MULTILINE,
)

# 3. Replace the entire `http.listeners:` block with a single web+health
#    listener bound to [::]:7080. We splice in a deterministic block
#    instead of rewriting the existing one in-place, which is far more
#    robust than line-oriented edits against multi-listener YAML.
LISTENERS_REPLACEMENT = (
    "  listeners:\n"
    "  - name: web\n"
    "    resources:\n"
    "    - name: discovery\n"
    "    - name: human\n"
    "    - name: oauth\n"
    "    - name: restapi\n"
    "    - name: assets\n"
    "    - name: adminapi\n"
    "    - name: health\n"
    "    binds:\n"
    "    - address: '0.0.0.0:7080'\n"
    "    proxy_protocol: false\n"
)

# Find the `http:` section then the `listeners:` key inside it. Keep
# everything before `listeners:` and everything from the next sibling
# key (any line starting with `  <key>:` that is NOT a list child)
# onward.
m = re.search(r'^http:\s*$', src, flags=re.MULTILINE)
if not m:
    sys.exit("FATAL: no `http:` section in generated config")
http_start = m.end() + 1  # past the trailing newline

# Locate `  listeners:` *under http:*.
ls = re.search(r'^  listeners:\s*$', src[http_start:], flags=re.MULTILINE)
if not ls:
    sys.exit("FATAL: no `http.listeners:` key in generated config")
ls_abs_start = http_start + ls.start()

# Find the next sibling `  <key>:` line (two-space indent + identifier
# starting at column 2) AFTER the listeners block. Children of the
# listeners list begin with `  -` (a dash at column 2) or have deeper
# indent — those stay inside the block. A sibling has an identifier
# character (a-z) at column 2, e.g. `  trusted_proxies:`.
tail_start = None
lines = src[ls_abs_start:].splitlines(keepends=True)
# Skip the `  listeners:` line itself.
offset = len(lines[0])
for line in lines[1:]:
    # Top-level key (no leading whitespace) ends the `http:` section.
    if line and not line[0].isspace():
        break
    # Sibling key under `http:` is exactly two leading spaces + an
    # identifier letter (so `  trusted_proxies:` matches but
    # `  - name: web` and `    name: ...` do not).
    if (
        len(line) > 2
        and line[0] == " "
        and line[1] == " "
        and line[2].isalpha()
    ):
        break
    offset += len(line)
else:
    # Reached EOF — listeners was the last key.
    pass
tail_start = ls_abs_start + offset

src = src[:ls_abs_start] + LISTENERS_REPLACEMENT + src[tail_start:]

out_path.write_text(src, encoding="utf-8")
PY
    rm -f "${GENERATED_CONFIG}.raw"
    echo "[integration-up] generated $(wc -l < "${GENERATED_CONFIG}") line config"
else
    echo "[integration-up] reusing existing ${GENERATED_CONFIG} (set REGENERATE_CONFIG=1 to refresh)"
fi

# ─────────────────────────────────────────────────────────────────────
# Step 3: bring the stack up. `--wait` returns once every healthcheck
# transitions to healthy or budget expires; failures dump logs.
# ─────────────────────────────────────────────────────────────────────
COAUTH_IMAGE="${COAUTH_IMAGE_REF}" \
    docker compose -f "${COMPOSE_FILE}" "${profile_args[@]}" up -d --wait || {
        echo "[integration-up] compose up failed; dumping recent logs" >&2
        docker compose -f "${COMPOSE_FILE}" "${profile_args[@]}" logs --tail=100 >&2 || true
        exit 3
    }

echo "[integration-up] stack is up. Endpoints:"
echo "  coauth   http://127.0.0.1:57080/health"
if [[ " $* " == *" --with-downstream "* ]]; then
    echo "  coland   http://127.0.0.1:58008/health"
    echo "  codmin   http://127.0.0.1:59090/health"
fi
echo
echo "Run ./scripts/integration-smoke.sh to verify each /health returns 200."
