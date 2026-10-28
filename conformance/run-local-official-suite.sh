#!/usr/bin/env bash
# Local HTTPS Coauth, real static clients, and the official Java/Mongo API.
set -euo pipefail

: "${DATABASE_URL:?a dedicated migrated-or-empty test database is required}"
: "${COAUTH_CONFORMANCE_SOURCE:?the pinned official suite checkout is required}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
suite_source_ref=$(git -C "$COAUTH_CONFORMANCE_SOURCE" rev-parse HEAD)
run_dir=$(mktemp -d)
target_dir=$(cargo metadata --locked --format-version 1 --no-deps --manifest-path "${repo_root}/Cargo.toml" | jq -er .target_directory)
results_dir="${COAUTH_CONFORMANCE_RESULTS:-${target_dir}/conformance-results}"
private_results_dir="$run_dir/official-results"
mkdir -p "$results_dir" "$private_results_dir"
coauth_pid=""
suite_pid=""
proxy_name="coauth-oidc-proxy-${GITHUB_RUN_ID:-$$}"
cleanup() {
    local incoming_status=$?
    set +e
    python3 "${repo_root}/conformance/publish-evidence.py" \
        --archives "$private_results_dir" \
        --junit "${COAUTH_CONFORMANCE_SOURCE}/target/surefire-reports" \
        --source-ref "$suite_source_ref" \
        --output "$results_dir"
    local evidence_status=$?
    for pid in "$coauth_pid" "$suite_pid"; do
        if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
    done
    docker rm -f "$proxy_name" >/dev/null 2>&1 || true
    # Configuration, wrapping keys and TLS keys never become CI artifacts.
    rm -rf "$run_dir"
    if [[ "$incoming_status" == 0 && "$evidence_status" != 0 ]]; then
        exit "$evidence_status"
    fi
    exit "$incoming_status"
}
trap cleanup EXIT
binary="${COAUTH_BINARY:-${target_dir}/debug/coauth}"
export COAUTH_CONFORMANCE_ASSETS="${COAUTH_CONFORMANCE_ASSETS:-${target_dir}/dx/coauth-frontend/release/web/public}"
test -f "$COAUTH_CONFORMANCE_ASSETS/index.html"
"$binary" config generate > "$run_dir/generated.yaml"
python3 "${repo_root}/conformance/prepare-local-config.py" "$run_dir/generated.yaml" "$run_dir"
export COAUTH_CONFORMANCE_FULL_PLAN_DIR="$run_dir/full-plans"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$run_dir/tls.key" \
    -out "$run_dir/tls.crt" -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
    > /dev/null 2>&1
keytool -importcert -noprompt -alias coauth-local-conformance \
    -file "$run_dir/tls.crt" -keystore "$run_dir/truststore" -storepass changeit > /dev/null
cat > "$run_dir/nginx.conf" <<EOF
events {}
http {
    server {
        listen 8445 ssl;
        ssl_certificate /fixture/tls.crt;
        ssl_certificate_key /fixture/tls.key;
        location / {
            proxy_pass http://127.0.0.1:7080;
            proxy_set_header Host localhost:8445;
            proxy_set_header X-Forwarded-Proto https;
        }
    }
    server {
        listen 8446 ssl;
        ssl_certificate /fixture/tls.crt;
        ssl_certificate_key /fixture/tls.key;
        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Host localhost:8446;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host localhost:8446;
            proxy_set_header X-Forwarded-Port 8446;
        }
    }
}
EOF
docker run --detach --name "$proxy_name" --network host \
    --mount "type=bind,source=$run_dir,target=/fixture,readonly" \
    --mount "type=bind,source=$run_dir/nginx.conf,target=/etc/nginx/nginx.conf,readonly" \
    nginx:1.28-alpine > /dev/null
SSL_CERT_FILE="$run_dir/tls.crt" "$binary" server --first-provisioning --config "$run_dir/coauth.yaml" \
    > "$private_results_dir/coauth-server.log" 2>&1 &
coauth_pid=$!
java -Xmx2g -Djavax.net.ssl.trustStore="$run_dir/truststore" \
    -Djavax.net.ssl.trustStorePassword=changeit \
    -jar "${COAUTH_CONFORMANCE_SOURCE}/target/fapi-test-suite.jar" \
    --server.port=8081 --fintechlabs.devmode=true \
    --fintechlabs.base_url=https://localhost:8446 \
    --spring.mongodb.uri="${COAUTH_CONFORMANCE_MONGO_URI:-mongodb://localhost:27017/coauth_conformance}" \
    > "$private_results_dir/official-server.log" 2>&1 &
suite_pid=$!
export CURL_CA_BUNDLE="$run_dir/tls.crt"
for endpoint in https://localhost:8445/health https://localhost:8446/api/runner/available; do
    ready=0
    for _ in {1..180}; do
        kill -0 "$coauth_pid"
        kill -0 "$suite_pid"
        if curl -fsS "$endpoint" >/dev/null 2>&1; then ready=1; break; fi
        sleep 1
    done
    if [[ "$ready" != 1 ]]; then echo "::error::Service unavailable: $endpoint" >&2; exit 2; fi
done
# Register a genuine local user through the product CLI after provisioning.
# Keep argv construction and all command output out of public CI evidence.
python3 - "$binary" "$run_dir" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
binary, directory = sys.argv[1:]
directory = Path(directory)
user = json.loads((directory / "browser-user.json").read_text())
with (directory / "register-user-private.log").open("w") as log:
    result = subprocess.run([binary, "--config", str(directory / "coauth.yaml"), "manage", "register-user", user["handle"], "--password", user["password"], "--yes", "--no-admin"], stdout=log, stderr=subprocess.STDOUT)
if result.returncode:
    raise SystemExit("Could not register the isolated conformance account")
PY
export COAUTH_CONFORMANCE_BROWSER_USER="$run_dir/browser-user.json"
export RESULTS_DIR="$private_results_dir"
export COAUTH_SKIP_BOOT=1 COAUTH_RUN_FULL_CONFORMANCE=1
export COAUTH_CONFORMANCE_ISSUER=https://localhost:8445
export COAUTH_CONFORMANCE_DISCOVERY_CONFIG="$run_dir/discovery.json"
export CONFORMANCE_SERVER=https://localhost:8446/ CONFORMANCE_DEV_MODE=1
bash "${repo_root}/scripts/oidc-conformance.sh" --plan "${CONFORMANCE_PLAN:-all}"
