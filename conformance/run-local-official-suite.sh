#!/usr/bin/env bash
# Local HTTPS Coauth, real static clients, and the official Java/Mongo API.
set -euo pipefail

: "${DATABASE_URL:?a dedicated migrated-or-empty test database is required}"
: "${COAUTH_CONFORMANCE_SOURCE:?the pinned official suite checkout is required}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_dir=$(mktemp -d)
target_dir=$(cargo metadata --locked --format-version 1 --no-deps --manifest-path "${repo_root}/Cargo.toml" | jq -er .target_directory)
results_dir="${COAUTH_CONFORMANCE_RESULTS:-${target_dir}/conformance-results}"
mkdir -p "$results_dir"
coauth_pid=""
suite_pid=""
proxy_name="coauth-oidc-proxy-${GITHUB_RUN_ID:-$$}"
cleanup() {
    for pid in "$coauth_pid" "$suite_pid"; do
        if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
    done
    docker rm -f "$proxy_name" >/dev/null 2>&1 || true
    # Configuration, wrapping keys and TLS keys never become CI artifacts.
    rm -rf "$run_dir"
}
trap cleanup EXIT
binary="${COAUTH_BINARY:-${target_dir}/debug/coauth}"
"$binary" config generate > "$run_dir/generated.yaml"
python3 "${repo_root}/conformance/prepare-local-config.py" "$run_dir/generated.yaml" "$run_dir"
if [[ -n "${COAUTH_CONFORMANCE_FULL_PLANS_JSON:-}" ]]; then
    export COAUTH_CONFORMANCE_FULL_PLAN_DIR="$run_dir/full-plans"
fi
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
"$binary" server --first-provisioning --config "$run_dir/coauth.yaml" \
    > "$results_dir/coauth-server.log" 2>&1 &
coauth_pid=$!
java -Xmx2g -Djavax.net.ssl.trustStore="$run_dir/truststore" \
    -Djavax.net.ssl.trustStorePassword=changeit \
    -jar "${COAUTH_CONFORMANCE_SOURCE}/target/fapi-test-suite.jar" \
    --server.port=8081 --fintechlabs.devmode=true \
    --fintechlabs.base_url=https://localhost:8446 \
    --spring.mongodb.uri="${COAUTH_CONFORMANCE_MONGO_URI:-mongodb://localhost:27017/coauth_conformance}" \
    > "$results_dir/official-server.log" 2>&1 &
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
export RESULTS_DIR="$results_dir"
export COAUTH_SKIP_BOOT=1 COAUTH_RUN_FULL_CONFORMANCE=1
export COAUTH_CONFORMANCE_ISSUER=https://localhost:8445
export COAUTH_CONFORMANCE_DISCOVERY_CONFIG="$run_dir/discovery.json"
export CONFORMANCE_SERVER=https://localhost:8446/ CONFORMANCE_DEV_MODE=1
bash "${repo_root}/scripts/oidc-conformance.sh" --plan "${CONFORMANCE_PLAN:-all}"
