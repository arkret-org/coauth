#!/bin/sh
# Device Authorization Grant (RFC 8628) test helper for Pasion
#
# Usage: ./device-code-grant.sh <server-url> [scope ...]
#
# This script performs the full device authorization grant flow:
#   1. Discovers OIDC metadata from the server
#   2. Dynamically registers a client
#   3. Initiates device authorization
#   4. Polls for the user to complete authorization

set -eu

die() { echo "error: $*" >&2; exit 1; }

http() {
  local method="$1" url="$2"
  shift 2
  printf "[%s] %s\n" "$method" "$url" >&2
  curl -sS --fail-with-body \
    -X "$method" \
    -H "Accept: application/json" \
    "$@" "$url"
}

# ── Argument parsing ──────────────────────────────────────────────
[ "$#" -ge 1 ] || die "usage: $0 <server-url> [scope ...]"

server="${1%/}"
shift

scope="${*:-urn:matrix:org.matrix.msc2967.client:api:*}"

# ── Step 1: OIDC Discovery ───────────────────────────────────────
echo "==> Discovering OIDC metadata"
meta=$(http GET "${server}/_matrix/client/unstable/org.matrix.msc2965/auth_metadata")

device_authz_ep=$(printf '%s' "$meta" | jq -r '.device_authorization_endpoint')
token_ep=$(printf '%s' "$meta" | jq -r '.token_endpoint')
registration_ep=$(printf '%s' "$meta" | jq -r '.registration_endpoint')

[ "$device_authz_ep" != "null" ] || die "server does not advertise device_authorization_endpoint"
[ "$token_ep" != "null" ]        || die "server does not advertise token_endpoint"
[ "$registration_ep" != "null" ] || die "server does not advertise registration_endpoint"

# ── Step 2: Dynamic client registration (RFC 7591) ───────────────
echo "==> Registering client"
reg=$(http POST "$registration_ep" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "coauth-device-grant-test",
    "client_uri": "https://github.com/contrix-dev/coauth",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "application_type": "native",
    "token_endpoint_auth_method": "none"
  }')

client_id=$(printf '%s' "$reg" | jq -r '.client_id')
[ "$client_id" != "null" ] || die "client registration failed"

# ── Step 3: Device authorization request ──────────────────────────
echo "==> Requesting device authorization"
device=$(http POST "$device_authz_ep" \
  --data-urlencode "client_id=${client_id}" \
  --data-urlencode "scope=${scope}")

user_code=$(printf '%s' "$device" | jq -r '.user_code')
verification_uri=$(printf '%s' "$device" | jq -r '.verification_uri')
verification_uri_complete=$(printf '%s' "$device" | jq -r '.verification_uri_complete')
device_code=$(printf '%s' "$device" | jq -r '.device_code')
interval=$(printf '%s' "$device" | jq -r '.interval // 5')

cat <<SUMMARY

────────────────────────────────────────
  Server:           ${server}
  Client ID:        ${client_id}
  Scope:            ${scope}
  User Code:        ${user_code}
────────────────────────────────────────

Open this URL in your browser:
  ${verification_uri_complete}

Or go to ${verification_uri} and enter code: ${user_code}

SUMMARY

# Show QR code if qrencode is available
if command -v qrencode > /dev/null 2>&1; then
  printf '%s' "$verification_uri_complete" | qrencode -t ANSI256UTF8
  echo
fi

# ── Step 4: Poll for token (RFC 8628 §3.4-3.5) ──────────────────
echo "==> Waiting for user authorization..."
while true; do
  resp=$(http POST "$token_ep" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "device_code=${device_code}" \
    --data-urlencode "client_id=${client_id}" 2>/dev/null || true)

  err=$(printf '%s' "$resp" | jq -r '.error // empty')

  case "$err" in
    authorization_pending)
      printf "  …still waiting (poll every %ss)\n" "$interval"
      sleep "$interval"
      ;;
    slow_down)
      interval=$((interval + 5))
      printf "  …server asked to slow down (new interval: %ss)\n" "$interval"
      sleep "$interval"
      ;;
    "")
      echo "==> Token response:"
      printf '%s' "$resp" | jq .
      break
      ;;
    *)
      echo "==> Error: $err"
      printf '%s' "$resp" | jq .
      exit 1
      ;;
  esac
done
