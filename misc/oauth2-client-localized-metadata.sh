#!/bin/sh
# OAuth 2.0 client localised metadata management helper for Pasion.
#
# Usage:
#   ./oauth2-client-localized-metadata.sh get  <admin-url> <admin-token> <client-id>
#   ./oauth2-client-localized-metadata.sh put  <admin-url> <admin-token> <client-id> <payload-file>
#
# Example:
#   # Set Japanese and German variants for client 01H...:
#   cat > payload.json <<EOF
#   {
#     "client_name": {
#       "ja": "テストクライアント",
#       "de": "Testklient"
#     },
#     "logo_uri": {
#       "ja": "https://example.com/logo-ja.png"
#     }
#   }
#   EOF
#   ./oauth2-client-localized-metadata.sh put \
#     https://auth.example.com 'urn:coauth:admin:...' 01H... payload.json
#
# This wraps T08b's `GET / PUT /api/admin/v1/oauth2-clients/{id}/localized-metadata`
# endpoint so operators can manage localised client metadata without a UI.
# The Dioxus admin SPA editor (T08c) will eventually replace this script.

set -eu

die() { echo "error: $*" >&2; exit 1; }

usage() {
    cat >&2 <<'EOF'
usage:
  oauth2-client-localized-metadata.sh get  <admin-url> <admin-token> <client-id>
  oauth2-client-localized-metadata.sh put  <admin-url> <admin-token> <client-id> <payload-file>
EOF
    exit 1
}

[ "$#" -ge 4 ] || usage

cmd="$1"
admin_url="${2%/}"
admin_token="$3"
client_id="$4"

endpoint="${admin_url}/api/admin/v1/oauth2-clients/${client_id}/localized-metadata"

case "$cmd" in
    get)
        curl -sS --fail-with-body \
            -H "Accept: application/json" \
            -H "Authorization: Bearer ${admin_token}" \
            "$endpoint"
        ;;

    put)
        [ "$#" -eq 5 ] || usage
        payload_file="$5"
        [ -r "$payload_file" ] || die "payload file not readable: $payload_file"

        curl -sS --fail-with-body \
            -X PUT \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -H "Authorization: Bearer ${admin_token}" \
            --data-binary "@${payload_file}" \
            "$endpoint"
        ;;

    *)
        die "unknown command: $cmd"
        ;;
esac

echo
