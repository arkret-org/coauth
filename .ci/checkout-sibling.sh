#!/usr/bin/env bash
set -euo pipefail

repo="${1:?repo name is required}"
dest="${2:?destination path is required}"
ref="${3:-main}"

server="${GITHUB_SERVER_URL:-https://github.com}"
owner="${GITHUB_REPOSITORY_OWNER:-${GITHUB_REPOSITORY%/*}}"
token="${CI_REPO_TOKEN:-}"

if [ -z "$token" ]; then
  echo "::error::CI_REPO_TOKEN is required to clone private sibling repository ${owner}/${repo}" >&2
  exit 1
fi

rm -rf "$dest"
auth="$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')"
git -c "http.${server}/.extraheader=AUTHORIZATION: basic ${auth}" \
  clone --depth 1 --branch "$ref" "${server}/${owner}/${repo}.git" "$dest"
