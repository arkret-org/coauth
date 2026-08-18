#!/bin/sh
set -eu

BASE_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
CONFIG_SCHEMA="${BASE_DIR}/docs/config.schema.json"
POLICIES_SCHEMA="${BASE_DIR}/policies/schema/"

set -x
mkdir -p "${POLICIES_SCHEMA}"
cargo run -q -p coauth-config --bin schema > "${CONFIG_SCHEMA}"
OUT_DIR="${POLICIES_SCHEMA}" cargo run -q -p coauth-policy --bin schema
