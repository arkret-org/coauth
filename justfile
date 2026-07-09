# coauth — development task runner
# Usage: just <recipe>
# See all recipes: just --list

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Stable local device-enrollment-authority seed (decision 0002, B model).
# Without a fixed seed coauth generates a random enrollment key every start, so
# every restart orphans the `CokretDeviceEnrollmentAuthority` did:key already
# pinned into existing principals' DID documents (device enrollment then fails
# `device_enrollment_authority_not_designated`). This is a DEV-ONLY key; set a
# real secret seed in production.
export COAUTH_DEVICE_ENROLLMENT_KEY_SEED := "wgGYluck4bZVA5oa9khVpSriHgrcV81H4iPu6rqtRRY="

# Dev-only escape hatch for the registration email-delivery bypass.
# config.dev.yaml enables `account.registration_email_delivery_bypass_allowed`
# (in-band verification code, no SMTP) so local dev needs no mail server. The
# config validator fails closed unless this variable is also set, so a
# mis-configured production deployment refuses to start. NEVER set in production.
export COAUTH_ALLOW_INSECURE_DEV_EMAIL_BYPASS := "1"

# Dev-only SSRF egress allowlist for the loopback-fronted local hosts.
# COA-SEC-01 made outbound private/loopback egress deny-by-default in ALL
# builds (debug no longer auto-allows via `cfg!(debug_assertions)`). Local dev
# fronts coauth and soland behind Caddy at `auth.local.host` / `local.host`,
# both resolving to 127.0.0.1. The OIDC session-grant exchange has coauth fetch
# its own issuer discovery doc (`https://auth.local.host/.well-known/...`) and
# call soland (`https://local.host/...`); without this allowlist those self
# calls are blocked at the resolver and the exchange fails closed with a 409
# `invalid_discovery_binding`. Scoped to the two dev hosts so SSRF protection
# stays on for every other target. NEVER set in production.
export COAUTH_OUTBOUND_HTTP_PRIVATE_ALLOWLIST := "auth.local.host,local.host"

# Dev-only coauth service DID. Production deployments must configure a real
# did:webvh service DID in their config file; this keeps `just dev` aligned with
# the fail-closed config validator even when config.dev.yaml is regenerated.
export COAUTH_COKRET__SERVICE_DID := "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:auth.local.host:webvh:service"

# Default recipe: show available commands
default:
    @just --list

# ── Development ──────────────────────────────────────────────

# One-click: start PostgreSQL + backend with dev config
dev: frontend-assets
    # docker compose -f .devcontainer/compose.yml up -d postgres
    # @echo "Waiting for PostgreSQL..."
    # @until docker compose -f .devcontainer/compose.yml exec -T postgres pg_isready -U coauth > /dev/null 2>&1; do sleep 1; done
    # @if [ ! -f config.dev.yaml ]; then just config-dev-generate; fi
    cargo run -p coauth --features cedar,password-bootstrap -- server -c config.dev.yaml

# Stop dev services (PostgreSQL)
dev-down:
    docker compose -f .devcontainer/docker-compose.yml down

# Generate a dev config pointing to the local Docker PostgreSQL
config-dev-generate:
    cargo run -p coauth -- config generate --dev -o config.dev.yaml.tmp
    mv config.dev.yaml.tmp config.dev.yaml
    @echo "Created config.dev.yaml"

# Start the backend server (auto-migrates DB)
backend *ARGS: frontend-assets
    if (!(Test-Path config.dev.yaml)) { just config-dev-generate }
    cargo run -p coauth --features cedar,password-bootstrap -- server -c config.dev.yaml {{ARGS}}

# Start the backend with a config file
backend-config config="config.yaml":
    cargo run -p coauth --features cedar,password-bootstrap -- server -c {{config}}

# Start the frontend dev server (Dioxus hot-reload)
frontend:
    dx serve -p coauth-frontend --port 8182

# Start the frontend in hot-reload mode
frontend-hot:
    dx serve -p coauth-frontend --hot-reload

# Build the frontend for production (output → dist/)
frontend-build:
    dx build -p coauth-frontend --release
    {{ if os() == "windows" { "if (Test-Path dist) { Remove-Item -Recurse -Force dist }; Copy-Item -Recurse target/dx/coauth-frontend/release/web/public dist" } else { "rm -rf dist && cp -r target/dx/coauth-frontend/release/web/public dist" } }}

# Build backend-served frontend assets from the current source tree.
# Uses a debug build on purpose: `dx build --release` always invokes wasm-opt,
# whose bundled binaryen binary crashes on Windows (exit 0xc0000409) and prints
# a scary ERROR during `just dev`/`just backend`. Debug builds skip wasm-opt
# entirely and are perfectly fine for locally serving the dev frontend.
frontend-assets:
    dx build -p coauth-frontend
    {{ if os() == "windows" { "if (Test-Path dist) { Remove-Item -Recurse -Force dist }; Copy-Item -Recurse target/dx/coauth-frontend/debug/web/public dist" } else { "rm -rf dist && cp -r target/dx/coauth-frontend/debug/web/public dist" } }}

# ── Build ────────────────────────────────────────────────────

# Build the backend in release mode
build:
    cargo build --release -p coauth --features cedar,password-bootstrap

# Build everything (backend + frontend)
build-all:
    just frontend-build
    cargo build --release -p coauth --features cedar,password-bootstrap

# Check the entire workspace for errors
check:
    cargo check --workspace

# Run clippy on the entire workspace
lint:
    cargo clippy --workspace -- -D warnings

# Format all Rust code
fmt:
    cargo fmt --all

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# ── Database ─────────────────────────────────────────────────

# Run database migrations
db-migrate *ARGS:
    cargo run -p coauth -- database migrate {{ARGS}}

# Generate config, check, or sync
config *ARGS:
    cargo run -p coauth -- config {{ARGS}}

# ── User Management ─────────────────────────────────────────

# Register a new user
register-user *ARGS:
    cargo run -p coauth -- manage register-user {{ARGS}}

# Set or reset a user's password
set-password *ARGS:
    cargo run -p coauth -- manage set-password {{ARGS}}

# Promote a user to admin
promote-user *ARGS:
    cargo run -p coauth -- manage promote-user {{ARGS}}

# ── Testing ──────────────────────────────────────────────────

# Run all tests
test:
    cargo test --workspace

# Run tests for a specific crate
test-crate crate:
    cargo test -p {{crate}}

# ── Documentation ────────────────────────────────────────────

# Build the English documentation (mdBook)
docs-en:
    mdbook build -d ../target/docs/en

# Build the Chinese documentation (mdBook)
docs-zh:
    mdbook build -d ../target/docs/zh book-zh.toml

# ── Utilities ────────────────────────────────────────────────

# Run the doctor diagnostic tool
doctor *ARGS:
    cargo run -p coauth -- doctor {{ARGS}}

# Generate a configuration file
config-generate *ARGS:
    cargo run -p coauth -- config generate {{ARGS}}

# Clean all build artifacts
clean:
    cargo clean
