# coauth — development task runner
# Usage: just <recipe>
# See all recipes: just --list

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

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
    cargo run -p coauth --features cedar -- server -c config.dev.yaml

# Stop dev services (PostgreSQL)
dev-down:
    docker compose -f .devcontainer/docker-compose.yml down

# Generate a dev config pointing to the local Docker PostgreSQL
config-dev-generate:
    cargo run -p coauth -- config generate > config.dev.yaml.tmp
    sed -i 's|uri: postgresql://|uri: postgresql://coauth:coauth@localhost/coauth|' config.dev.yaml.tmp
    mv config.dev.yaml.tmp config.dev.yaml
    @echo "Created config.dev.yaml"

# Start the backend server (auto-migrates DB)
backend *ARGS: frontend-assets
    if (!(Test-Path config.dev.yaml)) { just config-dev-generate }
    cargo run -p coauth --features cedar -- server -c config.dev.yaml {{ARGS}}

# Start the backend with a config file
backend-config config="config.yaml":
    cargo run -p coauth --features cedar -- server -c {{config}}

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

# Build backend-served frontend assets from the current source tree
frontend-assets:
    just frontend-build

# ── Build ────────────────────────────────────────────────────

# Build the backend in release mode
build:
    cargo build --release -p coauth

# Build everything (backend + frontend)
build-all:
    just frontend-build
    cargo build --release -p coauth

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

# Generate a default configuration file
config-generate:
    cargo run -p coauth -- config generate

# Clean all build artifacts
clean:
    cargo clean
