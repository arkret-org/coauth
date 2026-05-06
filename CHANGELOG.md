# Changelog

All notable changes to `coauth` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release artefacts (container images, signed binaries, draft GitHub
releases) are produced by `.github/workflows/release.yaml`. See
[`docs/en/development/releasing.md`](docs/en/development/releasing.md)
for the full release process.

## [Unreleased]

### Added

- `_todos.md` consolidates the remaining Contrix migration work and
  hygiene items.
- `Dockerfile` `HEALTHCHECK` smoke-tests the binary on each pull; real
  liveness probes should target `/health` on the internal listener.
- This `CHANGELOG.md` scaffold.
- Default response-security headers middleware:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin`,
  `Cross-Origin-Opener-Policy: same-origin`.
- New deployment docs: `docs/en/setup/docker.md` (+ zh mirror) with a
  runnable `docker-compose.yaml`, Kubernetes probes, and Cosign
  verification example. Sample systemd unit at
  `misc/systemd/coauth.service` referenced from `running.md`.
- New operations docs: `docs/en/operations/backup-restore.md` and
  `docs/en/operations/upgrades.md` (+ zh mirrors).
- `COAUTH_CONFIG` / `COAUTH_*` environment variables are now honoured
  for configuration overrides. `PASION_CONFIG` / `PASION_*` remain
  accepted as a deprecation fallback; when both are set, `COAUTH_*`
  wins.
- Configurable HTTP request limits on `HttpConfig`:
  - `http.max_body_bytes` (default 1 MiB) wired into Salvo's
    `SecureMaxSize` middleware.
  - `http.request_timeout_seconds` (default 30 s) enforced by a new
    `RequestTimeout` middleware that surfaces a `503 Service
    Unavailable` on expiry. Set to `0` to disable.
  - `http.shutdown_grace_seconds` (default 30 s) plumbed into
    `LifecycleManager::with_timeout`, replacing the prior hardcoded
    60-second soft-shutdown grace.
- Opt-in HSTS (`http.hsts.max_age_seconds`,
  `http.hsts.include_subdomains`, `http.hsts.preload`); off by default
  because TLS commonly terminates upstream and HSTS has long-lived
  cache semantics.
- DID-binding rate limit (`config.rate_limiting.did_binding.per_ip` /
  `per_account`, default 5/min per source IP and 3/5min per target
  account) enforced for the admin
  `add_account_did` / `remove_account_did` endpoints.
- `coauth healthcheck` sub-command issues an HTTP probe against the
  internal `/health` listener and is now what the `Dockerfile`
  `HEALTHCHECK` runs, so it exercises the running server, not just
  the binary.
- TLS server config explicitly pins the protocol-version floor to TLS
  1.2 (TLS 1.3 preferred), making the policy reviewable instead of
  relying on rustls defaults.
- Daily scheduled `cargo-deny` advisory sweep in CI
  (`schedule: cron '37 5 * * *'`) so newly disclosed CVEs surface
  even without pushes.
- Container-image signing scope documented in
  `docs/en/development/releasing.md` (Cosign signs `v*` tags and
  `main` only) with a `cosign verify` snippet for operators.
- `_todos.md` notes the rolling-upgrade hazard around the Postgres
  advisory-lock label `"Pasion config sync"` (intentionally not
  renamed).
- Bearer-token authentication enforced on the Contrix session-grant
  admin surface (`/api/v1/session-grants`,
  `/api/v1/session-grants/introspect`,
  `/api/v1/session-grants/{id}/revoke`). Read paths accept admin
  scopes or `urn:contrix:principal-server:session.bind`; revocation
  requires an admin scope. Implemented in
  `crates/backend/src/handlers/contrix.rs::require_session_grant_caller`.

### Audited

- Notification dispatch and queue worker logs verified: no OTP codes,
  recovery tokens, or password material are emitted; only Ulid
  identifiers and destination email/phone (which already live in the
  database row being processed) appear in log fields.

### Fixed

- `cargo check --workspace` now compiles cleanly. Six clusters of
  pre-existing compile errors fixed:
  - Salvo `#[handler]` macro rejected destructured `JsonBody(body)`
    parameters in `recovery.rs`; switched to `req: &mut Request` +
    `parse_json`.
  - `Depot::get(...).cloned().ok_or_else(...)` in `auth.rs` (the call
    returns `Result`, not `Option`); switched to `.map_err(...)`.
  - Missing `Resource` impl on `AccountRiskActionCurrentResponse`.
  - Missing `From<RepositoryError>` for `ContrixRouteError`.
  - Missing `derive(ToSchema)` on `AuthBridge*` and
    `IntegrationManifest*` response types.
  - Partially-moved `user` borrow in `AccountRecord::from_user`.
- `.github/workflows/ci.yaml` clippy job now pins
  `dtolnay/rust-toolchain@1.93.0` to match the `Dockerfile` builder.
- Repository URLs / container registry references unified under
  `github.com/contrix-dev/coauth` and `ghcr.io/contrix-dev/coauth`
  (previously a mix of `palpo-im`, `taidge`, `meldry-com`).
- User-visible `Pasion` strings in CLI help, library doc-comments, and
  contributor / architecture docs replaced with `coauth`. (Internal
  identifiers that affect runtime state — e.g. the Postgres advisory
  lock label — are kept for backwards compatibility and tracked in
  `_todos.md`.)

[Unreleased]: https://github.com/contrix-dev/coauth/compare/v1.8.0...HEAD
