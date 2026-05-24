# Changelog

All notable changes to `coauth` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release artefacts (container images, signed binaries, draft GitHub
releases) are produced by `.github/workflows/release.yaml`. See
[`docs/en/development/releasing.md`](docs/en/development/releasing.md)
for the full release process.

## [Unreleased]

### Round R4 — protocol review closures (2026-05-20, contrix-spec `2a4d39b..a77b995`)

Closes 8 protocol-review commits on the auth / identity / policy surfaces.
See [`../_todos.md`](../_todos.md) for the workstream context.

- **BREAKING** 3PID OOB invite split into two wire modes (`offline_token`
  vs `lookup`), with all plaintext 3PID values removed from the wire. The
  `offline_token` form carries `token_commitment` (sha256) + `token_salt_id`
  + `token_entropy_bits ≥ 128`; the `lookup` form carries
  `lookup_table_ref` + `pepper_id` with 3-strike invalidation. Token salt
  and lookup pepper are zeroized within 24h of any of 5 terminal states
  (`claimed` / `send_failed` / `revoked_by_capability_loss` /
  `revoked_by_inviter_left` / `invalidated_by_rate_limit`).
- **Added** invite-claim flow now produces `binding_proof{verification_service_did,
  verification_method, subject_did, realm_id, audience, claim_nonce,
  expires_at, signature}` and `subject_proof`. Full verifier chain is a
  `TODO(round4)`; wire-shape lands now.
- **BREAKING** `cx.cross_signing.publish` CAS: publisher must read the
  current generation and submit `expected_previous_generation`; post-reset
  generation steps are strictly `+1`.
- **BREAKING** `/policy/check` v2 — request switches to `PolicyCheckRequest`
  (`signed_transport`, `source_ip_digest`, `source.{service_did,
  service_type}`). Response is `PolicyCheckResponse` carrying
  `bound_to{realm_id, actor, action, request_canonical_digest,
  policy_server_id}` + `auth_state_digest` + `policy_frontier_digest` +
  `membership_frontier_digest` + signature (`kid: did:.+#.+`). Full signing
  transcript is a `TODO(round4)`; binding fields land now.
- **BREAKING** identity_link encrypted payload is now Realm-scoped: bound
  to `realm_id` + `trust_domain`.
- **Added** `trust_domain` injected into the `ServiceDescribe` /
  Realm-policy publish path via soland's config API.
- **Added** DID method-name regex sweep tightened to
  `^did:[a-z0-9]+:[^\s]+$` across coauth's DID parsers and fixtures.

### Added — Round R2/R3 (2026-05-20, spec 8b7978d)

- **3PID OOB code generation** (`backend::services::oob_code`,
  T15). Two configurable code forms:
  - `OobCodeKind::OfflineVerifiable` (default) — 27-char restricted
    base32 (excludes `I`, `L`, `0`, `1`, `O`), ≥128-bit entropy,
    offline-verifiable.
  - `OobCodeKind::Lookup` — 6-char human-typeable code paired with a
    server-side HMAC-SHA256 pepper, `oob_code_kind="lookup"` advertised
    on the wire, and 3-strike invalidation (see `LookupStrikes`).
  - Helper `generate_oob_code(kind)` mints either form.
- **7-trigger non-enumerable failure state machine for OOB invites**
  (`backend::services::oob_invite_state`, T15). All seven triggers
  (`expired`, `send_failed`, `capability_loss`, `inviter_left`,
  `revoked`, `claim_success`, `rate_limit_invalidated`) surface as
  the byte-identical wire body `{"error":"not_found"}` with constant-
  time padding to ≤50 ms. The `Expired` trigger's internal reason code
  joins the SDK error catalog as `expired_invite_token` (re-exported
  from `contrix_core::error::ERROR_CODE_EXPIRED_INVITE_TOKEN`).
- **Deployment `trust_domain` config** (`ContrixConfig::trust_domain`,
  T08). Optional `cx:trust_domain:<scope>` value validated against the
  SDK `TypedTrustDomainId` rules (scope `[a-z0-9._:-]{1,128}`,
  lowercase-leading). The value is propagated into Realm policy and
  server-describe via soland's config API. **Changing `trust_domain`
  invalidates every existing `cx.cross_signing.reset` proof** because
  the trust domain enters the proof's canonical transcript; operators
  MUST rotate device-quorum / recovery-unlock proofs in tandem with
  the rotation. See the README "Trust domain rotation" note for the
  full migration procedure.
- **Cross-account consent revoke `scope=any` cascade**
  (`handlers::account::mimi_consent::cascade_any_revoke`, T17). When a
  holder revokes consent with `scope=any`, coauth now emits the
  primary `(peer, scope=any)` revoke plus one `or_set_remove` per
  pre-existing subscope tag, each marked
  `superseded_by_any_revoke`. A stubbed broadcast helper
  (`broadcast_cache_invalidation_for_any_revoke`) is wired in for the
  teabay / floria cache-invalidation channel; the channel itself is
  not yet implemented (tracked under `TODO(round23-T17)`).

### Changed

- Realm/Space terminology inversion (wire-breaking): old `Space` (security
  boundary) → **Realm**, old `Place` (container) → **Space**. Session
  grants, capabilities, and admin scopes now key on `realm_id`; legacy
  `space_id` remains accepted as a serde alias for back-compat clients.

### Security

- Anti-enumeration timing equivalence on the password-login path. When
  the supplied identifier does not match an account, or the matched
  account has no active password (e.g. SSO-only), `login_with_password`
  now runs a dummy verify with the supplied password through the
  current hashing scheme (`PasswordManager::dummy_verify`). This makes
  response latency for `InvalidCredentials` independent of whether the
  account exists, blocking the username/email enumeration oracle.
- CAPTCHA verification is now reachable from every abuse-sensitive
  REST surface. New `handlers::captcha::verify_token` helper dispatches
  a single string token to the configured provider's `siteverify`
  endpoint (reCAPTCHA v2, hCaptcha, Cloudflare Turnstile) and is
  fail-closed when a token is supplied without `site.captcha` being
  configured. Wired into:
  - `POST /api/v1/auth/login` — `LoginRequest.captcha_token` is
    verified before credentials are checked when `site.captcha` is set.
  - `POST /api/v1/auth/register` — `RegisterInput.captcha_token` is
    verified before policy / availability checks.
  - `POST /api/v1/auth/recovery/start` — `StartRecoveryInput.captcha_token`
    is verified before a rate-limited recovery session is allocated.
  - `POST /api/admin/v1/accounts/{id}/dids` and
    `DELETE /api/admin/v1/accounts/{id}/dids/{binding_id}` —
    `AddAccountDidBindingRequest.captcha_token` /
    `RemoveAccountDidBindingRequest.captcha_token` are verified after
    the DID-binding rate limit. The underlying handlers still return
    `501 Not Implemented`, so the gate is dormant until the binding
    write logic lands.
- Flow-engine CAPTCHA verification (`POST /api/v1/flow/.../respond`)
  no longer hardcodes `site_hostname = "localhost"` and now threads
  the requester IP through `remote_ip`. The hostname mismatch check
  was effectively disabled before, so deployments with a CAPTCHA stage
  could accept tokens issued for any hostname.

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
- Postgres advisory-lock label renamed to `"coauth config sync"`.
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
  `github.com/contrix-dev/coauth` and `ghcr.io/contrix-dev/coauth`.
- User-visible legacy product strings in CLI help, library doc-comments, and
  contributor / architecture docs replaced with `coauth`.

[Unreleased]: https://github.com/contrix-dev/coauth/compare/v1.8.0...HEAD
