# coauth Active TODO

> Updated: 2026-05-06
> Scope: Contrix Auth / Account Server. Remaining work after the
> Contrix migration sweep. Items kept here are still open; completed items
> have been pruned.

## 0. Boundary recap

- `coauth` proves who logged in to which local account / device / session,
  and exposes that to Principal Servers (`soland`) and admin tooling
  (`sodmin`). It is **not** a DID Registry — DID documents, key logs and
  registry receipts live in delegated/public DID resolver services.
- Matrix / Palpo support is a legacy compatibility adapter, not the
  primary path.

---

## P0: Branch compiles ✅

`cargo check --workspace` is now clean. Specific fixes applied in this
changeset:

- [x] `crates/backend/src/handlers/account/recovery.rs` — switched all
      seven `post_recovery_principal_cache_*` handlers from
      `JsonBody(body): JsonBody<Value>` to `req: &mut Request` +
      `req.parse_json().await`.
- [x] `crates/backend/src/handlers/account/auth.rs:490-505` — replaced
      `depot.get::<T>().cloned().ok_or_else(…)?` (`Depot::get` returns
      `Result`, not `Option`) with `.map_err(…)?`.
- [x] `crates/backend/src/handlers/admin/v1/accounts.rs` — added a
      `Resource` impl on `AccountRiskActionCurrentResponse` with a
      canonical path of `/api/admin/v1/accounts/{id}/risk-action/current`.
- [x] `crates/backend/src/handlers/contrix.rs` — added
      `impl From<coauth_data::RepositoryError> for ContrixRouteError`.
- [x] `crates/backend/src/handlers/account/auth.rs` — added
      `derive(ToSchema)` to `AuthBridgeDescribeResponse`,
      `AuthBridgeOAuthDescriptor`, `AuthBridgeContrixDescriptor`,
      `AuthBridgeAdminDescriptor`, `IntegrationManifestResponse`,
      `IntegrationManifestDependency`, `IntegrationManifestSurface`.
- [x] `crates/backend/src/handlers/admin/v1/accounts.rs` —
      `AccountRecord::from_user` no longer partially moves `user`
      (precompute `primary_principal_did` before destructuring).

## P0: Repository hygiene & release pipeline

These are low-effort, high-impact: a wrong CI toolchain or wrong image
registry blocks every release.

- [x] Fix invalid Rust toolchain pin in `.github/workflows/ci.yaml`
      (`dtolnay/rust-toolchain@1.100.0` → `@1.93.0`).
- [x] Container registry consistency: unify everything on
      `ghcr.io/contrix-dev/coauth` and `github.com/contrix-dev/coauth`
      across `Cargo.toml`, `release.yaml`, `book.toml`, `book-zh.toml`,
      README, docs, library doc-comments.
- [x] User-visible `Pasion` strings replaced with `coauth` in CLI help,
      library doc-comments, and contributing / architecture / reverse-proxy
      docs.
- [x] Add a top-level `CHANGELOG.md` scaffold.
- [x] Env-var prefix deprecation path: `COAUTH_CONFIG` and `COAUTH_*`
      are now read first; `PASION_CONFIG` / `PASION_*` are still honoured
      as fallback so existing deployments don't break silently. Documented
      in `docs/en/operations/upgrades.md` and `docs/en/reference/configuration.md`.
- [ ] Drop the `PASION_*` fallback once a major release notice has been
      out for one minor cycle. Track in `CHANGELOG.md` under the next
      major heading.
- [ ] Postgres advisory-lock label in `crates/backend/src/sync.rs`
      (`"Pasion config sync"`) is intentionally **not** renamed —
      changing it would let an old and a new process hold different
      locks and step on each other during a rolling upgrade. Plan a
      coordinated cutover before renaming.
- [x] CI advisory sweep: daily `schedule: cron '37 5 * * *'` runs the
      existing `cargo-deny` job so newly disclosed CVEs surface even
      without pushes (`cargo-deny check advisories` is the project's
      `cargo audit` equivalent — same advisory-db source).
- [x] Cosign signing scope documented in
      `docs/en/development/releasing.md` (signing only on `v*` tags and
      `main`; PR/branch builds intentionally unsigned because the GitHub
      OIDC identity for short-lived builds is unstable). Includes a
      runnable `cosign verify` snippet for operators.

---

## P0: Operator-facing security & config

- [x] Default response security headers middleware
      (`security_headers_middleware` in `crates/backend/src/server.rs`)
      now sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
      `Referrer-Policy: strict-origin-when-cross-origin`, and
      `Cross-Origin-Opener-Policy: same-origin` on every response.
- [x] Opt-in HSTS landed: `http.hsts` config block (max-age,
      `includeSubDomains`, `preload`); off by default. The
      `security_headers_middleware` reads
      `AppState::hsts_header` and emits `Strict-Transport-Security`
      only when set. Documented in
      `docs/en/reference/configuration.md`.
- [ ] Outstanding security-header work:
  - [ ] Per-route `Content-Security-Policy` for HTML responses.
  - [ ] Whitelist embed routes that legitimately need
        `X-Frame-Options: SAMEORIGIN` or a tighter `frame-ancestors`.
- [x] Configurable HTTP body / timeouts on `HttpConfig`:
  - [x] `http.max_body_bytes` (default 1 MiB) wired into Salvo's
        `SecureMaxSize` middleware on the public router.
  - [x] `http.request_timeout_seconds` (default 30 s) wired through a
        new `RequestTimeout` middleware. Returns
        `503 Service Unavailable` on expiry. Set to `0` to disable.
  - [x] `http.shutdown_grace_seconds` (default 30 s) wired into
        `LifecycleManager::with_timeout` — replaces the previous
        60-second hardcoded soft-shutdown grace.
- [x] DID-binding rate limit landed (`config.rate_limiting.did_binding`,
      `Limiter::check_did_binding`, enforced in
      `crates/backend/src/handlers/admin/v1/account_dids.rs` for
      `add_account_did` and `remove_account_did` before the call
      context is loaded). Defaults: 5 / minute per source IP and
      3 / 5 minutes per target account.
- [ ] MFA / TOTP enrolment & verification rate limits. Requires
      threading a `Limiter` and `RequesterFingerprint` through the
      flow-stage executor signature
      (`crates/backend/src/handlers/flow/stages/mod.rs:129`,
      `authenticator_validate::execute`). Defer until the flow-stage
      refactor lands so we don't add infrastructure with no caller.
- [x] TLS hardening: `build_tls_server_config` now pins the
      protocol-version floor to TLS 1.2 and prefers TLS 1.3
      (`builder_with_protocol_versions`). rustls 0.23 already refused
      TLS 1.0/1.1; stating the policy explicitly makes it reviewable.
- [x] Trusted-proxy / `X-Forwarded-For` documented in
      `docs/en/setup/reverse-proxy.md` + zh mirror, with a security
      note against widening the trust list to `0.0.0.0/0`.

---

## P0: Deployment & startup documentation

- [x] `docs/en/setup/docker.md` + zh mirror with a runnable
      `docker-compose.yaml` (Postgres + coauth), Kubernetes probes, and
      Cosign signature verification example.
- [x] Sample systemd unit at `misc/systemd/coauth.service`, referenced
      from `docs/en/setup/running.md`.
- [x] Dockerfile `HEALTHCHECK` (binary smoke test; orchestrators should
      probe `/health` on the internal listener for real liveness).
- [x] `coauth healthcheck` sub-command lands at
      `crates/cli/src/commands/healthcheck.rs`: probes
      `http://127.0.0.1:<port>/health` (port derived from the first
      listener that exposes the `health` resource) and exits non-zero
      on failure. The `Dockerfile` `HEALTHCHECK` now invokes this
      sub-command, so the probe exercises the running server, not
      just the binary.
- [x] `docs/en/operations/backup-restore.md` + zh mirror (Postgres
      `pg_dump`, key material, encryption-secret restore semantics,
      DR checklist).
- [x] `docs/en/operations/upgrades.md` + zh mirror covering routine
      upgrades, compatibility surface, Pasion/Palpo migration
      checklist, and the `COAUTH_*` env-var migration.
- [x] OpenAPI discovery URLs (`/api/admin/v1/openapi.yaml`,
      `/.well-known/contrix/openapi.yaml`,
      `/api-doc/admin/openapi.json`, `/admin-swagger-ui/`) documented
      in `docs/en/topics/admin-api.md` and zh mirror, including the
      sodmin-discovery hint.

---

## P1: Contrix protocol gaps that still return 501 / scaffold

`/api/v1/server/describe` still advertises features whose handlers
return 501 or use scaffolded state. Either remove the advertisement or
land the implementation.

- [ ] DID binding write path (admin):
  - [ ] `add_account_did` – validate `control_proof` against starid /
        configured DID resolver before persisting
        (`crates/backend/src/handlers/admin/v1/account_dids.rs:216-231`).
  - [ ] `remove_account_did` – soft-revoke with audit trail instead of
        hard delete (`account_dids.rs:234-246`).
- [ ] Device admin:
  - [ ] Cascade revoke active session grants when a device is revoked
        (`crates/backend/src/handlers/admin/v1/devices.rs:75`).
  - [ ] Wire device records to the device DID registration flow.
- [ ] Risk-action / approval workflow:
  - [ ] Replace in-memory scaffolds with durable proposal records
        (`accounts/risk_action.rs:532,657,766`).
  - [ ] Persist reason + approval proof for high-risk admin actions
        (`accounts.rs:573`).
- [ ] Claims / attestations:
  - [ ] Land claim issuance / revocation storage and signed
        attestation issuance behind `urn:contrix:admin:claim.*`.
  - [ ] Surface claim status list endpoint and revocation status
        fail-closed semantics promised in the protocol.
- [ ] Session-grant audience selection:
  - [ ] `password_login_session_grant_target`
        (`crates/backend/src/handlers/contrix.rs:537`) currently picks
        the first principal server. Replace with the explicit audience
        proven during the OIDC / passkey flow.
- [x] Session-grant listing / introspection / revocation now require
      bearer-token authentication. `list_session_grants` and
      `introspect_session_grant` accept either an admin scope or
      `urn:contrix:principal-server:session.bind`;
      `revoke_session_grant` requires admin scope (Principal Server
      callers cannot revoke). Implemented in
      `crates/backend/src/handlers/contrix.rs::require_session_grant_caller`.
- [ ] Surface a structured 401/403 envelope from
      `require_session_grant_caller` (currently 400 to match the
      existing `ContrixRouteError` shape; cleaner classification will
      come with the planned error-envelope refactor).

---

## P1: OIDC / OAuth2 contract polish

- [ ] OIDC discovery advertises the Contrix-specific scopes / claims
      (and only those) in production builds.
- [ ] Dynamic client registration supports the four Contrix client
      profiles (`chask`, `sodmin`, `soland`, internal automation).
- [ ] Passkey/WebAuthn registration + authentication + recovery +
      step-up.
- [ ] Upstream OIDC mapping: trusted-issuer rules for claim
      forwarding, upstream logout / session revocation propagation.

---

## P1: Notification & abuse controls

- [x] Audited notification dispatch + queue worker
      (`crates/backend/src/handlers/notification_dispatch.rs`,
      `crates/tasks/src/notifications.rs`): no OTP codes, recovery
      tokens, or password material are emitted to logs. Only Ulid
      identifiers and the destination email/phone (already in the
      database row being processed) are logged.
- [ ] CAPTCHA hook reachable from registration, login, recovery,
      DID-binding paths.
- [ ] Account-enumeration resistance on registration / recovery /
      login error responses.

---

## P1: Migration / compatibility

- [ ] Make the legacy Matrix compatibility adapter opt-in and disabled
      by default for fresh Contrix deployments.
- [ ] Migration tool (`coauth migrate ...`) for existing Pasion users,
      Matrix localpart → handle claim, OAuth client registry,
      admin scopes.
- [x] Legacy route policy documented in
      `docs/en/topics/legacy-compatibility.md` + zh mirror: which
      `/account/*`, OAuth2/OIDC and `/_matrix/*` / `/_palpo/*` paths
      are still served, and which are explicitly removed from the
      production router.

---

## P2: Test & release gates

- [ ] Unit tests for: session-grant issuance, DID binding control proof,
      claim issuance / revocation.
- [ ] HTTP contract tests for every admin endpoint advertised in the
      OpenAPI bundle.
- [ ] OIDC conformance smoke against generated discovery / JWKS / token
      endpoints in CI.
- [ ] Integration stack with `soland` + `starid` + `sodmin`.
- [ ] Security review checklist before each minor release: token
      storage, WebAuthn ceremony, recovery flow, admin audit, log
      redaction.

---

## Definition of Done

- New Contrix functionality is documented in README and OpenAPI.
- The production code path does not depend on Matrix / Palpo / Pasion
  naming or scopes.
- Every session / token is bound to principal DID, device, audience,
  and expiry.
- Every DID / claim operation has proof verification and audit trail.
- `sodmin` can manage coauth through the stable Contrix admin APIs.
- `cargo deny`, `cargo clippy -D warnings`, `cargo fmt --check` and the
  workspace test suite all pass on `main`.
