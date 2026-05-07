# coauth Active TODO

> Updated: 2026-05-07
> Scope: Contrix Auth / Account Server. Only **unfinished** items are
> listed here. Completed items live in `git log` and `CHANGELOG.md`.
> Historical Pasion-era backlog (`_tasks.md`) folded into the relevant
> sections below; the standalone file has been removed.

## 0. Boundary recap

- `coauth` proves who logged in to which local account / device / session,
  and exposes that to Principal Servers (`soland`) and admin tooling
  (`sodmin`). It is **not** a DID Registry — DID documents, key logs and
  registry receipts live in delegated/public DID resolver services.
- Matrix / Palpo support is a legacy compatibility adapter, not the
  primary path.

---

## P0: Repository hygiene & release pipeline

- [ ] Drop the `PASION_*` env-var fallback once a major release notice
      has been out for one minor cycle. Track in `CHANGELOG.md` under
      the next major heading.
- [ ] Postgres advisory-lock label in `crates/backend/src/sync.rs`
      (`"Pasion config sync"`) is intentionally **not** renamed yet —
      changing it would let an old and a new process hold different
      locks and step on each other during a rolling upgrade. Plan a
      coordinated cutover before renaming.

---

## P0: Operator-facing security & config

- [x] Per-route override hooks for `csp_html` and `X-Frame-Options`:
      handlers can call `crate::server::override_response_csp` /
      `override_response_frame_options` to pre-set the response
      header. The middleware uses `entry().or_insert()` for both
      headers, so any handler-set value wins over the deployment-wide
      default. Both helpers ship in `crates/backend/src/server.rs`
      with doc-comments pointing at the override pattern. Embed-
      friendly HTML routes can now opt into `SAMEORIGIN` framing or a
      relaxed CSP without touching the global config.
- [ ] MFA / TOTP enrolment & verification rate limits. Requires
      threading a `Limiter` and `RequesterFingerprint` through the
      flow-stage executor signature
      (`crates/backend/src/handlers/flow/stages/mod.rs:129`,
      `authenticator_validate::execute`). Defer until the flow-stage
      refactor lands so we don't add infrastructure with no caller.

---

## P1: Contrix protocol gaps that still return 501 / scaffold

`/api/v1/server/describe` still advertises features whose handlers
return 501 or use scaffolded state. Either remove the advertisement or
land the implementation.

- [ ] DID binding write path (admin):
  - [ ] `add_account_did` – validate `control_proof` against configured
        DID resolver before persisting (`starid` only when the
        deployment opts into the `did:webvh` profile)
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

- [ ] CAPTCHA hook reachable from registration, login, recovery,
      DID-binding paths.
- [ ] Timing-equivalence anti-enumeration: when the username is
      unknown, run a dummy password verify so attackers cannot use
      response latency to enumerate accounts. Requires a stable
      pre-computed hash held in `PasswordManager` and careful
      benchmarking so the dummy work matches a real verify.

---

## P1: Migration / compatibility

- [ ] Migration tool (`coauth migrate ...`) for existing Pasion users,
      Matrix localpart → handle claim, OAuth client registry,
      admin scopes.

---

## P2: Test & release gates

- [ ] Unit tests for: session-grant issuance, DID binding control proof,
      claim issuance / revocation.
- [ ] HTTP contract tests for every admin endpoint advertised in the
      OpenAPI bundle.
- [ ] OIDC conformance smoke against generated discovery / JWKS / token
      endpoints in CI.
- [ ] Integration stack with `soland` + `sodmin` plus optional `starid`
      profile coverage.
- [ ] Security review checklist before each minor release: token
      storage, WebAuthn ceremony, recovery flow, admin audit, log
      redaction.

---

## P2: Robustness & maintainability (folded from `_tasks.md`)

### `unwrap` / `expect` clean-up in admin handlers (was T20b)

- [x] Re-audit on 2026-05-07 found the admin v1 surface clean:
      `upstream_oauth_links.rs`, `user_emails.rs`, and
      `admin/v1/users/*` no longer contain any `.expect()` calls
      (only one trivially-infallible Ulid round-trip in
      `accounts/risk_action.rs:309`). The remaining ~26
      `depot.get::<T>("…").expect("…")` sites in `oauth2/discovery.rs`,
      `oauth2/keys.rs`, `oauth2/introspection.rs`, `oauth2/keys.rs`,
      `oauth2/registration.rs`, and `oauth2/revoke.rs` are deliberate
      server-invariant assertions on `Json<…>`-returning handlers —
      converting them to `?` would require changing the return type
      to add an error path that can never fire in a correctly
      configured server. Track those under "discovery handler error
      surface" if and when we revisit them.

### Stale `TODO` / `XXX` triage (was T15b)

- [ ] 87 `TODO|FIXME|XXX|HACK` markers in the backend, mostly
      load-bearing discussion notes:
      `oauth2/token_service.rs` (replay/race threads),
      `jose/claims.rs` (OIDC claim ergonomics),
      `oauth2/device/consent.rs` (404 vs 500 mapping for missing
      grant), `oauth2/registration.rs` (substring-match of policy
      violation messages for error-code routing). These are real but
      need their subsystem owner to evaluate — do not bulk-edit. Pick
      them off alongside the next substantive PR in each subsystem.

---

## P3: Structural refactors (folded from `_tasks.md`)

### `ViewContext` follow-on (was T23d)

- [ ] ~22 view handlers still hand-roll the SSR prelude (rng / clock /
      locale / templates / repo / cookie jar). Either finish migrating
      them to `ViewContext::extract`, or evaluate introducing an
      `ApiContext` for REST handlers and document which abstraction
      goes where. Decide before doing more piecemeal work.

### Frontend `PageShell` / Suspense (was T24)

- [ ] `crates/frontend/src/pages/*.rs` — 27 pages each maintain their
      own loading / error state. Extract `components/page_shell.rs`,
      wrap the Account routes with it, and let pages opt into a shared
      skeleton + error fallback.

### OAuth2 client i18n editor in admin SPA (was T08d)

- [ ] Backend endpoint and the `misc/oauth2-client-localized-metadata.sh`
      shell tool already cover localized metadata management. The
      Dioxus admin SPA does not yet have an admin section to host a
      proper editor. Land alongside the broader admin SPA work; the
      shell script keeps operators unblocked in the meantime.

---

## P4: Compliance follow-ups (folded from `_tasks.md` / `_report.md`)

> Historical context: dual-baseline review (Apache-2.0 + AGPL-3.0)
> against the legacy Pasion fork. Independent / new content reached
> 79.6 %; the `rewrite-closer-to-agpl-high` bucket is empty. ~52
> medium-delta files (~8 368 AGPL-shared lines) remain.

### Continue lowering high-delta files (was T13)

- [ ] In priority order (AGPL − Apache delta):
      | File | delta |
      |------|-----:|
      | `Cargo.toml` (root) | 383 |
      | `config/sections/secrets.rs` | 232 |
      | `matrix/src/lib.rs` | 119 |
      | `config/sections/clients.rs` | 96 |
      | `.github/workflows/build.yaml` | 87 |
      Low-delta files (`oidc.rs`, `keystore/lib.rs`, `claims.rs`,
      `jwk/mod.rs`, etc., delta < 30) are now annotated as
      "Apache-explainable" and need no further rewrite.

### `review-mixed` final classification (was T14)

- [ ] Reclassify the following files as `retain-apache` and update the
      compliance ledger (Apache ≈ AGPL, < 5-line delta):
      `errors.rs`, `base64.rs`, `hmac.rs`, `header.rs`, `raw.rs`,
      `cli/commands/mod.rs`.

---

## Cross-project registration

- [~] **Root C3 · coauth → soland session grant**: grant id is returned,
      authenticated introspection works, and login-time audience pinning
      landed. Remaining coauth-side work: durable PKCE / state / nonce
      material and formal proof semantics for `yougen` / `sodmin`.
- [~] **Root C5 · recovery bridge**: principal-cache contract surface
      and scaffold handlers are available for `soland` restore-ticket
      flows, the `sodmin` recovery console, and cotest release-gate
      checks. Remaining coauth-side work: durable upstream snapshot /
      cache records plus real refresh / complete / fail worker
      semantics.
- [~] **Root C6 · DID resolver / starid optional integration**: soland
      now advertises optional StarID resolver discovery and cotest
      gates it. coauth still needs DID control-proof validation via
      configured public resolvers. `starid` remains optional high-trust
      `did:webvh`, not a required v1 core dependency.
- [ ] **Root C7 · admin API discovery / codegen**: keep
      `bridge/describe`, `/api/admin/v1/openapi.*`, risk-action,
      DID-binding, claims and device admin schemas stable enough for
      `sodmin`-generated clients.
- [~] **Root C8 · conformance**: cotest release gate covers
      session-grant introspection, recovery restore surface, optional
      StarID discovery, and anti-enumeration fixtures. Remaining live
      coauth scenarios: DID-binding proof failure, durable
      principal-cache refresh, and account-enumeration response shapes.

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
