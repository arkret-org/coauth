# coauth Active TODO

> Updated: 2026-05-07
> Scope: Contrix Auth / Account Server. Only **unfinished** items are
> listed here. Completed items live in `git log` and `CHANGELOG.md`.

## 0. Boundary recap

- `coauth` proves who logged in to which local account / device / session,
  and exposes that to Principal Servers (`soland`) and admin tooling
  (`sodmin`). It is **not** a DID Registry — DID documents, key logs and
  registry receipts live in delegated/public DID resolver services.

---

## P0: Repository hygiene & release pipeline

- [ ] Drop the `PASION_*` env-var fallback once a major release notice
      has been out for one minor cycle.
- [ ] Postgres advisory-lock label in `crates/backend/src/sync.rs`
      (`"Pasion config sync"`) is intentionally **not** renamed yet —
      changing it would let an old and a new process hold different
      locks. Plan a coordinated cutover before renaming.

---

## P0: Operator-facing security & config

- [ ] MFA / TOTP enrolment & verification rate limits. Requires
      threading a `Limiter` through the flow-stage executor signature.
      Defer until the flow-stage refactor lands.

---

## P1: Contrix protocol gaps that still return 501 / scaffold

`/api/v1/server/describe` still advertises features whose handlers
return 501 or use scaffolded state.

- [ ] DID binding write path (admin):
  - [ ] `add_account_did` — validate `control_proof` against configured
        DID resolver before persisting (`starid` only when the
        deployment opts into the `did:webvh` profile).
  - [ ] `remove_account_did` — soft-revoke with audit trail instead of
        hard delete.
- [ ] Device admin:
  - [ ] Cascade revoke active session grants when a device is revoked.
  - [ ] Wire device records to the device DID registration flow.
- [ ] Risk-action / approval workflow:
  - [ ] Replace in-memory scaffolds with durable proposal records.
  - [ ] Persist reason + approval proof for high-risk admin actions.
- [ ] Claims / attestations:
  - [ ] Land claim issuance / revocation storage and signed
        attestation issuance behind `urn:contrix:admin:claim.*`.
  - [ ] Surface claim status list endpoint and revocation status
        fail-closed semantics.

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

## P1: Move / Anchor / Lattice — invite / consent gate

> Source: `contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 替换旧 state slot 模型。See root [`../_todos.md` C10.E](../_todos.md) and [`../contrix-spec/_state_todos.md`](../contrix-spec/_state_todos.md).
>
> Coauth impact is small: invite consent gate + MIMI consent interop + (rare) anchorer signer. No host endorsement work anywhere.

- [ ] **Invite consent gate** (spec consent-model §6.1, rebased onto Move): before
      issuing or relaying an invite to a target principal, query the holder's
      consent cell (`cx:cell:cx.component.consent.v1:<consent_id>`) in their
      principal control Space and read its or-set join value to determine
      whether `(peer=requester, scope="invite" OR scope="any")` is currently
      granted. Match cases:
  - granted + active window → continue normal invite flow
  - revoked or absent + `cx.space.policy_components.preauth.require_consent`
    is true → reject with `consent_required`
  - revoked or absent + default profile → route to holder's quarantine inbox
- [ ] **MIMI consent interop** (rebased onto Move): when accepting incoming
      MIMI `request_consent` / `update_consent`, validate the actor is the
      declared holder or an authorized controller, then construct a Move on
      the holder's consent cell (or-set: grant=add tag, revoke=remove tag)
      written into that holder's principal control Space; preserve
      `consent_id` as inter-protocol correlation.
- [ ] **Anchorer signer (rare deployment mode)**: typical deployments have
      soland as anchorer for principal control Spaces; if coauth controls a
      principal control Space and acts as its anchorer, coauth needs a light
      anchorer signer (single_did profile) — share the contrix-rust-sdk
      lattice + anchor crate rather than reimplementing.

---

## P1: Notification & abuse controls

- [x] CAPTCHA hook reachable from registration, login, recovery,
      DID-binding paths.
      Helper: `handlers::captcha::verify_token` (single-token,
      provider-agnostic, fail-closed when a token is supplied without
      configured CAPTCHA). Wired into:
        * `POST /api/v1/auth/login` — `LoginRequest.captcha_token`
        * `POST /api/v1/auth/register` — `RegisterInput.captcha_token`
        * `POST /api/v1/auth/recovery/start` — `StartRecoveryInput.captcha_token`
        * `POST /api/admin/v1/accounts/{id}/dids` and
          `DELETE /api/admin/v1/accounts/{id}/dids/{binding_id}` —
          `AddAccountDidBindingRequest.captcha_token` /
          `RemoveAccountDidBindingRequest.captcha_token` (admin write
          paths still return 501; CAPTCHA gating runs before the stub
          so it lights up automatically when the binding logic lands).
      Bug fix on the legacy flow-engine path: `site_hostname` no
      longer hardcoded to `"localhost"` and `remote_ip` is now
      threaded through from the bound activity tracker.
- [x] Timing-equivalence anti-enumeration: when the username is
      unknown, run a dummy password verify so attackers cannot use
      response latency to enumerate accounts.
      Implemented via `PasswordManager::dummy_verify`, called from
      `login_with_password` on both the user-not-found and no-active-
      password branches.

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
- [ ] Security review checklist before each minor release.

---

## P2: Robustness & maintainability

### Stale `TODO` / `XXX` triage

- [ ] 87 `TODO|FIXME|XXX|HACK` markers in the backend, mostly
      load-bearing discussion notes. Pick them off alongside the next
      substantive PR in each subsystem.

---

## P3: Structural refactors

### `ViewContext` follow-on

- [ ] ~22 view handlers still hand-roll the SSR prelude. Either finish
      migrating them to `ViewContext::extract`, or evaluate introducing
      an `ApiContext` for REST handlers.

### Frontend `PageShell` / Suspense

- [ ] `crates/frontend/src/pages/*.rs` — 27 pages each maintain their
      own loading / error state. Extract `components/page_shell.rs`.

### OAuth2 client i18n editor in admin SPA

- [ ] Backend endpoint and shell tool already cover localized metadata
      management. The Dioxus admin SPA does not yet have an admin
      section to host a proper editor.

---

## P4: Compliance follow-ups

### Continue lowering high-delta files

- [ ] In priority order (AGPL − Apache delta):
      `Cargo.toml` (root, 383), `config/sections/secrets.rs` (232),
      `matrix/src/lib.rs` (119), `config/sections/clients.rs` (96),
      `.github/workflows/build.yaml` (87).

### `review-mixed` final classification

- [ ] Reclassify `errors.rs`, `base64.rs`, `hmac.rs`, `header.rs`,
      `raw.rs`, `cli/commands/mod.rs` as `retain-apache`.

---

## Cross-project registration

- [~] **Root C3 · coauth → soland session grant**: grant id is returned,
      authenticated introspection works. PKCE / state / nonce material is
      durable (`oauth2_authorization_grants`, schema
      `crates/data/src/pg/schema.rs:299-303`). Formal session-key JWS
      proof verification is wired into introspection
      (`crates/backend/src/handlers/contrix.rs:1692-1730` →
      `introspect_session_grant`). Hourly cleanup worker for expired
      `oauth2_session_grants` is registered
      (`CleanupExpiredSessionGrantsJob`, cron `0 27 * * * *`).
      Remaining coauth-side work: explicit per-request audience selection
      beyond the configured admin / principal allowlist.
- [~] **Root C5 · recovery bridge**: principal-cache contract surface
      and scaffold handlers available. Remaining: durable upstream
      snapshot / cache records plus real refresh / complete / fail worker.
- [~] **Root C6 · DID resolver / starid optional integration**: soland
      now advertises optional StarID resolver discovery. coauth still
      needs DID control-proof validation via configured public resolvers.
- [ ] **Root C7 · admin API discovery / codegen**: keep
      `bridge/describe`, `/api/admin/v1/openapi.*`, risk-action,
      DID-binding, claims and device admin schemas stable for
      `sodmin`-generated clients.
- [~] **Root C8 · conformance**: cotest release gate covers
      session-grant introspection, recovery restore surface, optional
      StarID discovery. Remaining: DID-binding proof failure, durable
      principal-cache refresh, account-enumeration response shapes.
- [ ] **Root C10.E · invite + consent gate from spec Phase 5**: see
      "P1: v1 wire model rework — invite / consent gate" section above.
      Coauth's footprint here is small (no SDK rewrite needed); main work
      is invite handler integration with `cx.consent.*` queries.

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

## 已完成（changelog）

- `[x]` Per-route override hooks for `csp_html` and `X-Frame-Options`.
- `[x]` Re-audit of admin v1 surface: `unwrap`/`expect` clean.
