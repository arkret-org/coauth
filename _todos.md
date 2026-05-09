# coauth Active TODO

> Updated: 2026-05-09
> Scope: Contrix Auth / Account Server. Only **unfinished** items are
> listed here. Completed items live in `git log` and `CHANGELOG.md`.

## C10.E 续³ — invite-quarantine outbox persistence + admin review surface + MIMI SDK-gap audit (2026-05-09 二十轮)

Round 20 lands the persistence + review side of the consent-gate
quarantine path, and locks down the SDK-gap story for the MIMI
anchor-signer that was left as a stub in round 19.

Landed:
- New Diesel migration
  `crates/data/migrations/20260509000100_invite_quarantine_queue/{up,down}.sql`
  + matching `diesel::table!` + `allow_tables_to_appear_in_same_query!`
  entry in `crates/data/src/pg/schema.rs`. Schema:
  `(id uuid pk default gen_random_uuid(), created_at, peer_did,
  target_holder_did, consent_id, scope, requesting_admin_did, payload
  jsonb, status text default 'pending', resolved_at, resolution_note)`.
  CHECKs constrain non-empty DIDs and a closed `pending|approved|rejected`
  status set; indexes on `(status, created_at desc)`,
  `target_holder_did`, and `consent_id`.
- New service module
  `crates/backend/src/services/invite_quarantine.rs` exposing the
  `InviteQuarantineService` trait + `PgInviteQuarantineService` impl
  (mirrors the round-18 `account_claims` style — raw `sql_query` against
  the shared `DieselPool<AsyncPgConnection>`, no full repo abstraction).
  Methods: `enqueue / list_pending / get / mark_resolved`. The status
  transition on `mark_resolved` is intentionally narrow (only `pending`
  rows can move forward, returns `None` on already-resolved). Wired
  into `app_state.rs` + `test_utils.rs` and exposed as
  `DepotExt::invite_quarantine_service()`.
- `crates/backend/src/handlers/admin/v1/users/create.rs`:
  - `Quarantined` branch now persists the gate intent to the queue via
    `invite_quarantine_service.enqueue(...)`. Audit log records
    `quarantine_id` so sodmin / yougen can correlate the admin op back
    to the queue row. The wire response is still 422 + `quarantined`
    (the immediate batch_invite call did not mint tokens; admin must
    resolve via the new endpoints below). If the enqueue itself fails
    (DB hiccup), the gate decision still wins — we surface
    quarantined-without-id rather than swallowing the gate.
- New admin handler module
  `crates/backend/src/handlers/admin/v1/invite_quarantine.rs`:
  - `GET /api/admin/v1/invite-quarantine?limit=N` — paged list of
    `pending` rows, oldest first.
  - `POST /api/admin/v1/invite-quarantine/{id}/resolve` — body
    `{decision: "approve"|"reject", note?: ...}`. Returns 404 if the
    row does not exist or is already resolved. Approve is intentionally
    a *flag flip* (not auto-replay) — sodmin re-issues `batch-invite`
    with confirmed parameters once consent has been re-anchored.
  - Auth via the same `extract_call_context` chain as the rest of the
    admin v1 surface (admin scope check, oauth2 / personal session).
  - Wire-status enum (`pending|approved|rejected`) decoupled from the
    service-layer enum so the admin OpenAPI is stable across future
    service-level renames.
  - Wired into `crates/backend/src/server.rs` admin router beside
    `audit-feed`.
- `crates/backend/src/handlers/account/mimi_consent.rs::anchor_pending_move`:
  re-audited the SDK surface (`contrix-rust-sdk` 0.4.0 at
  `D:/Works/contrix-dev/contrix-rust-sdk/crates/`). Confirmed there is
  **no** `Move` envelope or `sign_move(...)` API exposed from
  `crates/lattice` (only the CRDT primitives `or_set`, `mv_register`,
  `counter`, `ordered_log`); coauth does not currently depend on
  `contrix-lattice`, `contrix-operations`, `contrix-signatures`, or
  `contrix-core` either. The doc-comment now spells out the precise
  three-step gap (envelope/signer landing in SDK → keystore wiring →
  POST to soland's `/api/v1/moves`) so the next round either lands the
  SDK piece or has a clear reason not to. The handler still returns
  `MimiConsentError::NotImplemented`; behaviour unchanged.
- 9 new unit tests:
  `services::invite_quarantine::tests` (4):
  `status_round_trips`, `status_parse_unknown_returns_none`,
  `row_into_record_falls_back_to_pending_on_unknown_status`,
  `enqueue_dto_carries_payload`.
  `handlers::admin::v1::invite_quarantine::tests` (5):
  `wire_status_round_trip`, `entry_from_record_preserves_fields`,
  `resolve_request_parses_approve`,
  `resolve_request_parses_reject_with_note`,
  `resolve_request_rejects_unknown_decision`.
  All pure (no DB / no HTTP); the existing wiremock + test-db
  integration patterns cover the enqueue→list→resolve loop end-to-end
  via the batch_invite gate test once `DATABASE_URL` is present
  (DB-pool failures unrelated to this round are left as-is, per task
  scope).

Test counts: `cargo check --workspace` clean. `cargo test -p
coauth-backend --lib` exercises 9 new tests on top of the 22 from round
19 (and the 17 before that) — all consent-gate / mimi /
invite-quarantine / typed_uuid7 tests pass; the workspace's
pre-existing 115 Postgres-pool test failures are unrelated and bounded
by `DATABASE_URL`.

Deferred (intentional):
- Auto-replay of the original invite on `approve`: out of scope per the
  module docstring rationale (sodmin re-issues `batch-invite` with
  confirmed parameters; the queue stores enough context to render the
  decision UI).
- `is_typed_uuid7` admin-handler call-sites: still no incoming
  `cx:device:` / `cx:space:` / `cx:event:` parsing on the wire (admin
  surface uses ULIDs for resource IDs). The helper stays staged ahead
  of demand; will be wired the moment the first admin handler accepts
  one of those typed wire ids.
- `anchor_pending_move` real-wire: blocked on SDK surface (see above).

## C10.E 续² — batch_invite consent gate + MIMI scaffolding + typed-uuid7 helper (2026-05-09 十九轮)

Aggressive follow-on round: wires the consent gate into the existing
`batch_invite` admin endpoint, scaffolds the MIMI consent → Move bridge,
and adds a typed-uuid7 validator for future Contrix wire-id call-sites.

Landed:
- `crates/backend/src/handlers/admin/v1/users/create.rs`:
  - `BatchInviteRequest` gains an optional nested `consent_gate` field
    (`BatchInviteConsentGate { peer_did, target_holder_did, consent_id,
    scope, target_principal_url?, require_consent }`). Legacy callers
    that omit the field skip the gate entirely (registration-token-only
    behaviour preserved).
  - New pure helper `evaluate_batch_invite_gate(...)` calls
    `consent_cell_query::query_consent_cell` + `evaluate_invite_gate` and
    returns `BatchInviteGateOutcome::{Allow, ConsentRequired, Quarantined}`.
    Mirrors the relay handler's split-concern shape so both the Salvo
    handler and unit tests can share the logic.
  - `batch_invite` now consults the gate before minting tokens. The
    previous `let _ = ... evaluate_invite_gate;` dead anchor is gone.
    `ConsentRequired` → 422 + `consent_required`; `Quarantined` → 422 +
    `quarantined` (distinct reasons preserved on the wire). Real
    quarantine-outbox persistence remains
    `TODO(c10e-quarantine-outbox)`.
  - 6 wiremock-driven unit tests (`consent_gate_tests`):
    `batch_invite_gate_allows_when_metadata_absent`,
    `batch_invite_gate_allows_when_consent_granted`,
    `batch_invite_gate_returns_consent_required_when_missing`,
    `batch_invite_gate_quarantines_when_unknown_and_not_required`,
    `batch_invite_gate_rejects_when_peer_mismatch`,
    `batch_invite_gate_fails_closed_when_no_principal_url`.
- `crates/backend/src/util.rs` — new `is_typed_uuid7(s, prefix)` helper
  that validates `cx:<prefix>:<uuid-v7-strict>` strings. Rejects legacy
  ULIDs, v4 UUIDs, missing `cx:` namespace, wrong prefix, extra
  segments, and empty bodies. 7 unit tests under `util::tests`. Coauth
  has no current `cx:device:`/`cx:space:` parsing call-sites, so this
  is staged ahead of demand — the next admin handler that consumes a
  Contrix wire id should call this rather than rolling its own check.
- New `crates/backend/src/handlers/account/mimi_consent.rs` —
  scaffolding for MIMI `request_consent` / `update_consent` → consent
  cell **Move** mapping:
  - Typed envelopes `RequestConsent` / `UpdateConsent` (subset of
    MIMI spec, `non_exhaustive` for forward-compat).
  - Pure helpers `consent_cell_id(consent_id)` and
    `build_consent_tag(peer, scope)` matching spec §6.1 wire format.
  - `update_consent_to_pending_move(...)` translates an envelope into a
    `PendingMove { cell_id, op: OrSetAdd|OrSetRemove, tag }` without
    touching I/O.
  - `authorize_actor(actor, holder, controllers)` covers self-update +
    static-controller-list cases. Delegated-controller resolution
    (requires soland round trip) deferred.
  - `anchor_pending_move(...)` is the eventual signer call-site;
    intentionally returns `MimiConsentError::NotImplemented` until the
    SDK lattice + anchor crate is wired in. Tracked under
    `TODO(c10e-mimi-move)`.
  - 9 unit tests (cell-id format, tag form, grant→add / revoke→remove
    mapping, missing-field rejection, actor-authorization variants,
    NotImplemented stub).
- `crates/backend/src/handlers/account/mod.rs` — `pub mod mimi_consent;`.

Test counts: `cargo test -p coauth-backend --lib` exercises 22 new
tests on top of the 17 from earlier C10.E rounds. All consent /
mimi / typed_uuid7 tests pass; the workspace's pre-existing Postgres
failures (115) are unrelated — they require `DATABASE_URL` env var.

Deferred (intentional):
- ~~Quarantine outbox persistence + admin-review UI~~ — landed in
  round 20 (see top of file).
- Real anchorer signer for `anchor_pending_move` — depends on the SDK
  lattice + anchor crate's `sign_move` API surface; round-20 audit
  confirms `contrix-rust-sdk` 0.4.0 does not expose this. Tracked
  alongside the §"P1: Move / Anchor / Lattice" anchorer signer subtask
  below.
- Delegated-controller resolution in `authorize_actor` — needs a
  soland round trip; static-list path is enough for the scaffolding.

## C10.E 续 — invite-relay handler (2026-05-09 十八轮 并行)

Per-recipient invite-relay handler that consumes the `consent_cell_query`
helper from the previous round.

Landed:
- New `crates/backend/src/handlers/account/invite_relay.rs`:
  - `relay_invite_with(...)` — pure async helper. Calls
    `query_consent_cell` + `evaluate_invite_gate`, then on `Allow`
    forwards the inviter-signed payload via `reqwest::post`. Returns
    `RelayOutcome::Forwarded { forwarded_ok } | ConsentRequired |
    Quarantined`. Designed for wiremock-driven unit tests (no DB / no
    Salvo Service plumbing).
  - `relay_outcome_to_response(...)` — pure mapper from `RelayOutcome`
    to `(StatusCode, RelayResponse)`: 200 + `forwarded`, 403 +
    `consent_required`, 202 + `quarantined`.
  - `post_invite_relay` (Salvo `#[endpoint]`) — handler at
    `POST /api/v1/account/invites/relay`. Body validation rejects empty
    `inviter_did / target_holder_did / consent_id / scope` with 400
    `missing_required_fields`. Body's `target_principal_url` overrides
    `ContrixConfig::principal_server_url`; if neither is set, returns
    400 `config_required`. The forward target is computed as
    `{principal_url}/api/v1/invites/intake` (placeholder path tracked
    under `TODO(c10e-invite-intake)`).
- `crates/backend/src/handlers/account/mod.rs` — `pub mod invite_relay;`.
- `crates/backend/src/server.rs` — route registered alongside the OAuth2
  consent block: `Router::with_path("account/invites/relay")
  .post(invite_relay::post_invite_relay)`.
- 6 unit tests in `invite_relay.rs#tests`, all wiremock-backed:
  - `relay_allows_when_consent_granted` (cell granted + forward 200 →
    `Forwarded { forwarded_ok: true }`).
  - `relay_returns_consent_required_when_no_consent` (cell 404 +
    `require_consent=true` → `ConsentRequired`, 403).
  - `relay_quarantines_when_consent_unknown_and_not_required` (soland
    500 + `require_consent=false` → `Quarantined`, 202).
  - `relay_rejects_when_target_principal_url_missing` (no URL anywhere
    → 400 `config_required`).
  - `relay_reports_forward_failure_as_forwarded_ok_false` (Allow but
    forward target returns 503 → 200 with `forwarded_ok: false`,
    caller-retry signal).
  - `relay_allow_without_forward_target_is_gate_only_success`
    (gate-only mode for callers like yougen that forward themselves).

Deferred (intentional):
- The forward path `/api/v1/invites/intake` is a placeholder until
  soland exposes the canonical invite-intake endpoint
  (`TODO(c10e-invite-intake)` in the handler).
- `Quarantine` currently only returns 202 with status `quarantined`; the
  holder-side queue persistence + admin-review UI are separate items.
- Auth on the relay route reuses the surrounding API auth chain
  (cookie + bearer); per-route DID-binding/audit-log refinements are
  tracked alongside the broader consent-gate work below.

## C10.E (2026-05-09 十七轮 并行)

Coauth-side scaffolding for the Move/Anchor/Lattice invite consent gate.

Landed:
- New `crates/backend/src/handlers/account/consent_cell_query.rs`:
  - `query_consent_cell(principal_server_url, holder_did, consent_id, http_client)`
    issues a GET against
    `{principal_server_url}/api/v1/admin/cells/<cell_id>` and parses the
    OrSet tag list. Returns `ConsentLookup::Known(...)` on success,
    `ConsentLookup::Unknown { reason }` on missing config / network / parse
    error. Marked `TODO(soland-cell-query)` because soland does not yet
    expose this admin endpoint.
  - `evaluate_invite_gate(lookup, peer_did, scope, require_consent)` is a
    pure function that translates a lookup result to one of
    `Allow / ConsentRequired / Quarantine`, matching spec §6.1's
    `peer=…;scope=invite|any` tag pattern.
  - 11 unit tests (5 wiremock-driven HTTP scenarios + 6 pure-fn gate cases).
- `ContrixConfig::principal_server_url: Option<Url>` added in
  `crates/config/src/sections/contrix.rs`. Loadable today via figment as
  `PASION_CONTRIX__PRINCIPAL_SERVER_URL`; the helper docstring also
  notes the spec-suggested `COAUTH_PRINCIPAL_SERVER_URL` override path.
- Hook-point comment + `TODO(c10e-invite-relay)` added to
  `crates/backend/src/handlers/admin/v1/users/create.rs::batch_invite`,
  documenting where the per-recipient relay handler should call the gate
  once it lands. `batch_invite` itself only mints registration tokens,
  so it has no peer DID to gate on — the comment explains why this stub
  is intentional.

Deferred (intentional, per task scope):
- Cross-service wire integration: soland needs a public admin cell-read
  endpoint. Until then `query_consent_cell` returns `Unknown` from the
  network call. The hook-point comment leaves a `TODO(soland-cell-query)`.
- Per-recipient invite relay handler (the "real" call-site) is not in
  this PR; the helper is in place so it's a one-liner to wire when it
  lands.
- MIMI `request_consent` / `update_consent` interop and rare-mode
  anchorer signer remain in §"P1: Move / Anchor / Lattice" below.



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

- [~] **Invite consent gate** (spec consent-model §6.1, rebased onto Move): before
      issuing or relaying an invite to a target principal, query the holder's
      consent cell (`cx:cell:cx.component.consent.v1:<consent_id>`) in their
      principal control Space and read its or-set join value to determine
      whether `(peer=requester, scope="invite" OR scope="any")` is currently
      granted. Match cases:
  - granted + active window → continue normal invite flow
  - revoked or absent + `cx.space.policy_components.preauth.require_consent`
    is true → reject with `consent_required`
  - revoked or absent + default profile → route to holder's quarantine inbox

  Status (2026-05-09 二十轮): handler-level gate **wired** for both
  `POST /api/v1/account/invites/relay` (per-recipient, full forward
  path) and `POST /api/admin/v1/users/batch-invite` (token-mint, opt-in
  via `consent_gate` body field). On `Quarantined`, `batch_invite` now
  persists to the new `invite_quarantine_queue` table and exposes admin
  review via `GET /api/admin/v1/invite-quarantine` and
  `POST /api/admin/v1/invite-quarantine/{id}/resolve`. 37 tests across
  5 modules. Remaining: real soland cell-read endpoint
  (`TODO(soland-cell-query)`).
- [~] **MIMI consent interop** (rebased onto Move): when accepting incoming
      MIMI `request_consent` / `update_consent`, validate the actor is the
      declared holder or an authorized controller, then construct a Move on
      the holder's consent cell (or-set: grant=add tag, revoke=remove tag)
      written into that holder's principal control Space; preserve
      `consent_id` as inter-protocol correlation.

  Status (2026-05-09): typed envelopes + pure
  `update_consent_to_pending_move(...)` mapping landed at
  `crates/backend/src/handlers/account/mimi_consent.rs`. The signer
  call-site (`anchor_pending_move`) returns `NotImplemented` pending the
  SDK lattice + anchor crate; see anchorer-signer subtask below.
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
