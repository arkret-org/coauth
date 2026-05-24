# coauth — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: OIDC + account + DID-binding + policy for orgs running soland.
> Phase: **2 (track 2b)**, polish in **5**.

## State at start (2026-05-24)

- 17 crates, ~182 k LoC; Salvo + Diesel + Postgres + Dioxus(WASM) frontend.
- OIDC: auth code, device, refresh, dynamic registration, introspection, discovery, JWKS — all wired. PKCE required by default.
- Account: Argon2id + Bcrypt legacy; TOTP + WebAuthn; email verification + recovery.
- DID binding: control proof against resolved DID JWKS (did:web, did:webvh, did:key).
- Policy: pluggable Cedar / Remote HTTP backends; policy/check v2 wire shape post-R4.
- i18n: Fluent + ICU; en + zh via Localazy.
- Crypto: keystore AES via ChaCha20Poly1305; algorithm allowlist excludes `none`/asymmetric HS256.
- CI: comprehensive (rustfmt, clippy, deny, postgres, conformance plans shipped, e2e compose).

## Phase 2 tasks (critical-path)

### Round 4 binding-proof closure
- [ ] §1 Finish `services/did_binding_proof.rs` verifier chain — chain (a) JWS signature, (b) DID document resolve, (c) verificationMethod match, (d) canonical statement match. Currently the structure exists but full transcript validation is TODO per CHANGELOG.
- [ ] §2 Wire policy-response signing transcript (R4 closure) end-to-end. Reference: CHANGELOG entry 2026-05-20.
- [ ] §3 Add a fixture-driven test against `contrix-spec/spec/v1/artifacts/fixtures/` binding proof vectors.

### Conformance polish
- [ ] §4 Ship `conformance/conformance-keys.sh` to generate mTLS test fixtures (currently TODO in `conformance/README.md`).
- [x] §5 Promote full OIDC conformance from manual `COAUTH_RUN_FULL_CONFORMANCE=1` to a **nightly** GHA job. PR jobs stay smoke-only. (Q4 in master plan.)
- [x] §6 Add the three plans (`plan-basic-op.json`, `plan-fapi2-baseline.json`, `plan-mtls-baseline.json`) into the nightly run.

### Admin types extraction
- [ ] §7 Land the `TODO(a0-shared-crate)` items: extract applets_admin, bridge_admin, federation_admin, space_policy_admin into `coauth-admin-types`. sodmin currently has these inline (a known duplicate).
- [ ] §8 Publish OpenAPI examples for the admin bridge surface (currently noted as TODO).

### Frontend (Dioxus SPA) polish
- [ ] §9 Cross-check `crates/frontend/src/pages/login.rs` against sodmin's login flow — confirm they hit the same endpoints. (Today they share `coauth-admin-types` but with different request flows.)
- [ ] §10 Add WCAG 2.1 AA check to the frontend (focus rings, aria-live for OTP errors, contrast). Capture in `frontend/A11Y.md`.
- [ ] §11 Confirm `dx build` output bundles the latest Fluent translations (en+zh) — currently the WASM SPA embeds them.

### Engineering hygiene (master plan §5)
- [x] §12 Add Trivy scan to release.yaml's container build step.
- [x] §13 Add local cosign/SLSA provenance command documentation; do not push images or tags.
- [x] §14 SBOM generation via `syft` as a local artifact.
- [x] §15 Set up Dependabot for cargo + actions.

### Observability
- [x] §16 Confirm OpenTelemetry exporter works against a real OTEL collector (jaeger/tempo) — currently jaeger/otlp/stdout exporters are present; add an example in `docs/en/observability.md`.
- [x] §17 Add `/readyz` probe (Postgres reachable + JWKS warmed).
- [x] §18 Expose Prometheus on a separate port via `COAUTH_METRICS_BIND`.

### Doc updates
- [ ] §19 Document the Round R4 wire-breaking changes in `docs/en/upgrade-to-r4.md` (cross-signing reset proofs must be reissued after trust_domain rotation).
- [ ] §20 Confirm the 5-state invite-claim flow is in `docs/en/account-lifecycle.md`.

## Phase 3 tasks

- [ ] §21 Pair with sodmin to land `admin-types` shared-crate extraction (§7) once the bridge/risk-action surfaces stabilize.

## Phase 5 tasks (final 1.0)

- [ ] §22 External security review — same vendor as soland.
- [ ] §23 Bump to `v1.0.0` and build image + book sites (en + zh) locally.

## Exit gate (phase 2)

All of:
1. §1-§20 closed.
2. Nightly full OIDC conformance green for all three plans.
3. `cotest fast-smoke` green against coauth+soland.
4. Local internal milestone `v0.9.0` recorded in docs/todos.

## Notes

- The book (mdBook) at `book.toml` / `book-zh.toml` should publish per-PR previews — confirm `docs.yaml` workflow does this.
- Policy default rules: ship a `policies/` directory of Cedar policies as a reference deployment.
