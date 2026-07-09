# coauth

> **Spec target**: [arkret-spec @ 5d66aeb](../arkret-spec) (v1 sync 2026-06-21)

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` and `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/pre-commit` is missing on a
branch, copy it from
[`arkret-rust-sdk`](https://github.com/arkret/arkret-rust-sdk) and
adapt the package list to coauth's workspace.

> **DO NOT commit secrets.** Files like `config.dev.yaml`, `config.local.*`,
> `*.log`, and unencrypted private keys are gitignored and must stay local.
> Use [`config.example.yaml`](config.example.yaml) as a template and source
> real values from environment variables. A CI `gitleaks` job (see
> [`.github/workflows/ci.yaml`](.github/workflows/ci.yaml)) fails the build
> if anything that looks like a credential lands in a tracked path.

`coauth` is the Arkret Auth / Account Server. It provides OIDC/OAuth login,
account lifecycle management, short-lived session grants, policy hooks,
notifications, and a stable admin API for Arkret deployments.

`coauth` is not a DID registry. It proves who authenticated to which local
account, device, and session, then publishes that state to Principal Servers
and admin tooling. DID documents, key logs, and registry receipts belong to
delegated/public DID resolver services.

## Realm vs Space

Sessions, capabilities, and admin scopes attach to a **Realm** (the security
boundary). Navigation containers — **Space** in the new vocabulary — sit
inside a Realm and inherit its auth context.

- **Realm:** membership, capability, E2EE, federation are governed here.
- **Space:** board, list, section, or calendar bucket inside a Realm.

## Trust domain rotation

Round R2/R3 (2026-05-20) introduces the deployment-level `trust_domain`
config knob (`arkret.trust_domain` in `config.yaml`):

```yaml
arkret:
  trust_domain: ck:trust_domain:soland-prod.eu
```

The value MUST match `ck:trust_domain:<scope>` where `<scope>` is
`[a-z0-9._:-]{1,128}` and starts with `[a-z0-9]`. coauth validates it
on load via `CokretConfig::validate_trust_domain` (mirrors the SDK's
`TypedTrustDomainId` acceptance rules) and injects it into the Realm
policy + `/_arkret/describe` document via soland's config API.

**Rotation is wire-breaking for existing cross-signing reset proofs.**
The `trust_domain` value enters the canonical transcript of every
`ck.cross_signing.reset` proof (see
`arkret_core::round23::CrossSigningResetPayload`). Changing it
invalidates all previously-issued `principal_signing` /
`recovery_unlock` / `device_quorum` / `trusted_recovery_service`
proofs. Operators MUST roll fresh proofs through the device-lifecycle
recovery strand as part of the rotation.

## OOB invite code form (Round R2/R3 — T15)

`coauth` mints third-party invite OOB codes in one of two configurable
forms. Deployments choose per `auth.oob_code_kind`:

- **`offline_verifiable`** (default) — 27-char restricted-base32 token
  (excludes `I`, `L`, `0`, `1`, `O`), ≥128-bit entropy, no server
  lookup needed for entropy proof.
- **`lookup`** — 6-char human-typeable code paired with a server-side
  HMAC-SHA256 pepper, `oob_code_kind="lookup"` advertised on the wire,
  3-strike invalidation per code.

Both forms run the same 7-trigger non-enumerable failure state machine
(byte-identical `{"error":"not_found"}` body, ≤50 ms constant-time
padding) so external observers cannot distinguish "expired" from
"never existed". The normative source is the v1 spec under
[`../arkret-spec/spec/v1/`](../arkret-spec/spec/v1/).

## Round R4 (protocol review closures)

Spec round 4 layers on top of the R2/R3 trust-domain and OOB-invite work.
The canonical wire-breaking list lives in the v1 spec artifacts and prose
under [`../arkret-spec/spec/v1/`](../arkret-spec/spec/v1/).

- **3PID OOB invite has two wire modes.** Either `offline_token`
  (`token_commitment` + `token_salt_id` + `token_entropy_bits ≥ 128`,
  default) or `lookup` (`lookup_table_ref` + `pepper_id`, 3-strike
  invalidation). Plaintext 3PIDs are no longer carried on the wire. Both
  modes share the 5-terminal-state machine (`claimed` / `send_failed` /
  `revoked_by_capability_loss` / `revoked_by_inviter_left` /
  `invalidated_by_rate_limit`); salt / pepper are zeroized within 24h.
- **`ck.cross_signing.publish` CAS** — publisher reads the current
  generation and submits `expected_previous_generation`; new generation
  is strictly `current + 1`.
- **`/policy/check` v2** — request switches to `PolicyCheckRequestBody`
  (`signed_transport` + `source_ip_digest` + `source.{service_did,
  service_type}`); response is `PolicyCheckOutcome` carrying the
  `bound_to{realm_id, actor_id, action, request_canonical_digest,
  policy_server_id}` envelope plus `auth_state_digest` /
  `policy_frontier_digest` / `membership_frontier_digest` and a signed
  `kid: did:.+#.+`.
- **identity_link is Realm-scoped** — encrypted payload now binds
  `realm_id` + `trust_domain`.

## Cross-project task tracking

Per-project task lists are maintained outside this repository. Protocol
work that affects wire shape is tracked in [`../arkret-spec/spec/v1/`](../arkret-spec/spec/v1/).

## Integration model

- `inkson` acts as a public/native Arkret client and consumes OIDC tokens.
- Principal Servers such as `soland` consume session grants and account
  metadata from `coauth`.
- `sodmin` uses the admin API with `urn:coauth:admin` or
  `urn:arkret:admin:*`.
- A delegated/public DID resolver remains the identity registry / resolver source.

## Current status

The primary Arkret paths include:

- `/.well-known/openid-configuration`
- `/_arkret/describe`
- `/_arkret/root/identity/describe`
- `/_arkret/find/directory/resolve-handle`

coauth hosts **no** DID documents (`/.well-known/did.json`, `/did.json`, and
`/users/{id}/did.json` were removed): DID hosting is the principal server's
job — soland's embedded webvh provider (or an external starid) serves
`did:webvh` documents under its own authority, and coauth only mints/registers
against it. coauth-issued artefacts (session grants, handle claims) are
verified via the introspection endpoints and the OAuth JWKS.

## Features

- OpenID Connect provider with authorization code, refresh token, client
  credentials, and device code grants
- Arkret discovery, service DID documents, handle resolution, and short-lived
  session grants with Principal Server introspection
- Local account lifecycle, password auth, upstream OAuth federation, and
  recovery workflows
- Admin APIs for sessions, tokens, users, clients, templates, connectors, and
  policy data
- Email / SMS notification runtime, rate limiting, CAPTCHA hooks, telemetry,
  and policy enforcement

## Quick start

### 1. Generate configuration

```bash
coauth config generate > config.yaml
```

### 2. Fill in the deployment-specific sections

```yaml
http:
  public_base: https://auth.example.com/

database:
  uri: postgresql://coauth:password@localhost/coauth

arkret:
  principal_servers:
    - name: soland
      audience: did:webvh:<scid>:soland.example.com:webvh:service
      endpoint: https://soland.example.com/
      did: did:webvh:<scid>:soland.example.com:webvh:service
  identity_registry:
    kind: public_did_resolver
    resolver: https://resolver.example.com/
    proof_required_for_pairwise: true
  service_did: did:webvh:<scid>:auth.example.com:webvh:service
  issuer_did: did:webvh:<scid>:auth.example.com:webvh:service
  admin_audience: https://auth.example.com/_arkret

secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: ./keys/signing.pem

passwords:
  enabled: true
```

### 3. Start the server

```bash
coauth server -c config.yaml
```

This runs migrations, syncs config-backed state, starts the HTTP service, and
launches the background worker unless disabled with flags.

## Build from source

`coauth` is a Rust workspace. The frontend is a Dioxus app.

```bash
git clone https://github.com/arkret/coauth.git
cd coauth

# Backend binary only. The default configuration uses the Cedar policy engine.
cargo build --release -p coauth --features cedar

# Full production build with web assets (requires `just` and `dx`)
just build-all
```

## Key endpoints

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/_arkret/describe` | Arkret service metadata |
| `/_arkret/root/identity/describe` | Identity-registry contract |
| `/_arkret/find/directory/resolve-handle` | Handle -> DID resolution |
| `/_arkret/gate/account/session-grants/introspect` | Principal Server session grant validation |
| `/_coauth/admin/*` | Admin API for `sodmin` and service automation |
| `/_coauth/admin/openapi.yaml` | Coauth admin API OpenAPI document |
| `/.well-known/arkret/openapi.yaml` | Admin API discovery document for `sodmin` |

## Documentation

- English configuration reference: [docs/en/reference/configuration.md](docs/en/reference/configuration.md)
- English scope reference: [docs/en/reference/scopes.md](docs/en/reference/scopes.md)
- Chinese configuration reference: [docs/zh/reference/configuration.md](docs/zh/reference/configuration.md)
- Chinese scope reference: [docs/zh/reference/scopes.md](docs/zh/reference/scopes.md)

## Production Deployment Checklist

Before exposing coauth to the public internet, walk every item below.
The same list will be computed at runtime and surfaced on
`/health.hardening` so sodmin's `/hardening` dashboard can flag failing
checks across the whole fleet (see T8.3 for the cross-service shape).

- [ ] `COAUTH_DEVELOPMENT_MODE=false` (or unset in production builds)
- [ ] TLS enabled at the reverse proxy (`COAUTH_TLS_CERT_PATH` / `COAUTH_TLS_KEY_PATH` when terminated in-process)
- [ ] CSP header configured at the reverse proxy
- [ ] CORS limited to the allowed origins for sodmin / public clients
- [ ] Secrets in a secret manager (session-grant signing seed, OAuth client secrets, upstream provider creds)
- [ ] Log redaction enabled (default outside dev mode)
- [ ] Admin auth in production mode (admin capabilities + scopes, no dev-login)
- [ ] Rate limit enabled
- [ ] Provider credential rotation scheduled for upstream OAuth providers

## License

`coauth` is distributed under `AGPL-3.0-only`. See [LICENSE](LICENSE).

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_coauth_todos.md` in the parent `arkret/` directory for the
> circle-rollout (CKP-0007) work item list and per-stage checkpoints.
