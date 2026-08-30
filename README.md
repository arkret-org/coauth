# coauth

> **Normative protocol source**: [arkret-spec v1](../arkret-spec/spec/v1/)

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` and `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/pre-commit` is missing on a
branch, copy it from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk) and
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
account, device, and session, then publishes that state to Stations
and admin tooling. DID documents, key logs, and registry receipts belong to
delegated/public DID resolver services.

## Realm vs Space

Sessions, capabilities, and admin scopes attach to a **Realm** (the security
boundary). Navigation containers — **Space** in the new vocabulary — sit
inside a Realm and inherit its auth context.

- **Realm:** membership, capability, E2EE, federation are governed here.
- **Space:** board, list, section, or calendar bucket inside a Realm.

## Trust domain rotation

The deployment-level `trust_domain` config knob is
`arkret.trust_domain` in `config.yaml`:

```yaml
arkret:
  trust_domain: ak:trust_domain:soland-prod.eu
```

The value MUST match `ak:trust_domain:<scope>` where `<scope>` is
`[a-z0-9._:-]{1,128}` and starts with `[a-z0-9]`. coauth validates it
on load via `ArkretConfig::validate_trust_domain` (mirrors the SDK's
`TrustDomainId` acceptance rules) and injects it into the Realm
policy + `/_arkret/describe` document via soland's config API.

The `trust_domain` value binds peer and recovery authorization
transcripts to this deployment. Rotate it only with coordinated expiry
of in-flight proofs and sessions issued under the prior value.

## Current protocol behavior

The canonical wire behavior lives in the v1 spec artifacts and prose under
[`../arkret-spec/spec/v1/`](../arkret-spec/spec/v1/).

- **3PID OOB invite has two wire modes.** Either `offline_token`
  (`token_commitment` + `token_salt_id` + `token_entropy_bits ≥ 128`,
  default) or `lookup` (`lookup_table_ref` + `pepper_id`, 3-strike
  invalidation). Plaintext 3PIDs are no longer carried on the wire. Both
  modes share the 5-terminal-state machine (`claimed` / `send_failed` /
  `revoked_by_capability_loss` / `revoked_by_inviter_left` /
  `invalidated_by_rate_limit`); salt / pepper are zeroized within 24h.
- **identity_link is Realm-scoped** — encrypted payload now binds
  `realm_id` + `trust_domain`.

## Cross-project task tracking

Per-project task lists are maintained outside this repository. Protocol
work that affects wire shape is tracked in [`../arkret-spec/spec/v1/`](../arkret-spec/spec/v1/).

## Integration model

- `inkson` acts as a public/native Arkret client and consumes OIDC tokens.
- Stations such as `soland` consume session grants and account
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
`/users/{id}/did.json` were removed): DID hosting is the Station's
job — soland's embedded webvh provider serves
`did:webvh` documents under its own authority, and coauth only mints/registers
against it. coauth-issued artefacts (session grants, handle claims) are
verified via the introspection endpoints and the OAuth JWKS.

## Features

- OpenID Connect provider with authorization code, refresh token, client
  credentials, and device code grants
- Arkret discovery, service DID documents, handle resolution, and short-lived
  session grants with Station introspection
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
  public_base_url: https://auth.example.com/

database:
  uri: postgresql://coauth:password@localhost/coauth

arkret:
  stations:
    - name: soland
      endpoint: https://soland.example.com/
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
  identity_registry:
    resolver: https://resolver.example.com/
    proof_required_for_pairwise: true
  admin_audience: ak:did_core:web:auth.example.com

secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: ./keys/signing.pem

passwords:
  enabled: true
```

Coauth resolves and persists its service DID through the one configured
registration-capable entry. A standalone Provider uses the product-neutral
`identity_services[]` shape (`name`, `endpoint`, `registration_bearer`). If
more than one entry can register identities, set `arkret.identity_provider` to
the selected entry name.

### 3. Start the server

```bash
coauth server -c config.yaml
```

This runs migrations, syncs config-backed state, starts the HTTP service, and
launches the background worker unless disabled with flags.

## Build from source

`coauth` is a Rust workspace. The frontend is a Dioxus app.

```bash
git clone https://github.com/arkret-org/coauth.git
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
| `/_arkret/gate/account/session-grants/introspect` | Station session grant validation |
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
This is an operator checklist, not a runtime health endpoint. Use `/healthz`,
`/readyz`, and `/metrics` for automated monitoring, and see the
[deployment hardening guide](docs/en/topics/deployment_hardening.md) for
rollout details.

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
