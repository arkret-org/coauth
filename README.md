# coauth

`coauth` is the Contrix Auth / Account Server. It provides OIDC/OAuth2 login,
account lifecycle management, short-lived session grants, policy hooks,
notifications, and a stable admin API for Contrix deployments.

`coauth` is not a DID registry. It proves who authenticated to which local
account, device, and session, then publishes that state to Principal Servers
and admin tooling. DID documents, key logs, and registry receipts belong to
delegated/public DID resolver services.

## Integration model

- `chask` acts as a public/native Contrix client and consumes OIDC tokens.
- Principal Servers such as `soland` consume session grants and account
  metadata from `coauth`.
- `sodmin` uses the admin API with `urn:coauth:admin` or
  `urn:contrix:admin:*`.
- A delegated/public DID resolver remains the identity registry / resolver source.
- Matrix / Palpo support remains available as a legacy compatibility adapter,
  not the primary product path.

## Current status

The repository is still migrating away from older Pasion / Matrix assumptions.
The primary Contrix paths already include:

- `/.well-known/openid-configuration`
- `/.well-known/did.json`
- `/api/v1/server/describe`
- `/api/v1/identity/describe`
- `/api/v1/directory/resolve-handle`

Some legacy naming and compatibility code still exists in non-primary paths.
Track the remaining work in [`_todos.md`](_todos.md).

## Features

- OpenID Connect provider with authorization code, refresh token, client
  credentials, and device code grants
- Contrix discovery, service DID documents, handle resolution, and short-lived
  session grants with Principal Server introspection
- Local account lifecycle, password auth, upstream OAuth2 federation, and
  recovery workflows
- Admin APIs for sessions, tokens, users, clients, templates, connectors, and
  policy data
- Email / SMS notification runtime, rate limiting, CAPTCHA hooks, telemetry,
  and policy enforcement
- Legacy Matrix / Palpo compatibility adapter for deployments that still need
  delegated-auth bridging

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

contrix:
  principal_servers:
    - name: soland
      audience: https://soland.example.com/api
      endpoint: https://soland.example.com/
      did: did:web:soland.example.com
  identity_registry:
    kind: public_did_resolver
    resolver: https://resolver.example.com/
    proof_required_for_pairwise: true
  service_did: did:web:auth.example.com
  issuer_did: did:web:auth.example.com
  admin_audience: https://auth.example.com/api/v1

secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: ./keys/signing.pem

passwords:
  enabled: true

matrix:
  homeserver: matrix.example.com
  secret: legacy-shared-secret
  endpoint: https://matrix.example.com/
```

`matrix` is still present in the config model because the compatibility adapter
has not been fully split into a separate profile yet. Treat it as legacy
integration config unless you are actively serving Matrix / Palpo flows.

### 3. Start the server

```bash
coauth server -c config.yaml
```

This runs migrations, syncs config-backed state, starts the HTTP service, and
launches the background worker unless disabled with flags.

## Build from source

`coauth` is a Rust workspace. The frontend is a Dioxus app.

```bash
git clone https://github.com/meldry-com/coauth.git
cd coauth

# Backend binary only
cargo build --release -p coauth

# Full production build with web assets (requires `just` and `dx`)
just build-all
```

## Key endpoints

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/.well-known/did.json` | Service DID document |
| `/api/v1/server/describe` | Contrix service metadata |
| `/api/v1/identity/describe` | Identity-registry contract |
| `/api/v1/directory/resolve-handle` | Handle -> DID resolution |
| `/api/v1/session-grants/introspect` | Principal Server session grant validation |
| `/api/admin/v1/*` | Admin API for `sodmin` and service automation |
| `/api/admin/v1/openapi.yaml` | Contrix admin API OpenAPI document |
| `/.well-known/contrix/openapi.yaml` | Admin API discovery document for `sodmin` |

## Documentation

- English configuration reference: [docs/en/reference/configuration.md](docs/en/reference/configuration.md)
- English scope reference: [docs/en/reference/scopes.md](docs/en/reference/scopes.md)
- Chinese configuration reference: [docs/zh/reference/configuration.md](docs/zh/reference/configuration.md)
- Chinese scope reference: [docs/zh/reference/scopes.md](docs/zh/reference/scopes.md)

## License

`coauth` is distributed under `AGPL-3.0-only`. See [LICENSE](LICENSE).
