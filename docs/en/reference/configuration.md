# Configuration file reference

`coauth` uses a YAML configuration file. Generate a complete example with:

```sh
coauth config generate > config.yaml
```

The generated schema in `docs/config.schema.json` is derived from
`coauth_config::RootConfig`. Environment overrides use the `COAUTH_` prefix.

## `http`

Controls public URLs, listeners, and which route groups are exposed.

```yaml
http:
  public_base_url: https://auth.example.com/
  issuer: https://auth.example.com/
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: restapi
        - name: assets
          path: ./dist
        - name: adminapi  # admin API
```

### `http.listeners`

Common resource names:

- `discovery` for `/.well-known/*`
- `human` for browser-facing pages
- `oauth` for OAuth / OIDC endpoints
- `restapi` for the SPA/API backend
- `assets` for frontend assets
- `adminapi` for `/_coauth/admin/*`
- `health` for `/health`, `/healthz`, and `/readyz` probes
- `prometheus` for `/metrics`

### Request limits and timeouts

| Key | Default | Purpose |
| --- | --- | --- |
| `http.max_body_bytes` | `1048576` (1 MiB) | Maximum accepted request-body size. Matches the Arkret `ak.server.read.describe.limits.max_body_bytes` advertisement. |
| `http.request_timeout_seconds` | `30` | Per-request handling deadline. Set to `0` to disable. |
| `http.shutdown_grace_seconds` | `30` | Grace period granted to in-flight requests on SIGTERM/SIGINT. |
| `http.trusted_proxies` | RFC1918 + loopback | CIDR ranges trusted to set `X-Forwarded-For`. See [reverse-proxy](../setup/reverse-proxy.md). |
| `http.csp_html` | conservative `'self'`-only policy | `Content-Security-Policy` value emitted on HTML responses (JSON / asset responses are unaffected). Set to an empty string to suppress, or override to relax/tighten. |

## `database`

PostgreSQL connection settings.

```yaml
database:
  uri: postgresql://coauth:password@localhost/coauth
  min_connections: 0
  max_connections: 10
  connect_timeout: 30
```

`coauth` should not be pointed at a transaction-pooled pgBouncer / pgCat
deployment because the service uses PostgreSQL features that require session
semantics.

## `arkret`

Arkret-specific deployment metadata layered on top of the generic OIDC server.

```yaml
arkret:
  deployment_profile: organization
  principal_method: did:webvh

  stations:
    - name: soland
      endpoint: https://soland.example.com/
      service_id: ak:did_core:webvh:<soland-scid>
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}

  identity_registry:
    resolver: https://resolver.example.com/
    proof_required_for_pairwise: true

  admin_audience: ak:did_core:web:auth.example.com
  session_grant_ttl: 300
```

- `stations`: trusted Station configuration; operations
  authenticating that service require an authorization pin — an explicit
  `service_id` or a trust enrollment persisted by
  `coauth station trust bootstrap` — and fail closed without one;
  Describe cannot act as identity discovery or an authorization root
- `deployment_profile`: identity deployment profile. `did:web` principal DIDs
  are accepted only for `personal_node`.
- `principal_method`: principal DID method. Defaults to `did:webvh`; `did:web`
  must be explicitly paired with `deployment_profile: personal_node`.
- `identity_registry`: delegated DID / identity resolver, typically a public DID resolver service
- Coauth resolves, registers, and persists its service DID through the configured Provider;
  configuration never accepts a DID.
- Station audiences and DIDs are pinned by configuration or by the
  persisted trust enrollment; `/_arkret/describe` is only used for online
  identity-chain verification during bootstrap and revalidation.
- `admin_audience`: audience expected by Arkret admin integrations, as a
  `did_core_id`; defaults to this deployment's own runtime service core id
- `session_grant_ttl`: lifetime in seconds for Arkret session-grant JWTs
  returned by the REST auth bridge login/exchange paths and refresh endpoint.
  Default: `300` (5 minutes).

## `templates`

Optional overrides for the HTML template and translation file paths.

```yaml
templates:
  path: ./templates
  translations_path: ./translations
```

## `clients`

Static OAuth / OIDC client registrations that are synchronized into the
database.

```yaml
clients:
  - client_id: 01HFVBY12TMNTYTBV8W921M5FA
    client_auth_method: client_secret_post
    client_secret: super-secret
    redirect_uris:
      - https://app.example.com/callback
```

## `secrets`

Encryption and signing keys.

```yaml
secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: ./keys/signing.pem
```

At least one signing key should be configured. `coauth` uses these keys for ID
tokens, signed userinfo responses, JWKS publication, and Arkret session
grants.

## `passwords`

Local password-login settings.

```yaml
passwords:
  enabled: true
  minimum_complexity: 3
  schemes:
    - version: 1
      algorithm: argon2id
```

## `account`

Self-service account-management options.

```yaml
account:
  email_change_allowed: true
  displayname_change_allowed: true
  password_registration_enabled: false
  password_registration_contact_required: true
  registration_email_delivery_bypass_allowed: false
  password_change_allowed: true
  password_recovery_enabled: false
  account_deactivation_allowed: true
  login_with_email_allowed: false
  admin_portal_url: https://admin.example.com/
  registration_token_required: false
  bootstrap_admin_token: null
```

`bootstrap_admin_token` is an optional one-time bootstrap secret for the first
administrator. When it is set and no admin user exists yet, the registration
finish page asks for the token; a matching token marks that new account as an
admin. Registrations without the token still complete as regular users, and
the token stops granting admin access after any admin exists.

Environment override example:

```sh
COAUTH_ACCOUNT__BOOTSTRAP_ADMIN_TOKEN=bootstrap-secret
```

## `captcha`

CAPTCHA protection for login, recovery, registration, or other abuse-sensitive
 strands.

```yaml
captcha:
  service: recaptcha_v2
  site_key: "site-key"
  secret_key: "secret-key"
```

## `policy`

Authorization policy engine configuration.

```yaml
policy:
  engine: cedar
  cedar_policy_file: ./policies/cedar/default.cedar
```

The project currently supports Cedar natively and can optionally delegate to a
remote policy service when the matching feature is compiled in.

## `rate_limiting`

Rate limits for login, recovery, registration, and similar workflows.

```yaml
rate_limiting:
  login:
    per_ip:
      burst: 3
      per_second: 0.05
    per_account:
      burst: 1800
      per_second: 0.5
  identity_resolution:
    per_ip:
      burst: 60
      per_second: 1.0
```

`identity_resolution` independently limits public DID resolve/document reads.
The default is 60 requests per source IP per minute and does not share a
bucket with handle-directory lookups.

## `telemetry`

Tracing, metrics, and Sentry error reporting.

```yaml
telemetry:
  tracing:
    exporter: otlp
    endpoint: https://otel.example.com:4318
  metrics:
    exporter: prometheus
  sentry:
    dsn: https://public@host/1
```

Prometheus metrics can also be exposed on a dedicated listener with
`COAUTH_METRICS_BIND`, for example `COAUTH_METRICS_BIND=127.0.0.1:9091`.
See [Observability](../observability.md) for OTLP collector examples and
Prometheus scraping options.

## `email`

Outbound email delivery settings.

```yaml
email:
  from: '"coauth" <noreply@example.com>'
  provider:
    type: resend
    api_key: re_xxxxxxxxx
```

Supported provider families include `blackhole`, `smtp`, `sendmail`, `resend`,
`sendgrid`, `twilio`, `brevo`, `aws_ses`, and `http_webhook`.

## `sms`

Outbound SMS delivery settings.

```yaml
sms:
  provider:
    type: twilio
    account_sid: ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    auth_token: your-auth-token
    from_number: "+12065550123"
```

## `upstream_oauth`

Trusted upstream OAuth / OIDC providers for federation.

```yaml
upstream_oauth:
  providers:
    - id: 01HFVBY12TMNTYTBV8W921M5FA
      issuer: https://accounts.google.com
      client_id: your-client-id
      client_secret: your-client-secret
      token_endpoint_auth_method: client_secret_post
      scope: "openid email profile"
```

This section is synced into the database on startup in the same way as
`clients`.

## `branding`

Service name, logos, footer links, privacy policy, and terms-of-service links.

```yaml
branding:
  service_name: Example Auth
  logo_uri: https://assets.example.com/logo.svg
  policy_uri: https://example.com/privacy
  tos_uri: https://example.com/terms
```

## `experimental`

Feature flags and tunables that may still move or change shape.

```yaml
experimental:
  access_token_ttl: 300
```

## `storage`

File or object-storage backend settings for uploaded assets and future binary
artifacts.

```yaml
storage:
  backend: fs
```
