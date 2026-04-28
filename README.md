# Pasion

An identity, notification, operations, and integration platform for [Palpo](https://palpo.im/) Matrix homeservers.

## Overview

Pasion is a comprehensive user operations platform built for Palpo. While it implements OAuth 2.0 and OpenID Connect for standards-based authentication ([MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861)), Pasion goes well beyond a conventional auth service. It provides a workflow engine for managing user lifecycle operations, a unified notification center for multi-channel dispatch, a connector platform for external system integration, and a dual policy engine for fine-grained access control.

### Key Features

- **Workflow Engine** — Registration, recovery, and verification flows managed as state machines with step tracking, deadlines, retry logic, and audit snapshots
- **Unified Notification Center** — Email + SMS dispatch with provider abstraction (SMTP, Sendmail, Resend, SendGrid, Twilio SendGrid, Brevo, AWS SES for email; Twilio, Aliyun SMS, and Tencent Cloud SMS for messaging)
- **Connector Platform** — Pluggable external system integration: Palpo Matrix homeserver provisioning and upstream OAuth 2.0 identity provider federation
- **Chinese Ecosystem SSO** — Native support for QQ, WeChat, WeCom, Feishu, Lark, and DingTalk with their non-standard OAuth2 flows
- **Cedar + OPA Policy Engine** — Dual policy backend: Amazon Cedar policies evaluated natively in Rust, OPA/Rego compiled to WebAssembly, or remote HTTP delegation
- **Dioxus Frontend** — Full-Rust SPA built with Dioxus (no TypeScript or React)
- **Admin Operational API** — User management, session oversight, OAuth 2.0 client administration, upstream provider management, and policy data control
- **Multi-Channel Verification** — Email and SMS verification codes with configurable templates, language selection, and background job dispatch
- **OAuth 2.0 & OpenID Connect** — Full OIDC Provider with authorization code, client credentials, and device code grant flows
- **Security** — Argon2id password hashing, encrypted cookies, rate limiting, CAPTCHA support
- **Observability** — OpenTelemetry tracing and Prometheus metrics export
- **Internationalization** — Multi-language UI with configurable templates

## Quick Start

### 1. Install

**Pre-built Binaries (Linux)**

```bash
curl -sL https://github.com/contrix-dev/coauth/releases/latest/download/coauth-x86_64-linux.tar.gz | tar xz
mv coauth /usr/local/bin/
```

**Docker**

```bash
docker pull ghcr.io/contrix-dev/coauth:latest
```

**From Source**

```bash
git clone https://github.com/contrix-dev/coauth.git
cd coauth
cd front && npm ci && npm run build && cd ..
cargo build --release
```

### 2. Prepare Database

```sql
CREATE USER coauth WITH PASSWORD 'your_password';
CREATE DATABASE coauth WITH OWNER coauth;
```

### 3. Generate and Edit Configuration

```bash
coauth config generate > config.yaml
# Edit config.yaml — see Configuration section below
```

### 4. Start the Server

```bash
coauth server -c config.yaml
```

This single command will automatically run database migrations, start the HTTP server, and launch the background task worker.

## Configuration

Pasion uses a YAML configuration file. Key sections:

```yaml
# Public-facing URL
http:
  public_base: https://auth.example.com/
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      resources:
        - name: discovery     # OIDC discovery endpoints
        - name: human         # Login / registration UI
        - name: oauth         # OAuth 2.0 endpoints
        - name: health        # Health check
        - name: assets        # Static frontend assets

# Database connection
database:
  uri: postgresql://coauth:password@localhost/coauth

# Matrix homeserver integration
matrix:
  homeserver: matrix.example.com
  secret: "shared-secret-with-homeserver"
  endpoint: "https://matrix.example.com"

# Encryption and signing keys
secrets:
  encryption: "base64-encoded-32-byte-key"
  keys:
    - kid: "key-id-1"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----

# Password authentication
passwords:
  enabled: true
  schemes:
    - version: 1
      algorithm: argon2id

# Upstream SSO providers (optional)
upstream_oauth2:
  providers:
    - id: "01HFRQFT5QFBM3Y5BHNFHMP6M0"
      issuer: "https://accounts.google.com"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      token_endpoint_auth_method: client_secret_post
      scope: "openid email profile"

# Email (optional, for verification and recovery)
email:
  from: '"Pasion" <noreply@example.com>'
  provider:
    type: resend
    api_key: "re_xxxxxxxxx"
    # Supported types: smtp, sendmail, resend, sendgrid, twilio, brevo, aws_ses, http_webhook

# SMS (optional, for phone verification and messaging)
sms:
  provider:
    type: twilio
    account_sid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    auth_token: "your-auth-token"
    from_number: "+12065550123"
```

See the [full configuration reference](docs/en/reference/configuration.md) for all options.

When registering a Google / GitHub / other upstream OAuth app, the callback URL is always derived from `http.public_base`:

```text
<http.public_base>/upstream/callback/<provider-id>
```

For example, if `http.public_base` is `https://auth.example.com/coauth/`, the callback for provider `01JABCDEF0123456789ABCDEFG` is `https://auth.example.com/coauth/upstream/callback/01JABCDEF0123456789ABCDEFG`.

## Architecture

Pasion is deployed alongside a Palpo Matrix homeserver behind a reverse proxy. Internally, HTTP requests flow through handler layers into workflow services, which coordinate across storage repositories, external connectors (Palpo Matrix, upstream OAuth 2.0 providers), and the notification center (email/SMS). The policy engine evaluates access decisions at each control point.

```
              ┌───────────────┐
 Users ──────>│ Reverse Proxy │ (TLS termination)
              └───────┬───────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼────┐  ┌────▼─────┐  ┌──▼──────────┐
    │ Pasion  │  │  Palpo   │  │   Static    │
    │  :8080  │  │ (Matrix) │  │   Assets    │
    └────┬────┘  │  :8008   │  └─────────────┘
         │       └──────────┘
         │
         │  ┌─────────────────────────────────────┐
         │  │          Pasion Internals            │
         │  │                                     │
         │  │  HTTP Handlers                      │
         │  │    ├── Workflow Engine               │
         │  │    │     (registration, recovery,    │
         │  │    │      verification state machines)│
         │  │    ├── Notification Center           │
         │  │    │     (email + SMS dispatch)       │
         │  │    ├── Connectors                    │
         │  │    │     (Palpo Matrix, upstream SSO) │
         │  │    └── Policy Engine                 │
         │  │          (Cedar / OPA / Remote)       │
         │  └─────────────────────────────────────┘
         │
    ┌────▼──────┐
    │ PostgreSQL │
    └───────────┘
```

### Palpo Homeserver Configuration

Configure Palpo to delegate authentication to Pasion:

```yaml
experimental_features:
  msc3861:
    enabled: true
    issuer: https://auth.example.com/
    client_id: 0000000000000000000PALPO
    client_auth_method: client_secret_basic
    client_secret: "your-secret"
    admin_token: "admin-token"
    account_management_url: "https://auth.example.com/account/"
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `coauth server -c config.yaml` | Start the HTTP server (default) |
| `coauth config generate` | Generate a default configuration file |
| `coauth config check -c config.yaml` | Validate configuration |
| `coauth config sync -c config.yaml` | Sync OAuth clients / upstream providers to the database |
| `coauth database migrate -c config.yaml` | Run database migrations manually |
| `coauth manage register-user` | Create a new user |
| `coauth manage set-password` | Set or reset a user's password |
| `coauth manage promote-user` | Promote a user to admin |
| `coauth worker -c config.yaml` | Run background task worker separately |
| `coauth doctor -c config.yaml` | Check deployment health |

### Server Options

```bash
coauth server -c config.yaml                # Full startup (default)
coauth server -c config.yaml --no-worker    # HTTP only, no background worker
coauth server -c config.yaml --no-migrate   # Skip automatic DB migrations
coauth server -c config.yaml --no-sync      # Skip config sync to DB
```

## Upstream SSO Providers

Pasion supports federation with external identity providers. Any standard OIDC provider works out of the box. Additionally, dedicated support is provided for these Chinese platforms with non-standard OAuth2 flows:

| Provider | `token_endpoint_auth_method` | Notes |
|----------|------------------------------|-------|
| Google, GitLab, Keycloak, Authentik, etc. | `client_secret_post` / `client_secret_basic` | Standard OIDC |
| GitHub | `client_secret_post` | OAuth 2.0 with manual authorization, token, and userinfo endpoints |
| Apple | `sign_in_with_apple` | Apple-specific JWT client secret |
| QQ | `qq_connect` | Non-standard token + separate OpenID endpoint |
| WeChat | `wechat` | Uses `appid`/`secret`, token includes `openid` |
| WeCom | `wecom` | Corp access token + user identity resolution |
| Feishu | `feishu` | Two-step: app_access_token then user token |
| Lark | `lark` | International Feishu, same flow with different endpoints |
| DingTalk | `dingtalk` | JSON body + custom access token header |

See the [SSO setup guide](docs/en/setup/sso.md) for provider-specific configuration examples.

## Production Deployment

For production, consider separating the HTTP server and background workers:

```bash
# HTTP server (can be load-balanced)
coauth server --no-worker -c config.yaml

# Background workers (can run multiple instances)
coauth worker -c config.yaml
```

Key endpoints exposed by the server:

| Endpoint | Purpose |
|----------|---------|
| `/health` | Health check |
| `/healthz` | Health check alias |
| `/metrics` | Prometheus metrics |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/oauth2/authorize` | OAuth 2.0 authorization |
| `/oauth2/token` | Token endpoint |
| `/api/admin/v1/*` | Admin API |

## Documentation

Full documentation is available at <https://palpo-im.github.io/coauth/>.

| Section | Description |
|---------|-------------|
| [Installation](docs/en/setup/installation.md) | Install and configure Pasion |
| [General Setup](docs/en/setup/general.md) | Basic configuration walkthrough |
| [Database](docs/en/setup/database.md) | Database setup and migrations |
| [Homeserver](docs/en/setup/homeserver.md) | Palpo / Matrix integration |
| [Reverse Proxy](docs/en/setup/reverse-proxy.md) | nginx / Caddy configuration |
| [SSO](docs/en/setup/sso.md) | Upstream identity provider setup |
| [Configuration Reference](docs/en/reference/configuration.md) | Full configuration options |
| [CLI Reference](docs/en/reference/cli/) | Command-line tool documentation |
| [Admin API](docs/en/topics/admin-api.md) | Manage users and sessions via API |
| [Architecture](docs/en/development/architecture.md) | Internal design and crate structure |
| [Contributing](docs/en/development/contributing.md) | How to contribute to the project |

## Requirements

- **PostgreSQL** 17 or later
- **Palpo** homeserver 0.2.1 or later (or any compatible Matrix homeserver)
- A reverse proxy (nginx, Caddy, etc.) for TLS termination

## License

Pasion is distributed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`). See [LICENSE](LICENSE).

Some files retain upstream copyright and notice headers where required.
