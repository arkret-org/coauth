# coauth — Deployment Guide

> Spec target: cokret-spec @ b47ff6ec (R3 sync 2026-05-27)

## Overview

`coauth` is the organization-deploy auth / DID-binding service that complements `soland` (Principal Server). This guide covers the supported deployment paths.

## Prerequisites

- PostgreSQL 14+ (primary) — `coauth-backend` uses Diesel migrations.
- Optional: OIDC upstream provider (Keycloak, Auth0, Azure AD, etc.) for `cx.account.oidc_*` flows.
- Optional: HSM / KMS for signing keys (production).
- Rust toolchain matching workspace MSRV (see root `Cargo.toml`).

## Configuration

Configuration lives in `config.example.yaml` (committed) — copy to `config.local.yaml` and adjust:

```yaml
listen_addr: "0.0.0.0:7080"
database_url: "postgres://coauth:coauth@localhost:5432/coauth"
trust_domain: "acme.example"
oidc:
  upstream:
    - provider_id: "primary"
      issuer: "https://idp.acme.example"
      client_id: "${OIDC_CLIENT_ID}"
      client_secret: "${OIDC_CLIENT_SECRET}"
soland:
  base_url: "https://soland.acme.example"
```

Secrets (OIDC client secret, signing keys, DB password) MUST come from environment variables, sealed secrets, or a secrets manager — NEVER committed `.env`.

## Database bootstrap

```sh
# Create role + database
sudo -u postgres psql <<'SQL'
CREATE ROLE coauth WITH LOGIN PASSWORD 'changeme';
CREATE DATABASE coauth OWNER coauth;
SQL

# Run migrations (Diesel)
diesel setup --database-url "$DATABASE_URL"
diesel migration run --database-url "$DATABASE_URL"
```

Migrations are idempotent and located under `crates/backend/migrations/`.

### Backup / restore

```sh
# Hot backup (logical)
pg_dump -Fc -h "$PG_HOST" -U coauth coauth > coauth.$(date +%F).dump

# Restore to a fresh DB
pg_restore --clean --if-exists -d coauth coauth.YYYY-MM-DD.dump
```

For PITR-class recovery use `pg_basebackup` + WAL archiving; see PostgreSQL ops docs.

## Helm deployment

A reference chart lives at `charts/coauth/` with values defaults at `charts/coauth/values.yaml`:

```sh
kubectl create secret generic coauth-db \
  --namespace cokret-system \
  --from-literal=url="postgres://coauth:$(vault read -field=password secret/coauth/db)@pg.acme.example/coauth"

helm upgrade --install coauth charts/coauth \
  --namespace cokret-system --create-namespace \
  --set database.urlSecret=coauth-db \
  --set image.tag=$(git rev-parse --short HEAD)
```

Defaults:
- `replicaCount: 3`
- `service.port: 8080`
- `resources.requests.memory: 256Mi`
- `livenessProbe: /healthz`, `readinessProbe: /readyz`
- `podDisruptionBudget.enabled: true`
- `autoscaling.enabled: false` (enable HPA explicitly)
- `networkPolicy.enabled: false` (enable and fill ingress/egress CIDRs per cluster)

External Postgres is REQUIRED — chart does not bundle a database.

NetworkPolicy application egress is default-deny when enabled without explicit
CIDRs. Add Postgres, upstream OIDC, and soland CIDR blocks through
`networkPolicy.egress.{postgresCidrs,oidcProviderCidrs,solandCidrs}`; DNS egress
is enabled for the cluster DNS pods by default.

## Operational hooks

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness — process up |
| `GET /readyz` | Readiness — DB reachable, dependencies healthy |
| `GET /metrics` | Prometheus scrape (full OTel + counter / histogram) |

Scrape config example:
```yaml
scrape_configs:
  - job_name: coauth
    static_configs:
      - targets: ['coauth.cokret-system.svc.cluster.local:8080']
    metrics_path: /metrics
```

## OIDC conformance

The OIDC adapter is tested against the standard conformance suite. Run locally with:

```sh
just conformance        # spins up Docker compose + executes
```

CI runs this automatically via `.github/workflows/oidc-conformance.yaml`.

## R3 migration notes (b47ff6ec sync)

- New error codes wired (CKP-0008 agent auth matrix): `pairing_request_expired`, `proof_invalid`, `verification_method_principal_mismatch`, `agent_paused`, `agent_deactivated`, `accountability_grant_missing`. No schema migration.
- 5 new capability action enum entries (`cx.call.{join, screen_share, record, transcribe, moderate}`) — backward-compatible policy evaluation; no rule storage migration.
- Handle homograph wire-level reject hook on organization-issued claims — no migration; existing claims revalidated on next refresh.
- `ck.profile.accountable_principals.strict_reject.v1` profile signal — opt-in per deployment via config (default: strict accountability-principal validation).

## Security

See [SECURITY.md](SECURITY.md). Highlights:
- Gitleaks CI job catches accidental secret commits (`.github/workflows/secret-scan.yaml`).
- `unsafe_code = deny` lint enforced workspace-wide (zero unsafe blocks).
- OTLP + Prometheus exporters always-on (no opt-in feature flag to forget).
