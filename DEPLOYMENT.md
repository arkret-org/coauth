# coauth — Deployment Guide

> Normative protocol source: [arkret-spec v1](../arkret-spec/spec/v1/)

## Overview

`coauth` is the organization-deploy auth / DID-binding service that complements `soland` (Station). This guide covers the supported deployment paths.

## Prerequisites

- PostgreSQL 14+ (primary) — `coauth-backend` uses Diesel migrations.
- Optional: OIDC upstream provider (Keycloak, Auth0, Azure AD, etc.) for `ak.account.oidc_*` flows.
- A durable `arkret-keystore` backend: platform credential storage for a
  single host, or encrypted-file storage plus a separately custodied master
  key for containers and replicas.
- Rust toolchain matching workspace MSRV (see root `Cargo.toml`).

## Configuration

Configuration lives in `config.example.yaml` (committed) — copy to `config.local.yaml` and adjust:

```yaml
http:
  listeners:
  - name: web
    resources: [discovery, human, oauth, restapi, assets, health]
    binds:
    - address: "0.0.0.0:8080"
  public_base_url: https://auth.acme.example/
  issuer: https://auth.acme.example/
database:
  uri: ${COAUTH_DATABASE_URI}
secrets:
  backend: encrypted_file
  path: /var/lib/coauth/keystore.v1
  master_key_file: /run/secrets/coauth_runtime_keys_master_key
arkret:
  trust_domain: ak:trust_domain:acme.example
  stations:
  - name: soland
    endpoint: https://soland.acme.example/
    embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
```

The KeyStore master key, OIDC client secrets, and DB password MUST come from
mounted secrets or a secrets manager — never a committed `.env`. Run exactly
one initial server with `--first-provisioning`; all later server and worker
processes load the existing bundle without that flag. Multi-replica deployments
must share the same encrypted file and master key.

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

Migrations are idempotent and located under `crates/storage-postgres/migrations/`.

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
  --namespace arkret-system \
  --from-literal=url="postgres://coauth:$(vault read -field=password secret/coauth/db)@pg.acme.example/coauth"

helm upgrade --install coauth charts/coauth \
  --namespace arkret-system --create-namespace \
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
      - targets: ['coauth.arkret-system.svc.cluster.local:8080']
    metrics_path: /metrics
```

## OIDC conformance

The OIDC adapter is tested against the standard conformance suite in CI via
`.github/workflows/oidc-conformance.yaml`. Local runners should use the
scripts under `conformance/` and `scripts/`; there is no `just conformance`
recipe in this workspace.

## Current protocol notes

- Agent authentication exposes `pairing_request_expired`, `proof_invalid`,
  `verification_method_principal_mismatch`, `agent_paused`,
  `agent_deactivated`, and `accountability_grant_missing` error codes.
- Call policy supports `ak.call.{join, screen_share, record, transcribe,
  moderate}` capability actions.
- Organization-issued handle claims reject homograph violations at the wire
  boundary and are revalidated on refresh.

## Security

See [SECURITY.md](SECURITY.md). Highlights:
- Gitleaks CI job catches accidental secret commits (`.github/workflows/secret-scan.yaml`).
- `unsafe_code = deny` lint enforced workspace-wide (zero unsafe blocks).
- OTLP + Prometheus exporters always-on (no opt-in feature flag to forget).
- Proof replay rejection (DPoP and DID-binding `jti` dedup) is backed by
  shared Postgres tables, so it holds across replicas and restarts.
