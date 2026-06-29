# coauth — Deployment Guide

> Spec target: cokret-spec @ 5d66aeb (v1 sync 2026-06-21)

## Overview

`coauth` is the organization-deploy auth / DID-binding service that complements `soland` (Principal Server). This guide covers the supported deployment paths.

## Prerequisites

- PostgreSQL 14+ (primary) — `coauth-backend` uses Diesel migrations.
- Optional: OIDC upstream provider (Keycloak, Auth0, Azure AD, etc.) for `ck.account.oidc_*` strands.
- Optional: HSM / KMS for signing keys (production).
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
  public_base: https://auth.acme.example/
  issuer: https://auth.acme.example/
database:
  uri: ${COAUTH_DATABASE_URI}
cokret:
  trust_domain: ck:trust_domain:acme.example
  principal_servers:
  - name: soland
    audience: did:webvh:soland.acme.example
    endpoint: https://soland.acme.example/
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

Migrations are idempotent and located under `crates/data/migrations/`.

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

The OIDC adapter is tested against the standard conformance suite in CI via
`.github/workflows/oidc-conformance.yaml`. Local runners should use the
scripts under `conformance/` and `scripts/`; there is no `just conformance`
recipe in this workspace.

## R3 migration notes (b47ff6ec sync)

- New error codes wired (CKP-0008 agent auth matrix): `pairing_request_expired`, `proof_invalid`, `verification_method_principal_mismatch`, `agent_paused`, `agent_deactivated`, `accountability_grant_missing`. No schema migration.
- 5 new capability action enum entries (`ck.call.{join, screen_share, record, transcribe, moderate}`) — backward-compatible policy evaluation; no rule storage migration.
- Handle homograph wire-level reject hook on organization-issued claims — no migration; existing claims revalidated on next refresh.
- `ck.profile.accountable_principals.strict_reject.v1` profile signal — opt-in per deployment via config (default: strict accountability-principal validation).

## Security

See [SECURITY.md](SECURITY.md). Highlights:
- Gitleaks CI job catches accidental secret commits (`.github/workflows/secret-scan.yaml`).
- `unsafe_code = deny` lint enforced workspace-wide (zero unsafe blocks).
- OTLP + Prometheus exporters always-on (no opt-in feature flag to forget).

### Replay protection is single-replica (deployment constraint)

The single-use / replay-rejection store for DID-binding control proofs and
3PID invite-claim proofs (`services::third_party_invite::NonceStore`) is an
**in-process** `Mutex<HashMap<jti, expires_at>>`. A consumed proof `jti` is
only remembered by the replica that handled it, and the table is lost on
restart. Within the proof freshness window (≤300s) the same proof can
therefore be replayed against a *different* replica.

The reference Helm chart defaults to `replicaCount: 3`, so this constraint is
**not satisfied by the default deployment**. Until the dedup store is backed
by a shared table (`invite_proof_seen_jti(jti, expires_at)` with a partial
unique index on `jti`), operators MUST either:

- run a single coauth replica for the proof-verifying surfaces, or
- front the proof-verifying routes
  (`/_coauth/self/invites/3pid/verify`, the admin DID-binding verify, and the
  session-grant refresh/revoke DID-proof paths) with a load balancer that
  pins a given `jti`/client to one replica for the freshness window,

otherwise cross-replica proof replay is possible. This is tracked as a known
limitation; the migration path is documented inline on `NonceStore`.
