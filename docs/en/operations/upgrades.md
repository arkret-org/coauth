# Upgrades

`coauth` follows [Semantic Versioning](https://semver.org/) for the HTTP
contracts. Patch and minor releases never break compatibility with the
existing OIDC / OAuth / Contrix surfaces. Major releases may remove
deprecated paths after at least one minor release of warning.

## Routine upgrades

The procedure below works for all in-place upgrades on the same major
line.

1. **Read the [`CHANGELOG.md`](../../../CHANGELOG.md)** entry for the
   target version and watch for `BREAKING:` callouts.
2. **Snapshot** the database with `pg_dump` ([backup-restore](backup-restore.md)).
3. **Pull** the new container image (or download the new binary) onto a
   staging instance.
4. **Run migrations** explicitly so they fail fast:

   ```sh
   coauth database migrate --config /etc/coauth/config.yaml
   ```

   Migrations are idempotent and forward-only. Older binaries cannot be
   started against a newer schema.

5. **Start one replica** with the new binary, watch
   `coauth doctor`, `/health`, and the access logs.
6. **Roll forward** the rest of the fleet.
7. **Keep the previous container tag pinned** for at least 24 h so a
   rollback is just a tag swap.

`coauth` is designed to be **horizontally scaled** — a rolling restart
through your orchestrator is supported on every minor release.

## Backwards-compatibility surface

The following surfaces are tracked compatibility contracts:

- `/.well-known/openid-configuration`
- `/.well-known/did.json`
- `/.well-known/contrix/openapi.yaml`
- `/api/admin/v1/openapi.yaml` (the canonical `sodmin` integration
  contract)
- `/api/v1/server/describe` and the rest of `/api/v1/*`
- The CLI subcommand surface (`server`, `worker`, `manage`, `database`,
  `config`, `templates`, `doctor`).

Items that **may** change between minor releases without a major bump:

- Internal listener routes (`/connection-info`, `/metrics`).
- Template variables — when you customise templates you must rebase
  them on each upgrade.
- Cedar / OPA policy bundles.

## Environment-variable migration

The legacy `PASION_CONFIG` and `PASION_*` environment variables are
still read by the binary but are deprecated. On your next deploy:

- Rename `PASION_CONFIG` → `COAUTH_CONFIG`.
- Rename `PASION_FOO__BAR` → `COAUTH_FOO__BAR` (the `__` separator and
  case rules are unchanged).

Both prefixes work simultaneously; if the same variable is set under
both, `COAUTH_*` wins. New variables added after `1.x` will only be
read under the `COAUTH_*` prefix.

## Rollback

A rollback after a successful migration is **not always safe**: a newer
schema may contain columns or NOT NULL constraints that the older
binary cannot satisfy. The supported rollback path is a database
restore from the pre-upgrade `pg_dump`.

Document the rollback runbook before every major upgrade and dry-run
it on staging.
