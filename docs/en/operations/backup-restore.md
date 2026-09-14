# Backup and restore

`coauth` keeps **all authoritative state in Postgres**. Backing up the
database, the signing key material, and the encryption secret is enough
to fully restore a deployment.

## What to back up

| Item                              | Where it lives                                         | Notes |
| ---                               | ---                                                     | --- |
| Postgres database                 | `database.uri` in `config.yaml`                         | Holds users, sessions, OAuth clients, audit log, etc. |
| Encrypted runtime key bundle      | `secrets.path`                                          | Contains long-lived JWS keys and the application encryption key. Losing it invalidates tokens and makes encrypted state unreadable. |
| KeyStore master key               | `secrets.master_key_file` (or external secret source)   | Required together with the encrypted bundle; back it up separately. |
| Configuration                     | `config.yaml` (and any layered files)                   | Treat as source code; commit to a private repo or a sealed-secrets store. |
| Templates / policies (if customised) | `templates.path`, `policy.path`                       | Optional; default copies ship in the container image / `share/`. |

> Database, encrypted key bundle, and its master key form the **minimum
> recoverable set**. A backup that misses any of them is incomplete.

## Postgres dump

```sh
pg_dump \
  --no-owner --no-privileges \
  --format=custom \
  --file=/var/backups/coauth-$(date -u +%Y%m%dT%H%M%SZ).dump \
  "$DATABASE_URL"
```

Schedule it with `cron`, `systemd-timer`, or your platform's equivalent.
Encrypt the dump (e.g. `age --encrypt --recipient ...`) before shipping
it off-host; it contains password hashes, refresh-token hashes, OAuth
client secrets, and recovery proofs.

For PITR / streaming backups, use `pg_basebackup` + WAL archiving or a
managed Postgres service.

## Verifying a backup

A backup that has never been restored is not a backup. At least once a
month, restore into a throwaway database and run:

```sh
pg_restore --create --clean --no-owner --no-privileges \
  --dbname=postgres /path/to/backup.dump

coauth database check --config /etc/coauth/config.yaml
coauth doctor          --config /etc/coauth/config.yaml
```

`database check` validates the migration ledger; `doctor` cross-checks
configuration against the runtime state.

## Restore procedure

1. **Provision** a fresh Postgres instance and an empty target database.
2. **Restore** the dump:

   ```sh
   pg_restore --create --clean --no-owner --no-privileges \
     --dbname=postgres /path/to/backup.dump
   ```

3. **Restore** both the encrypted KeyStore file and its separately custodied
   master key to the new host with the same paths and byte-identical content.
   Neither half can recover the signing or application-encryption keys alone.
4. **Restore** `config.yaml` (with `database.uri` adjusted to the new
   host).
5. **Run migrations** explicitly to confirm the schema matches the
   binary version:

   ```sh
   coauth database migrate --config /etc/coauth/config.yaml
   ```

6. **Start the service** and watch `coauth doctor` output.

## Key rotation

If the signing key is suspected of compromise:

1. Issue a new key (`coauth manage add-signing-key …`).
2. Demote the compromised key to verification-only (or remove it).
3. Force a refresh cycle for active sessions
   (`coauth manage revoke-sessions …` or per-user revocation through
   the admin API).

The encryption secret cannot be rotated transparently — a rotation
invalidates active session cookies. Plan an announced maintenance
window for that operation.

## Disaster-recovery checklist

- [ ] Dumps retained in two geographically separated locations.
- [ ] Off-host dumps encrypted with a key that is **not** stored on the
      coauth host.
- [ ] At least one monthly restore drill into a non-production
      environment.
- [ ] Documented contact path for the operator on call when a recovery
      is needed.
- [ ] Recovery procedure rehearsed with a fresh starter so it is not a
      single-person dependency.
