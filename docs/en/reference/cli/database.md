# `database`

Run database-related operations.

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `database migrate`

Run the pending database migrations. This updates the database schema to match the version expected by the current binary.

```
$ coauth database migrate -c config.yaml
```

### When to use

- **After upgrading** — When you install a new version of Pasion, run `database migrate` before starting the server if you use the `--no-migrate` flag.
- **CI/CD pipelines** — Run migrations as a separate step before deploying the new server version.
- **Manual control** — If you prefer to apply migrations explicitly rather than letting the server do it automatically on startup.

### Automatic migrations

By default, `coauth server` applies pending migrations automatically on startup. You can disable this with the `--no-migrate` flag, in which case the server will refuse to start if there are unapplied migrations.

### Recovery from failed migrations

If a migration fails partway through:

1. Check the server logs for the specific error.
2. Fix the underlying issue (usually a database permission or constraint problem).
3. Re-run `coauth database migrate` — it will resume from where it left off.

Migrations are applied inside transactions when possible, so a failed migration typically leaves the database in the state before that migration was attempted.
