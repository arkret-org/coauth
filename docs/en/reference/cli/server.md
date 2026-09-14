# `server`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `server`

Runs the authentication service. This is the main command for production deployments.

Options:
- `--no-migrate`: Do not apply pending database migrations on start.
- `--no-worker`: Do not start the background task worker (see [`worker`](./worker.md)).
- `--no-sync`: Do not sync the configuration (OAuth clients and upstream providers) with the database.
- `--first-provisioning`: Generate the runtime key bundle only when the durable KeyStore is empty. Use on exactly one initial production server.

```
$ coauth server -c config.yaml
INFO coauth_cli::server: Starting task scheduler
INFO coauth_cli::server: Listening on http://0.0.0.0:8080
```

### Startup behavior

On startup, the server performs these steps in order:

1. **Database migrations** — Applies any pending schema migrations (unless `--no-migrate`).
2. **Configuration sync** — Syncs OAuth client registrations and upstream provider definitions from the config file to the database (unless `--no-sync`).
3. **Key loading** — Loads the complete runtime key bundle from the configured durable KeyStore.
4. **Template compilation** — Loads and compiles page templates.
5. **Worker startup** — Starts the background task worker (unless `--no-worker`).
6. **HTTP listener** — Begins accepting connections on the configured addresses.

### Graceful shutdown

The server supports graceful shutdown via `SIGTERM` or `SIGINT` (Ctrl+C):

1. On the first signal, the server stops accepting new connections and waits for in-flight requests to complete.
2. On a second signal, the server forcefully terminates all connections.

### Health and readiness checks

The server exposes `/health` and `/healthz` for liveness checks, and
`/readyz` for readiness. `/readyz` verifies that Postgres is reachable, that
the KeyStore-backed signing keys can produce a public JWKS, and that configured
Station trust is ready.

### Example: systemd service

```ini
[Unit]
Description=coauth Authentication Service
After=network.target postgresql.service

[Service]
ExecStart=/usr/local/bin/coauth server -c /etc/coauth/config.yaml
Restart=on-failure
User=coauth

[Install]
WantedBy=multi-user.target
```

### Example: Docker Compose

```yaml
services:
  coauth:
    image: ghcr.io/arkret/coauth:latest
    command: server -c /config.yaml
    volumes:
      - ./config.yaml:/config.yaml:ro
      - coauth-keys:/var/lib/coauth
      - ./secrets/coauth-runtime-keys-master-key:/run/secrets/coauth_runtime_keys_master_key:ro
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
```

The container image runs as the distroless non-root user (`uid=65532`,
`gid=65532`).
Any path referenced by the configuration file must therefore be accessible by
that user. The encrypted KeyStore path must be writable; its separately mounted
`secrets.master_key_file` must be readable.

For example, if the config references
`/run/secrets/coauth_runtime_keys_master_key`, the mounted file must be readable by
the container process.
A host file with permissions like `0600 root:root` will fail at startup with
`Permission denied (os error 13)`.
Change ownership/ACLs so `uid=65532` can read the master-key file and write the
KeyStore volume. Run one initial replica with `--first-provisioning`; ordinary
replicas must omit it and share the same volume and master key.
