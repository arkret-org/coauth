# `worker`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `worker`

Runs the background task worker as a standalone process.

```
$ coauth worker -c config.yaml
```

### What the worker does

The worker process handles asynchronous tasks that do not need to be performed during an HTTP request. These include:

- **Sending emails** — Verification codes, password reset links, and notification emails.
- **Homeserver notifications** — Provisioning and deprovisioning users on the Matrix homeserver when accounts are created or deactivated.
- **Session cleanup** — Expiring old sessions and tokens according to configured TTL values.
- **Scheduled maintenance** — Periodic tasks like flushing activity tracking data to the database.

### When to use a separate worker

By default, `coauth server` runs the worker in the same process (unless `--no-worker` is passed). Running the worker separately is useful when:

- **Horizontal scaling** — You want multiple HTTP server instances but only one worker processing tasks.
- **Resource isolation** — Background tasks should not compete with HTTP request handling for CPU and memory.
- **Different deployment targets** — The HTTP server runs behind a load balancer while the worker runs on a separate node.

### Configuration

The worker uses the same configuration file as the server. It requires access to:

- The PostgreSQL database (for the task queue)
- SMTP credentials (if email sending is configured)
- The Matrix homeserver (for user provisioning tasks)

### Example: systemd service

```ini
[Unit]
Description=Pasion Background Worker
After=network.target postgresql.service

[Service]
ExecStart=/usr/local/bin/coauth worker -c /etc/coauth/config.yaml
Restart=on-failure
User=coauth

[Install]
WantedBy=multi-user.target
```
