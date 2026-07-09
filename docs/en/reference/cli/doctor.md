# `doctor`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `doctor`

Run diagnostics on the live deployment.
This tool should help diagnose common issues with the service configuration and deployment.

When running this tool, make sure it runs from the same point-of-view as the service, with the same configuration file and environment variables.

```
$ coauth doctor
```

### What it checks

The `doctor` command performs the following diagnostics:

- **Configuration validity** — Checks that the configuration file is syntactically and semantically valid.
- **Issuer hygiene** — Warns when the configured issuer is not HTTPS.
- **Principal Server configuration** — Reports the configured `arkret.principal_servers` entries.
- **OpenID discovery** — Fetches `/.well-known/openid-configuration` and verifies its issuer.
- **Arkret discovery** — Fetches `/_arkret/describe`.

### Interpreting the output

Each check prints a status line:

- **OK** — The check passed.
- **WARN** — A potential issue was detected that may cause problems, but the service can still start.
- **FAIL** — A critical issue was found. The service will likely not work correctly until it is resolved.

### Tips

- Run `doctor` after any configuration change to verify the setup before restarting the service.
- If deploying via Docker, run the command inside the same container or network to ensure network conditions match.
- Use `RUST_LOG=debug` for more verbose diagnostic output.
