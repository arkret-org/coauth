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

- **Database connectivity** — Verifies that the configured PostgreSQL database is reachable and the connection parameters are correct.
- **Configuration validity** — Checks that the configuration file is syntactically and semantically valid.
- **Template rendering** — Ensures all templates can be loaded and rendered without errors.
- **Key material** — Validates that the configured signing keys are present and usable.
- **Homeserver reachability** — Tests the connection to the configured Matrix homeserver.

### Interpreting the output

Each check prints a status line:

- **OK** — The check passed.
- **WARN** — A potential issue was detected that may cause problems, but the service can still start.
- **FAIL** — A critical issue was found. The service will likely not work correctly until it is resolved.

### Tips

- Run `doctor` after any configuration change to verify the setup before restarting the service.
- If deploying via Docker, run the command inside the same container or network to ensure network conditions match.
- Use `RUST_LOG=debug` for more verbose diagnostic output.
