# OIDC Core (OIDCC) certification runner

`run-oidcc-suite.sh` drives the OpenID Connect Core (OIDCC) certification
test plans listed in `../configs/test-plans.json` against a running
coauth instance.

This sits alongside — and is intentionally separate from —
`scripts/oidc-conformance.sh` at the coauth repo root. That sibling
runs the FAPI 2.0 / mTLS / basic-OP plans from
`conformance/plan-*.json`. The OIDCC certification matrix is its own
profile family and earns its own runner so a release engineer can run
exactly one without sweeping the other.

## Plans covered

| Short flag        | OIDF plan id                                  | Profile                         |
| ----------------- | --------------------------------------------- | ------------------------------- |
| `basic`           | `oidcc-basic-certification-test-plan`         | response_type=code              |
| `hybrid`          | `oidcc-hybrid-certification-test-plan`        | response_type=code id_token     |
| `device-code`     | `oidcc-device-code-certification-test-plan`   | RFC 8628 device authorization   |

All three target the same coauth instance and share the static-client
registration model. The full variant matrix is encoded in
`../configs/test-plans.json` — see that file for client ids, redirect
URIs, and the variant `(client_auth_type, response_mode, ...)` tuples.

## Prerequisites

1. **coauth running and reachable.** Default endpoint is
   `http://127.0.0.1:8080`; override with `COAUTH_BIND=host:port`. The
   runner expects `/health` and `/.well-known/openid-configuration` to
   respond. Bring it up with either of:
   ```bash
   # native release binary
   cargo run --release -p coauth-cli -- server --config <config.yaml>

   # docker compose
   bash scripts/integration-up.sh
   ```
2. **`jq`** on `$PATH` (the runner parses the plan matrix with `jq`).
3. **`docker`** on `$PATH` for the actual harness invocation. If you
   only want to verify configs render cleanly, run with `--dry-run`
   and docker is not required.
4. **OpenID Foundation conformance-suite image.** The OIDF does NOT
   publish a public Docker Hub image. Build it once locally:
   ```bash
   git clone https://gitlab.com/openid/conformance-suite
   cd conformance-suite
   ./builder-compose.sh
   docker tag conformance-suite:latest openid/conformance-suite:local
   export COAUTH_CONFORMANCE_IMAGE=openid/conformance-suite:local
   ```
   The runner respects `COAUTH_CONFORMANCE_IMAGE` so CI / mirrors can
   point at a private tag.

## Usage

```bash
# Show the matrix without running anything.
./conformance/scripts/run-oidcc-suite.sh --list

# Render configs against the current discovery URL, skip docker.
./conformance/scripts/run-oidcc-suite.sh --dry-run

# Run a single plan by short name.
./conformance/scripts/run-oidcc-suite.sh --plan basic
./conformance/scripts/run-oidcc-suite.sh --plan hybrid
./conformance/scripts/run-oidcc-suite.sh --plan device-code

# Or pass the full plan id / alias.
./conformance/scripts/run-oidcc-suite.sh \
    --plan oidcc-basic-certification-test-plan

# Run every plan (default).
./conformance/scripts/run-oidcc-suite.sh
```

Per-plan JSON reports land in `target/conformance-results/<alias>.json`
(override with `RESULTS_DIR=…`). The runner exits non-zero if any plan
fails; the per-plan report is still written so the operator can grep
which assertion broke.

## Environment matrix

| Variable                   | Default                              | Effect                                                          |
| -------------------------- | ------------------------------------ | --------------------------------------------------------------- |
| `COAUTH_BIND`              | `127.0.0.1:8080`                     | host:port the runner probes for `/health` + discovery.          |
| `COAUTH_SKIP_BOOT`         | `0`                                  | When `1`, silences the "operator-managed coauth" notice.        |
| `COAUTH_CONFORMANCE_IMAGE` | `openid/conformance-suite:latest`    | Docker image tag for the harness; override to a local build.    |
| `CONFORMANCE_OIDCC_PLAN`   | `all`                                | Same effect as `--plan`. CLI flag wins when both are set.       |
| `RESULTS_DIR`              | `target/conformance-results`         | Where per-plan JSON reports land.                               |
| `COAUTH_OIDCC_DRY_RUN`     | `0`                                  | When `1`, render configs to a temp dir and exit before docker.  |

## Exit codes

| Code | Meaning                                                                                    |
| ---- | ------------------------------------------------------------------------------------------ |
| `0`  | Every selected plan passed, or `--list` / `--dry-run` completed.                           |
| `2`  | CLI flag / config error (missing `jq`, unknown `--plan`, malformed `test-plans.json`, etc) |
| `3`  | coauth did not become healthy at `COAUTH_BIND` within 30s.                                 |
| `4`  | One or more plans FAILED — inspect `${RESULTS_DIR}/<alias>.json`.                          |

## CI wiring

The nightly OIDC conformance workflow
(`.github/workflows/oidc-conformance.yaml`) currently invokes
`scripts/oidc-conformance.sh` for the FAPI / mTLS / basic-OP plans.
Wiring this OIDCC runner into the same nightly cadence is a matter of
appending a step that runs `./conformance/scripts/run-oidcc-suite.sh`
after the existing FAPI / mTLS steps and uploading the resulting
`${RESULTS_DIR}/oidcc-*.json` reports as a separate artifact bundle.
Operators submitting a fresh OIDF certification round should run this
runner against a release-build coauth and attach the rendered configs
plus the per-plan reports to the submission.

## Adding a new plan

1. Append a new entry to `../configs/test-plans.json` with a unique
   `alias` of the form `coauth-oidcc-<short>` and the canonical OIDF
   plan id under `id`.
2. Run `./conformance/scripts/run-oidcc-suite.sh --list` and confirm
   the new entry shows up with the right alias / id.
3. Run `--dry-run --plan <short>` and inspect the rendered config in
   the printed temp directory.
4. Run the full plan once docker + the conformance-suite image are
   available locally.
