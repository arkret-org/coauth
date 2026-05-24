# OIDC conformance harness configs

This directory ships **plan-based YAML configs** for the
[OpenID Foundation conformance suite][openid-cs] that target a localhost
coauth instance brought up by `scripts/oidc-conformance.sh`. Each
`*.json` file in this directory is a *test plan configuration* — the
shape the conformance harness's `--config` flag accepts.

## CI split

The full conformance harness runs as a Java + MongoDB stack
(`openid/conformance-suite:latest`) and takes ~minutes to boot per CI
run. PR coverage stays smoke-only: the runner boots or targets a coauth
instance, fetches discovery, and lists the selected plan inventory
unless `COAUTH_RUN_FULL_CONFORMANCE=1` is set. The full suite is wired
through `.github/workflows/oidc-conformance.yaml` and runs nightly
against the three shipped plan files.

## Files

- `plan-basic-op.json` — covers the basic OP profile: discovery,
  authorization code, userinfo, id_token verification, refresh, and
  RP-initiated logout. Targets `http://127.0.0.1:8080`.
- `plan-fapi2-baseline.json` — covers the FAPI 2.0 baseline subset
  (PAR + DPoP-bound access tokens). Targets the same coauth instance
  but with a different client profile (private_key_jwt + ES256).
- `plan-mtls-baseline.json` — covers
  [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) Mutual TLS
  Client Authentication: PKI-bound client auth, self-signed client
  auth, the certificate-bound access-token confirmation claim
  (`x5t#S256`), and the cross-binding negative case from §3.

## Running locally

```bash
# 1. Build coauth.
cargo build --release -p coauth-cli

# 2. Run the smoke harness: boots coauth, fetches
#    /.well-known/openid-configuration, and prints plan inventory.
./scripts/oidc-conformance.sh
```

The smoke runner does not invoke the Java suite unless
`COAUTH_RUN_FULL_CONFORMANCE=1` is set. This keeps PR and local default
runs cheap and avoids requiring Docker for the discovery-only smoke.

## Wiring the full suite

The nightly GitHub Actions workflow sets `COAUTH_RUN_FULL_CONFORMANCE=1`
and runs:

```bash
./scripts/oidc-conformance.sh --plan all
```

`--plan all` expands to:

- `plan-basic-op.json`
- `plan-fapi2-baseline.json`
- `plan-mtls-baseline.json`

The workflow has no `pull_request` trigger; PR jobs remain smoke-only.
It also exposes a `workflow_dispatch` input for targeted reruns of a
single plan.

To run the same full conformance path locally (e.g. before a release),
set `COAUTH_RUN_FULL_CONFORMANCE=1` in the environment. The runner will
then:

1. `docker pull openid/conformance-suite:latest`
2. start a Java + MongoDB sidecar with this directory mounted at
   `/server/configs`
3. POST a plan-create request for each `plan-*.json` file
4. wait for `done` status
5. dump JSON results to `target/conformance-results/` and exit non-zero
   if any test failed

### Selecting a single plan

`scripts/oidc-conformance.sh` accepts a `--plan` flag (or the
`CONFORMANCE_PLAN` env var) so CI can pick exactly one plan instead of
fanning out across all of them:

```bash
./scripts/oidc-conformance.sh --plan basic-op
./scripts/oidc-conformance.sh --plan fapi2-baseline
./scripts/oidc-conformance.sh --plan mtls-baseline
./scripts/oidc-conformance.sh --plan all          # default
```

### Running against a docker-compose coauth

When CI brings up coauth via `docker-compose.integration.yaml` rather
than `cargo build --release -p coauth-cli`, set:

```bash
COAUTH_SKIP_BOOT=1 \
COAUTH_RUN_FULL_CONFORMANCE=1 \
COAUTH_BIND=127.0.0.1:57080 \
./scripts/oidc-conformance.sh --plan basic-op
```

The runner then skips the local-binary boot path, points discovery at
the published compose port, and rewrites each plan JSON's
`server.discoveryUrl` into a temp working copy before invoking the
conformance suite.

## TODO

- `TODO(oidc-conformance-fapi2-cert)`: cross-check the FAPI 2.0 plan
  against the `OpenID Connect for Identity Assurance` certification
  requirements once coauth ships eIDAS-grade evidence linking.
- `TODO(oidc-conformance-mtls-fixtures)`: lay down a per-plan key
  generator (`scripts/conformance-keys.sh`) that materialises
  `target/conformance-keys/mtls-client.{crt,key}` so the mTLS plan can
  run end-to-end without a manual setup step.

[openid-cs]: https://www.certification.openid.net/
