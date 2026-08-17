# Contributing to coauth

Thanks for your interest in coauth — the Arkret OIDC / OAuth 2.1 identity
service. This file describes the project values, the local development loop,
and the sign-off / security expectations for patches.

## Project values

- **Spec-faithful.** coauth implements the relevant slice of arkret-spec
  exactly. Behaviour that drifts from the spec is a bug, even when the spec
  is awkward — fix the spec first.
- **Conformance over convenience.** Every wire-level change is validated
  against the OIDC conformance suite and against `arkret-spec`'s JSON
  schemas before it merges.
- **No quiet failures.** Authentication errors must be explicit; never log
  a credential or proxy a request without trace context.
- **Boring crypto.** Pin algorithms in `arkret-spec`; do not invent.

## Local development

The full workspace builds with `cargo` on stable Rust (MSRV pinned in
`Cargo.toml`). For day-to-day work:

```sh
cargo check --workspace
cargo test  --workspace
```

`cargo test --workspace` does **not** cover the database-backed handler tests.
Every one of them early-returns unless `DATABASE_URL` is set, and the
policy-backed handlers are compiled out without the `cedar` feature, so that
face is silently skipped by the command above. Run it explicitly against a
scratch database that the suite may truncate:

```sh
DATABASE_URL=postgresql://postgres:postgres@localhost/coauth_test \
  cargo run -p coauth -- database migrate
DATABASE_URL=postgresql://postgres:postgres@localhost/coauth_test \
  just test-postgres
```

CI runs the same command in the `Postgres lib-test gate` workflow.

Conformance and integration helpers live under `conformance/` and `scripts/`;
use the CI workflow definitions as the source of truth for the exact command
line.

Integration stack (coauth + soland + Postgres) via docker-compose:

```sh
docker compose -f docker-compose.integration.yaml up --build
```

See [`docs/`](./docs) for service-specific runbooks.

## Patches & pull requests

1. Open an issue describing the change before writing more than ~50 LOC of
   new code, unless the change is a clear bug fix.
2. Keep commits small and focused. Squash trivial fixups before pushing.
3. Run `cargo +nightly fmt --all` and `cargo clippy --workspace -- -D warnings`
   locally; CI enforces both.
4. New protocol behaviour must come with at least one conformance or
   integration test exercising the wire path.

### Developer Certificate of Origin (DCO)

All commits must be signed off using the
[Developer Certificate of Origin](https://developercertificate.org/) —
`git commit -s` appends the required trailer:

```
Signed-off-by: Your Name <you@example.com>
```

By signing off you certify that you have the right to submit the change
under the project's AGPL-3.0-only license.

## Security

Do **not** open public issues for security vulnerabilities. Follow the
disclosure process in [`SECURITY.md`](./SECURITY.md) instead.

## License

By contributing you agree that your contributions will be licensed under
the project's AGPL-3.0-only license. See [LICENSE](./LICENSE).
