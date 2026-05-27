# Contributing to coauth

Thanks for your interest in coauth — the Contrix OIDC / OAuth 2.1 identity
service. This file describes the project values, the local development loop,
and the sign-off / security expectations for patches.

## Project values

- **Spec-faithful.** coauth implements the relevant slice of contrix-spec
  exactly. Behaviour that drifts from the spec is a bug, even when the spec
  is awkward — fix the spec first.
- **Conformance over convenience.** Every wire-level change is validated
  against the OIDC conformance suite and against `contrix-spec`'s JSON
  schemas before it merges.
- **No quiet failures.** Authentication errors must be explicit; never log
  a credential or proxy a request without trace context.
- **Boring crypto.** Pin algorithms in `contrix-spec`; do not invent.

## Local development

The full workspace builds with `cargo` on stable Rust (MSRV pinned in
`Cargo.toml`). For day-to-day work:

```sh
cargo check --workspace
cargo test  --workspace
```

OIDC conformance suite (Docker required):

```sh
just conformance       # spins up the conformance harness
```

Integration stack (coauth + soland + Postgres) via docker-compose:

```sh
docker compose -f docker-compose.integration.yaml up --build
```

See [`docs/`](./docs) for service-specific runbooks.

## Patches & pull requests

1. Open an issue describing the change before writing more than ~50 LOC of
   new code, unless the change is a clear bug fix.
2. Keep commits small and focused. Squash trivial fixups before pushing.
3. Run `cargo fmt --all` and `cargo clippy --workspace -- -D warnings`
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
under the project's Apache-2.0 license.

## Security

Do **not** open public issues for security vulnerabilities. Follow the
disclosure process in [`SECURITY.md`](./SECURITY.md) instead.

## License

By contributing you agree that your contributions will be licensed under
the [Apache License 2.0](./LICENSE).
