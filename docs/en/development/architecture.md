# Architecture

coauth is the Contrix Auth Server. It handles account authentication,
OAuth/OIDC, session grants, and Principal Server integration for downstream
systems such as Soland. It is meant to stay lightweight in terms of resource
usage and easily scalable horizontally.

## Scope and goals

coauth focuses on Contrix authentication and authorization workflows rather
than acting as a general purpose Identity Provider (IdP).

It speaks OAuth / OIDC for authentication and exposes Contrix session grant
surfaces for Principal Servers. If you want to connect to an upstream SAML, CAS
or LDAP backend then you need to pair coauth with a separate service (such as
[Dex](https://dexidp.io) or [Keycloak](https://www.keycloak.org)) which does that
translation for you.

If you need some other feature that coauth doesn't support (such as TOTP or WebAuthn), then you should consider pairing coauth with another IdP that does support the features you need.

## Workspace and crate split

The whole repository is a [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) that includes multiple crates under the `/crates` directory.

This includes:

 - `coauth`: Command line utility, main entry point
 - [`coauth-config`][coauth-config]: Configuration parsing and loading
 - [`coauth-data-model`][coauth-data-model]: Models of objects that live in the database, regardless of the storage backend
 - [`coauth-email`][coauth-email]: High-level email sending abstraction
 - [`coauth-handlers`][coauth-handlers]: Main HTTP application logic
 - [`coauth-policy`][coauth-policy]: Policy engine abstraction layer supporting multiple backends (OPA/WASM, Cedar, Remote HTTP)
 - [`coauth-iana`][coauth-iana]: Auto-generated enums from IANA registries
 - [`coauth-iana-codegen`][coauth-iana-codegen]: Code generator for the `coauth-iana` crate
 - [`coauth-jose`][coauth-jose]: JWT/JWS/JWE/JWK abstraction
 - [`coauth-frontend`][coauth-frontend]: Frontend application (Dioxus-based Rust SPA)
 - [`coauth-storage`][coauth-storage]: Abstraction of the storage backends
 - [`coauth-storage-pg`][coauth-storage-pg]: Storage backend implementation for a PostgreSQL database
 - [`coauth-tasks`][coauth-tasks]: Asynchronous task runner and scheduler
 - [`oauth-types`][oauth-types]: Useful structures and types to deal with OAuth/OpenID Connect endpoints. This might end up published as a standalone library as it can be useful in other contexts.

[coauth-config]: ../rustdoc/coauth_config/index.html
[coauth-data-model]: ../rustdoc/coauth_data_model/index.html
[coauth-email]: ../rustdoc/coauth_email/index.html
[coauth-handlers]: ../rustdoc/coauth_handlers/index.html
[coauth-policy]: ../rustdoc/coauth_policy/index.html
[coauth-iana]: ../rustdoc/coauth_iana/index.html
[coauth-iana-codegen]: ../rustdoc/coauth_iana_codegen/index.html
[coauth-jose]: ../rustdoc/coauth_jose/index.html
[coauth-frontend]: ../rustdoc/coauth_frontend/index.html
[coauth-storage]: ../rustdoc/coauth_storage/index.html
[coauth-storage-pg]: ../rustdoc/coauth_storage/index.html
[coauth-tasks]: ../rustdoc/coauth_tasks/index.html
[oauth-types]: ../rustdoc/oauth_types/index.html

## Important crates

The project makes use of a few important crates.

### Async runtime: `tokio`

[Tokio](https://tokio.rs/) is the async runtime used by the project.
The choice of runtime does not have much impact on most of the code.

It has an impact when:

 - spawning asynchronous work (as in "not awaiting on it immediately")
 - running CPU-intensive tasks. They should be ran in a blocking context using `tokio::task::spawn_blocking`. This includes password hashing and other crypto operations.
 - when dealing with shared memory, e.g. mutexes, rwlocks, etc.

### Logging: `tracing`

Logging is handled through the [`tracing`](https://docs.rs/tracing/*/tracing/) crate.
It provides a way to emit structured log messages at various levels.

```rust
use tracing::{info, debug};

info!("Logging some things");
debug!(user = "john", "Structured stuff");
```

`tracing` also provides ways to create spans to better understand where a logging message comes from.
In the future, it will help building OpenTelemetry-compatible distributed traces to help with debugging.

`tracing` is becoming the standard to log things in Rust.
By itself it will do nothing unless a subscriber is installed to -for example- log the events to the console.

The CLI installs [`tracing-subcriber`](https://docs.rs/tracing-subscriber/*/tracing_subscriber/) on startup to log in the console.
It looks for a `RUST_LOG` environment variable to determine what event should be logged.

### Error management: `thiserror` / `anyhow`

[`thiserror`](https://docs.rs/thiserror/*/thiserror/) helps defining custom error types.
This is especially useful for errors that should be handled in a specific way, while being able to augment underlying errors with additional context.

[`anyhow`](https://docs.rs/anyhow/*/anyhow/) helps dealing with chains of errors.
It allows for quickly adding additional context around an error while it is being propagated.

Both crates work well together and complement each other.

### Database interactions: `diesel`

Interactions with the database are done through [`diesel`](https://diesel.rs/) with [`diesel-async`](https://docs.rs/diesel-async/) for async support and [`deadpool`](https://docs.rs/deadpool/) for connection pooling.
Schema migrations are managed by `diesel_migrations`.

### Templates: `minijinja`

[MiniJinja](https://github.com/mitsuhiko/minijinja) is used as the template engine. It is a Rust implementation of the Jinja2 template language, offering runtime template loading and a syntax familiar to Python developers.
The `minijinja-contrib` crate provides additional filters for Python compatibility.

### Crates from *RustCrypto*

The [RustCrypto team](https://github.com/RustCrypto) offer high quality, independent crates for dealing with cryptography.
The whole project is highly modular and APIs are coherent between crates.

## API Layering

### User Portal API (/api/v1/viewer/*, /api/v1/auth/*, /api/v1/email-auth/*, etc.)
User self-service endpoints, consumed by the Dioxus frontend.

### Workflow API (/api/v1/flow/*)
Flow engine endpoints, supporting multi-step interactive flows (registration, recovery, MFA, etc.).

### Admin Operations API (/api/admin/v1/*)
Administrative operation endpoints, consumed by the Padmin management interface.

### OAuth Protocol API (/oauth/*, /.well-known/*)
Standard OAuth / OIDC protocol endpoints.
