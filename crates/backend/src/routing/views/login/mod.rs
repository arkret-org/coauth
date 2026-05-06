//! View handlers for the password-login flow.
//!
//! Historically a single 891-line `login.rs`. Split into focused
//! submodules — see `_tasks.md` T21:
//!
//! - [`form`] — the `LoginForm` payload type
//! - [`get`] — `GET /login` (renders the form / redirects on existing session)
//! - [`post`] — `POST /login` (validates the form, runs `login_with_password`)
//! - [`render`] — the shared `render` helper plus `handle_login_hint`
//! - [`tests`] — the integration tests (was the larger half of the file)
//!
//! Public surface (`get`, `post`) is re-exported here so the router wiring
//! in `server.rs` does not need to know about the layout.

use std::sync::LazyLock;

use opentelemetry::{Key, metrics::Counter};

use crate::routing::METER;

mod form;
mod get;
mod post;
mod render;

#[cfg(test)]
mod tests;

pub use self::get::get;
pub use self::post::post;
pub(crate) use self::form::LoginForm;

/// Counter for password login attempts.
///
/// Label `result` is `"success"`, `"error"`, or carries one of the more
/// specific error labels emitted from `post.rs`. Lives in `mod.rs` so the
/// counter is initialised exactly once even though both `get.rs` and
/// `post.rs` reference it (only `post.rs` does today, but the constant
/// belongs to the module as a whole).
pub(crate) static PASSWORD_LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.user.password_login_attempt")
        .with_description("Number of password login attempts")
        .with_unit("{attempt}")
        .build()
});

pub(crate) const RESULT: Key = Key::from_static_str("result");
