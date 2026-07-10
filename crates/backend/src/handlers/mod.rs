//! HTTP request handlers for the coauth authentication service.
//!
//! This module contains all the HTTP handler logic, organized by protocol and
//! concern area:
//!
//! - [`admin`] — Admin API handlers for managing users, sessions, and clients
//! - [`health`] — Health-check endpoint
//! - [`oauth`] — OAuth / OpenID Connect endpoints (token, authorization, discovery, userinfo, etc.)
//! - [`rest`] — REST API endpoints for the account management frontend (JSON)
//! - [`spa`] — SPA shell handler (serves the Dioxus frontend HTML wrapper)
//! - [`upstream_oauth`] — Upstream SSO / federated identity provider strands
//! - [`passwords`] — Password hashing and verification utilities
//!
//! All user-facing pages are rendered by the Dioxus frontend
//! (`crates/frontend`). The backend serves only REST API endpoints and the SPA
//! shell.

/// Implement `From<E>` for `RouteError`, for "internal server error" kind of
/// errors.
macro_rules! impl_from_error_for_route {
    ($route_error:ty : $error:ty) => {
        impl From<$error> for $route_error {
            fn from(e: $error) -> Self {
                Self::Internal(Box::new(e))
            }
        }
    };
    ($error:ty) => {
        impl_from_error_for_route!(self::RouteError: $error);
    };
}

/// Implement [`salvo::oapi::EndpointOutRegister`] for an admin `RouteError`.
///
/// Accepts a list of `(status_code, description)` tuples.  The generated
/// implementation adds each pair as an error response with a JSON error
/// body to the `OpenAPI` operation.
#[allow(unused_macros)]
macro_rules! impl_endpoint_out_register {
    ($ty:ty, [ $(($status:expr, $desc:expr)),* $(,)? ]) => {
        impl salvo::oapi::EndpointOutRegister for $ty {
            fn register(
                _components: &mut salvo::oapi::Components,
                _operation: &mut salvo::oapi::Operation,
            ) {
                use salvo::oapi::*;

                let error_schema = Object::new()
                    .property("errors", Object::new()
                        .property("title", Object::new().schema_type(BasicType::String))
                        .required("title"));

                $(
                    {
                        let response = Response::new($desc)
                            .add_content("application/json", Content::new(error_schema.clone()));
                        _operation.responses.insert($status, RefOr::Type(response));
                    }
                )*
            }
        }
    };
}

use std::sync::LazyLock;

use opentelemetry::metrics::Meter;

/// Account management API endpoints consumed by the frontend SPA.
pub mod account;
/// Admin API handlers (JSON API, cursor-paginated).
pub mod admin;
/// Arkret-facing identity, directory, DID document, and session grant
/// handlers.
pub mod arkret;
/// Shared infrastructure types (DepotExt, RouteError, etc.).
pub mod common;
/// Public inbound webhooks for email delivery providers.
pub mod email_webhooks;
/// Health-check endpoint (`/health`).
pub mod health;
/// OAuth and OpenID Connect protocol endpoints.
pub mod oauth;
/// Password hashing, verification, and complexity checking.
pub mod passwords;
/// Round 4 `ak.self.policy.query.check` v2 handler. Round-4 wire shape:
/// `PolicyCheckRequestBody` → `PolicyCheckOutcome` with full `bound_to`
/// binding + frontier hashes + DID-URL signature kid.
pub mod policy_check;
/// Post-authentication action utilities (shared across handlers).
pub mod post_auth;
/// SPA shell serving (renders the Dioxus frontend HTML wrapper).
pub mod spa;
/// Strand execution engine for multi-step user interaction strands.
pub mod strand;
/// Upstream (federated) OAuth / OIDC provider integration.
pub mod upstream_oauth;
/// Canonical SSR prelude for server-rendered view handlers (round 25).
pub mod view_prelude;

mod activity_tracker;
mod captcha;
mod notification_dispatch;
mod notification_language;
mod preferred_language;
mod rate_limit;
mod session;
#[cfg(test)]
mod test_utils;

static METER: LazyLock<Meter> = LazyLock::new(|| {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
});

pub use self::activity_tracker::{ActivityTracker, Bound as BoundActivityTracker};
pub use self::common::{make_clock, make_rng};
pub use self::notification_language::notification_language;
pub use self::preferred_language::preferred_language;
pub use self::rate_limit::{Limiter, RequesterFingerprint};
pub use self::upstream_oauth::cache::MetadataCache;
pub use self::upstream_oauth::jwks_cache::JwksCache;
pub use crate::salvo_utils::cookies::CookieManager;
