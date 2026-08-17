//! Admin API handlers.
//!
//! Provides a JSON:API-style REST interface for managing users, sessions,
//! OAuth clients, upstream providers, and policy data. All endpoints
//! require the `urn:coauth:admin` scope or a Arkret admin scope.
//!
//! The API specification is available as an OpenAPI document served by the
//! [`swagger`] handler.

use salvo::prelude::*;
use serde::Serialize;

mod call_context;
mod model;
mod params;
mod response;
mod schema;
/// Version 1 of the Admin API endpoints.
pub mod v1;

pub use self::call_context::CallContext;
pub(crate) use self::call_context::Rejection as CallContextRejection;
pub(crate) use self::model::InconsistentPersonalSession;
pub(crate) use self::params::{PaginationRejection, UlidPathParamRejection};
pub(crate) use self::response::ErrorOutcome;

/// Common error response shape for admin API endpoints.
///
/// Individual handlers keep their own `RouteError` enums but can convert
/// to this shared shape for consistent JSON error bodies.
#[derive(Serialize)]
pub struct AdminErrorOutcome {
    /// A short machine-readable error code or label.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: Option<String>,
    /// An optional request identifier for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// The canonical admin scope for the coauth Admin API.
pub const ADMIN_SCOPE: &str = "urn:coauth:admin";

/// Arkret admin scope family.
pub const ARKRET_ADMIN_SCOPE: &str = "urn:arkret:admin:*";

/// Returns `true` if the given scope grants full admin access.
///
/// Matching is **exact**: only the two canonical full-admin scope tokens
/// (`urn:coauth:admin` and the `urn:arkret:admin:*` family marker) are
/// accepted. We deliberately do NOT prefix-match `urn:arkret:admin:`: a
/// prefix check would silently promote any future narrowly-scoped token
/// (e.g. a hypothetical `urn:arkret:admin:readonly`) to full admin. Such
/// sub-scopes must be authorized explicitly by their own predicate, never by
/// virtue of sharing the admin URN prefix.
#[must_use]
pub fn has_admin_scope(scope: &coauth_oauth_types::scope::Scope) -> bool {
    scope.contains(ADMIN_SCOPE) || scope.contains(ARKRET_ADMIN_SCOPE)
}

/// JSON response wrapper that sets HTTP 201 Created status code.
///
/// Drop-in replacement for `(StatusCode, Json<T>)` tuples that works with
/// Salvo's `#[endpoint]` macro by implementing both [`Scribe`] and
/// [`salvo::oapi::EndpointOutRegister`].
pub struct CreatedJson<T: Serialize + Send>(pub T);

impl<T: Serialize + Send> Scribe for CreatedJson<T> {
    fn render(self, res: &mut Response) {
        res.status_code(StatusCode::CREATED);
        res.render(Json(self.0));
    }
}

impl<T: Serialize + Send + salvo::oapi::ToSchema + 'static> salvo::oapi::EndpointOutRegister
    for CreatedJson<T>
{
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        let schema = T::to_schema(components);
        let response = salvo::oapi::Response::new("Created")
            .add_content("application/json", salvo::oapi::Content::new(schema));
        operation
            .responses
            .insert("201", salvo::oapi::RefOr::Type(response));
    }
}

/// Response for a write endpoint that either mints a resource or updates one
/// that already existed.
///
/// `201 Created` may only describe a resource the request brought into
/// existence, so an endpoint whose request can resolve to an existing row has
/// to be able to answer `200 OK` for that branch.
pub enum WriteOutcomeJson<T: Serialize + Send> {
    Created(T),
    Updated(T),
}

impl<T: Serialize + Send> Scribe for WriteOutcomeJson<T> {
    fn render(self, res: &mut Response) {
        match self {
            Self::Created(body) => {
                res.status_code(StatusCode::CREATED);
                res.render(Json(body));
            }
            Self::Updated(body) => {
                res.status_code(StatusCode::OK);
                res.render(Json(body));
            }
        }
    }
}

impl<T: Serialize + Send + salvo::oapi::ToSchema + 'static> salvo::oapi::EndpointOutRegister
    for WriteOutcomeJson<T>
{
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        let created = salvo::oapi::Response::new("Created").add_content(
            "application/json",
            salvo::oapi::Content::new(T::to_schema(components)),
        );
        let updated = salvo::oapi::Response::new("Updated").add_content(
            "application/json",
            salvo::oapi::Content::new(T::to_schema(components)),
        );
        operation
            .responses
            .insert("201", salvo::oapi::RefOr::Type(created));
        operation
            .responses
            .insert("200", salvo::oapi::RefOr::Type(updated));
    }
}

pub(crate) mod audit_helper;
