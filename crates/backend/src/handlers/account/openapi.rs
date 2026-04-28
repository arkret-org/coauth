//! OpenAPI specification and Swagger UI for the REST API.
//!
//! This module provides a helper that builds an `OpenApi` document from a
//! router whose handlers are annotated with `#[endpoint]`, and attaches a
//! Swagger UI frontend so that developers can explore the API interactively.

use salvo::{
    oapi::{OpenApi, swagger_ui::SwaggerUi},
    prelude::*,
};

/// Build an OpenAPI document from the given `router` and return a new router
/// that serves both the JSON spec and the Swagger UI.
///
/// # Arguments
///
/// * `router` - The router whose `#[endpoint]` handlers will be introspected to
///   produce the OpenAPI spec.
///
/// # Returns
///
/// A `Router` that serves:
///
/// * `GET /api-doc/openapi.json` - The generated OpenAPI 3.x JSON document.
/// * `GET /swagger-ui/**` - The Swagger UI single-page application.
pub fn build_openapi_router(router: &Router) -> Router {
    let doc = OpenApi::new("Pasion REST API", env!("CARGO_PKG_VERSION")).merge_router(router);

    Router::new()
        .push(doc.into_router("/api-doc/openapi.json"))
        .push(SwaggerUi::new("/api-doc/openapi.json").into_router("swagger-ui"))
}
