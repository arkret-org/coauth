//! Unified OpenAPI document & Swagger UI for the entire backend.
//!
//! Every route handler is annotated with salvo's `#[endpoint]` macro, which
//! contributes parameter, request-body, and response-schema metadata to a
//! single `OpenApi` document built here from the top-level router.
//!
//! Three artefacts are exposed at fixed paths under the request prefix:
//!
//! * `GET /api-doc/openapi.json` — the canonical OpenAPI 3.x JSON spec.
//! * `GET /api-doc/openapi.yaml` — the same document serialised as YAML.
//! * `GET /swagger-ui/**`        — the Swagger UI SPA pinned to that JSON.
//!
//! A second, narrower document is still served under `/api-doc/admin/...` so
//! that the admin surface can be consumed independently.

use http::{HeaderValue, header::CONTENT_TYPE};
use salvo::{
    oapi::{Contact, Info, License, OpenApi, swagger_ui::SwaggerUi},
    prelude::*,
};

const TITLE: &str = "coauth API";
const DESCRIPTION: &str = "Pasion authentication service — OAuth 2.0 / OIDC \
                           protocol, account management REST API, contrix \
                           identity bridge, and admin operations.";

/// Build the unified OpenAPI document from the given top-level router.
///
/// The router passed in should have ALL routes already mounted on it (admin,
/// account, oauth2, contrix, etc.) so the generated spec is comprehensive.
pub fn build_openapi_doc(router: &Router) -> OpenApi {
    OpenApi::new(TITLE, env!("CARGO_PKG_VERSION"))
        .info(
            Info::new(TITLE, env!("CARGO_PKG_VERSION"))
                .description(DESCRIPTION)
                .license(License::new("AGPL-3.0-only"))
                .contact(Contact::new().name("Meldry").url("https://meldry.com/")),
        )
        .merge_router(router)
}

/// Build the legacy admin-only OpenAPI document.
///
/// Kept separate so the admin surface can continue to be consumed in
/// isolation by integrators that only care about the admin REST API.
pub fn build_admin_openapi_doc(admin_router: &Router) -> OpenApi {
    OpenApi::new("coauth Admin API", env!("CARGO_PKG_VERSION"))
        .info(
            Info::new("coauth Admin API", env!("CARGO_PKG_VERSION"))
                .description("Administrative REST surface for managing users, sessions, OAuth2 clients, and policy data.")
                .license(License::new("AGPL-3.0-only")),
        )
        .merge_router(admin_router)
}

/// Mount the unified OpenAPI artefacts (`openapi.json`, `openapi.yaml`,
/// Swagger UI) onto the given router and return the augmented router.
pub fn mount_openapi(router: Router, doc: &OpenApi) -> Router {
    let yaml = OpenApiYaml::from_doc(doc);
    router
        .push(doc.clone().into_router("/api-doc/openapi.json"))
        .push(Router::with_path("/api-doc/openapi.yaml").get(yaml))
        .push(SwaggerUi::new("/api-doc/openapi.json").into_router("/swagger-ui"))
}

/// Build a `Router` that serves *only* the OpenAPI artefacts for the given
/// document. Useful when you already have the document built and just want a
/// drop-in router to push onto an existing tree.
pub fn openapi_router(doc: OpenApi) -> Router {
    let yaml = OpenApiYaml::from_doc(&doc);
    Router::new()
        .push(doc.clone().into_router("/api-doc/openapi.json"))
        .push(Router::with_path("/api-doc/openapi.yaml").get(yaml))
        .push(SwaggerUi::new("/api-doc/openapi.json").into_router("/swagger-ui"))
}

/// A clonable handler that renders a pre-serialized OpenAPI document as YAML.
#[derive(Clone)]
pub struct OpenApiYaml {
    yaml: String,
}

impl OpenApiYaml {
    /// Serialise the given `OpenApi` document to YAML once at construction time.
    #[must_use]
    pub fn from_doc(doc: &OpenApi) -> Self {
        Self {
            yaml: serde_yaml::to_string(doc)
                .expect("OpenAPI document should serialise to YAML"),
        }
    }
}

#[salvo::async_trait]
impl Handler for OpenApiYaml {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/yaml; charset=utf-8"),
        );
        res.render(Text::Plain(self.yaml.clone()));
    }
}
