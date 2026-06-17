use std::sync::LazyLock;

use opentelemetry::{Key, metrics::Counter};
use crate::salvo_utils::{
    GenericError,
    record_error,
};
use coauth_templates::ToFormState;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::UpstreamSessionsCookie;
use crate::handlers::{
    METER,
    upstream_oauth::link_workflow::UpstreamLinkWorkflowError,
};

mod get;
mod post;
#[cfg(test)]
mod tests;

pub use self::get::get;
pub use self::post::post;

static LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.upstream_oauth.login")
        .with_description("Successful upstream OAuth login to existing accounts")
        .with_unit("{login}")
        .build()
});
static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.upstream_oauth.registration")
        .with_description("Successful upstream OAuth registration")
        .with_unit("{registration}")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");

#[derive(Debug, Error)]
pub enum RouteError {
    /// Couldn't find the link specified in the URL
    #[error("Link not found")]
    LinkNotFound,

    #[error("Invalid form action")]
    InvalidFormAction,

    #[error("Upstream link workflow error")]
    Workflow(#[source] UpstreamLinkWorkflowError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(coauth_templates::TemplateError);
impl_from_error_for_route!(crate::salvo_utils::csrf::CsrfError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);
impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::account::RouteError);
impl_from_error_for_route!(coauth_policy::InstantiateError);
impl_from_error_for_route!(salvo::http::ParseError);

impl From<UpstreamLinkWorkflowError> for RouteError {
    fn from(error: UpstreamLinkWorkflowError) -> Self {
        Self::Workflow(error)
    }
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_)
                | Self::Workflow(_)
        );

        let status_code = match self {
            Self::LinkNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        GenericError::new(status_code, self).render(res);

        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "action")]
pub enum FormData {
    Register {
        #[serde(default)]
        handle: Option<String>,
        #[serde(default)]
        import_email: Option<String>,
        #[serde(default)]
        import_display_name: Option<String>,
        #[serde(default)]
        accept_terms: Option<String>,
    },
    Link,
}

impl ToFormState for FormData {
    type Field = coauth_templates::UpstreamRegisterFormField;
}
