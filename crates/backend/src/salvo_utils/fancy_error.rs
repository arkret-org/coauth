use coauth_templates::ErrorContext;
use http::StatusCode;
use salvo::prelude::*;

use super::sentry::SentryEventID;

fn build_context(mut err: &dyn std::error::Error) -> ErrorContext {
    let description = err.to_string();
    let mut details = Vec::new();
    while let Some(source) = err.source() {
        err = source;
        details.push(err.to_string());
    }

    ErrorContext::new()
        .with_description(description)
        .with_details(details.join("\n"))
}

pub struct GenericError {
    error: Box<dyn std::error::Error + Send + Sync + 'static>,
    code: StatusCode,
}

impl Scribe for GenericError {
    fn render(self, res: &mut Response) {
        tracing::warn!(message = &*self.error);
        let context = build_context(&*self.error);
        let context_text = format!("{context}");

        res.status_code(self.code);
        res.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        res.render(Text::Plain(context_text));
    }
}

impl GenericError {
    pub fn new(code: StatusCode, err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            error: Box::new(err),
            code,
        }
    }
}

pub struct InternalError {
    error: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl Scribe for InternalError {
    fn render(self, res: &mut Response) {
        tracing::error!(message = &*self.error);
        let event_id = SentryEventID::for_last_event();
        let context = build_context(&*self.error);
        let context_text = format!("{context}");

        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );

        // Add Sentry event ID header if available
        if let Some(event_id) = event_id {
            event_id.write_to_response(res);
        }

        res.render(Text::Plain(context_text));
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for InternalError {
    fn from(err: E) -> Self {
        Self {
            error: Box::new(err),
        }
    }
}

impl InternalError {
    /// Create a new error from a boxed error
    #[must_use]
    pub fn new(error: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        Self { error }
    }

    /// Create a new error from an [`anyhow::Error`]
    #[must_use]
    pub fn from_anyhow(err: anyhow::Error) -> Self {
        Self {
            error: err.into_boxed_dyn_error(),
        }
    }
}

impl salvo::oapi::EndpointOutRegister for InternalError {
    fn register(
        _components: &mut salvo::oapi::Components,
        _operation: &mut salvo::oapi::Operation,
    ) {
        use salvo::oapi::*;
        let error_schema = Object::new()
            .property("error", Object::new().schema_type(BasicType::String))
            .required("error");
        let response = Response::new("Internal server error")
            .add_content("text/plain", Content::new(error_schema));
        _operation.responses.insert("500", RefOr::Type(response));
    }
}
