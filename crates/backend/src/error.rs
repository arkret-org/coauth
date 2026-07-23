use std::error::Error as StdError;
use std::fmt;

use salvo::http::StatusCode;
use salvo::oapi::{self, BasicType, Content, EndpointOutRegister, Object};
use salvo::prelude::{Json, Response, Scribe};

use crate::handlers::admin::{
    CallContextRejection as AdminCallContextRejection, CreatedJson, ErrorOutcome,
    InconsistentPersonalSession, PaginationRejection, UlidPathParamRejection,
};
use crate::handlers::common::RouteError as RestRouteError;
use crate::salvo_utils::sentry::SentryEventId;

type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Return whether the process-wide development posture is enabled.
///
/// Detailed diagnostics follow this posture, while test-only endpoints and
/// insecure escape hatches retain their own explicit authorization switches.
#[must_use]
pub fn development_mode_from_env() -> bool {
    coauth_config::runtime_var("COAUTH_DEVELOPMENT_MODE")
        .is_ok_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    message: String,
    protocol_code: Option<&'static str>,
    source: Option<BoxError>,
    capture: bool,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            protocol_code: None,
            source: None,
            capture: false,
        }
    }

    pub fn with_source(
        status: StatusCode,
        message: impl Into<String>,
        source: BoxError,
        capture: bool,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            protocol_code: None,
            source: Some(source),
            capture,
        }
    }

    pub fn internal<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::with_source(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
            Box::new(error),
            true,
        )
    }

    #[must_use]
    pub fn internal_box(error: BoxError) -> Self {
        Self::with_source(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
            error,
            true,
        )
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn gone(message: impl Into<String>) -> Self {
        Self::new(StatusCode::GONE, message)
    }

    pub fn unprocessable_entity(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, message)
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    /// Preserve a canonical Arkret error code while an error crosses shared
    /// account-handler helpers. Product/admin routes ignore this metadata;
    /// protocol routes convert it into the standard [`arkret_wire::ErrorEnvelope`].
    #[must_use]
    pub fn with_protocol_code(mut self, code: &'static str) -> Self {
        self.protocol_code = Some(code);
        self
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn protocol_code(&self) -> Option<&'static str> {
        self.protocol_code
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for AppError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn StdError + 'static))
    }
}

impl Scribe for AppError {
    fn render(self, res: &mut Response) {
        let response = ErrorOutcome::from_error(&self);
        let sentry_event_id = if self.capture {
            if development_mode_from_env() {
                tracing::error!(
                    status = self.status.as_u16(),
                    protocol_code = self.protocol_code,
                    error = ?self,
                    "detailed application error"
                );
            } else {
                tracing::error!(message = &self as &dyn StdError);
            }
            SentryEventId::for_last_event()
        } else {
            if development_mode_from_env() {
                tracing::warn!(
                    status = self.status.as_u16(),
                    protocol_code = self.protocol_code,
                    error = ?self,
                    "detailed application error"
                );
            } else {
                tracing::warn!(message = &self as &dyn StdError);
            }
            None
        };

        res.status_code(self.status);
        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
        res.render(Json(response));
    }
}

impl EndpointOutRegister for AppError {
    fn register(_components: &mut oapi::Components, operation: &mut oapi::Operation) {
        let error_schema = Object::new().property(
            "errors",
            Object::new()
                .property("title", Object::new().schema_type(BasicType::String))
                .required("title"),
        );

        for (status, description) in [
            ("400", "Bad request"),
            ("401", "Unauthorized"),
            ("403", "Forbidden"),
            ("404", "Not found"),
            ("409", "Conflict"),
            ("410", "Gone"),
            ("422", "Unprocessable entity"),
            ("500", "Internal server error"),
            ("501", "Not implemented"),
        ] {
            let response = oapi::Response::new(description)
                .add_content("application/json", Content::new(error_schema.clone()));
            operation
                .responses
                .insert(status, oapi::RefOr::Type(response));
        }
    }
}

impl From<coauth_data::RepositoryError> for AppError {
    fn from(error: coauth_data::RepositoryError) -> Self {
        Self::internal(error)
    }
}

impl From<InconsistentPersonalSession> for AppError {
    fn from(error: InconsistentPersonalSession) -> Self {
        Self::internal(error)
    }
}

impl From<UlidPathParamRejection> for AppError {
    fn from(error: UlidPathParamRejection) -> Self {
        Self::bad_request(error.to_string())
    }
}

impl From<PaginationRejection> for AppError {
    fn from(error: PaginationRejection) -> Self {
        Self::bad_request(error.to_string())
    }
}

impl From<AdminCallContextRejection> for AppError {
    fn from(error: AdminCallContextRejection) -> Self {
        match error {
            AdminCallContextRejection::MissingAuthorizationHeader
            | AdminCallContextRejection::InvalidAuthorizationHeader => {
                Self::bad_request(error.to_string())
            }
            AdminCallContextRejection::InvalidAccessTokenType(_)
            | AdminCallContextRejection::UnknownAccessToken
            | AdminCallContextRejection::TokenExpired
            | AdminCallContextRejection::SessionRevoked
            | AdminCallContextRejection::UserLocked
            | AdminCallContextRejection::InvalidAdminOrg
            | AdminCallContextRejection::MissingScope => Self::unauthorized(error.to_string()),
            AdminCallContextRejection::RepositorySetup(source) => Self::with_source(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't load the database repository",
                source,
                true,
            ),
            AdminCallContextRejection::Repository(source) => Self::internal(source),
            AdminCallContextRejection::LoadSession(_) | AdminCallContextRejection::LoadUser(_) => {
                Self::internal(error)
            }
        }
    }
}

impl From<RestRouteError> for AppError {
    fn from(error: RestRouteError) -> Self {
        match error {
            RestRouteError::Internal(source) => Self::internal_box(source),
            RestRouteError::LoadFailed => Self::internal(error),
            RestRouteError::InvalidToken => Self::unauthorized(error.to_string()),
            RestRouteError::Unauthorized => Self::forbidden(error.to_string()),
            RestRouteError::NotFound => Self::not_found(error.to_string()),
            RestRouteError::BadRequest(message) => Self::bad_request(message),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
pub type JsonResult<T> = Result<Json<T>, AppError>;
pub type CreatedJsonResult<T> = Result<CreatedJson<T>, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_error_keeps_source_but_masks_public_message() {
        let error = AppError::internal(std::io::Error::other(
            "database password appeared in a diagnostic",
        ));

        assert_eq!(error.message(), "Internal server error");
        assert!(StdError::source(&error).is_some());
        assert!(
            format!("{error:?}").contains("database password appeared in a diagnostic"),
            "debug formatting must retain the source used by diagnostic mode"
        );
    }
}
