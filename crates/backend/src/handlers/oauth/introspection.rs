use std::sync::{Arc, LazyLock};

use coauth_config::ArkretConfig;
use coauth_data::{BoxClock, BoxRepository, BoxRepositoryFactory, SystemClock, UrlBuilder};
use coauth_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use coauth_keystore::Encrypter;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::requests::{IntrospectionRequest, IntrospectionResponse};
use coauth_principal::ConnectorAdmin;
use opentelemetry::metrics::Counter;
use opentelemetry::{Key, KeyValue};
use salvo::Extractible;
use salvo::prelude::*;
use thiserror::Error;
use ulid::Ulid;

use super::introspection_service;
use crate::handlers::{ActivityTracker, METER};
use crate::salvo_utils::client_authorization::{ClientAuthorization, CredentialsVerificationError};

static INTROSPECTION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.oauth.introspection_request")
        .with_description("Number of OAuth introspection requests")
        .with_unit("{request}")
        .build()
});

const KIND: Key = Key::from_static_str("kind");
const ACTIVE: Key = Key::from_static_str("active");

#[derive(Debug, Error)]
pub enum RouteError {
    /// An internal error occurred.
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The client could not be found.
    #[error("could not find client")]
    ClientNotFound,

    /// The client is not allowed to introspect.
    #[error("client {0} is not allowed to introspect")]
    NotAllowed(Ulid),

    /// An error from the introspection service indicating the token is
    /// inactive (unknown, invalid, expired, etc.).
    #[error(transparent)]
    Inactive(#[from] introspection_service::IntrospectionError),

    #[error("bad request")]
    BadRequest,

    #[error("failed to verify token")]
    FailedToVerifyToken(#[source] anyhow::Error),

    #[error(transparent)]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),

    #[error("bearer token presented is invalid")]
    InvalidBearerToken,
}

const INACTIVE: IntrospectionResponse = IntrospectionResponse {
    active: false,
    scope: None,
    client_id: None,
    username: None,
    token_type: None,
    exp: None,
    expires_in: None,
    iat: None,
    nbf: None,
    sub: None,
    aud: None,
    iss: None,
    jti: None,
    arkret_principal_did: None,
    arkret_device_id: None,
    arkret_session_id: None,
};

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            e @ (Self::Internal(_) | Self::FailedToVerifyToken(_)) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(
                    ClientError::from(ClientErrorCode::ServerError).with_description(e.to_string()),
                ));
            }
            Self::ClientNotFound => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidClient)));
            }
            Self::ClientCredentialsVerification(e) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClient)
                        .with_description(e.to_string()),
                ));
            }
            e @ Self::InvalidBearerToken => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(
                    ClientError::from(ClientErrorCode::AccessDenied)
                        .with_description(e.to_string()),
                ));
            }

            Self::Inactive(ref inner) => {
                // Map service-level errors that indicate repo/load failures to
                // 500; everything else means the token is simply inactive.
                use introspection_service::IntrospectionError;
                match inner {
                    IntrospectionError::Repository(_)
                    | IntrospectionError::CantLoadOAuthSession(_)
                    | IntrospectionError::CantLoadPersonalSession(_)
                    | IntrospectionError::CantLoadUser(_)
                    | IntrospectionError::CantLoadOAuthClient(_) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(
                            ClientError::from(ClientErrorCode::ServerError)
                                .with_description(self.to_string()),
                        ));
                    }
                    _ => {
                        INTROSPECTION_COUNTER.add(1, &[KeyValue::new(ACTIVE.clone(), false)]);
                        res.render(Json(INACTIVE));
                    }
                }
            }

            Self::NotAllowed(_) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::AccessDenied)));
            }

            Self::BadRequest => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRequest)));
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventId::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::salvo_utils::client_authorization::ClientAuthorizationError);

#[handler]
#[tracing::instrument(name = "handlers.oauth.introspection.post", skip_all)]
pub async fn post(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(reply) => {
            res.render(Json(reply));
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<IntrospectionResponse, RouteError> {
    let ClientAuthorization { credentials, form } =
        ClientAuthorization::<IntrospectionRequest>::extract(req, depot).await?;

    // Pull infrastructure off the depot, mapping a missing entry to a 500
    // instead of panicking so a mis-wired server returns an error response
    // rather than crashing the worker thread.
    let depot_missing = |what: &str| {
        RouteError::Internal(Box::new(std::io::Error::other(format!(
            "{what} not found in depot"
        ))))
    };

    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .map_err(|_| depot_missing("reqwest::Client"))?;
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .map_err(|_| depot_missing("Encrypter"))?;
    let principal_server = depot
        .get::<Arc<dyn ConnectorAdmin>>("principal_server_admin")
        .map_err(|_| depot_missing("ConnectorAdmin"))?;
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .map_err(|_| depot_missing("BoxRepositoryFactory"))?;
    let activity_tracker = depot
        .get::<ActivityTracker>("activity_tracker")
        .map_err(|_| depot_missing("ActivityTracker"))?;
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .map_err(|_| depot_missing("UrlBuilder"))?;
    let assertion_replay = depot
        .get::<crate::services::dpop::DpopVerifier>("dpop_verifier")
        .map_err(|_| depot_missing("DpopVerifier"))?;
    let assertion_audience = url_builder.oauth_introspection_endpoint().to_string();
    let arkret_config = depot
        .get::<ArkretConfig>("arkret_config")
        .cloned()
        .unwrap_or_default();

    #[allow(clippy::box_default)] // Box::default() doesn't apply to dyn Clock+Send
    let clock: BoxClock = Box::new(SystemClock::default());

    let mut repo: BoxRepository = repo_factory.create().await?;

    // Only the trusted Principal Server (homeserver bearer) is entitled to
    // the arkret device/principal/session association fields; arbitrary
    // confidential OIDC clients get the redacted RFC 7662 view.
    let disclosure = if let Some(token) = credentials.bearer_token() {
        if !principal_server
            .verify_token(token)
            .await
            .map_err(RouteError::FailedToVerifyToken)?
        {
            return Err(RouteError::InvalidBearerToken);
        }
        introspection_service::ArkretAssociationDisclosure::Full
    } else {
        // Otherwise, it presented regular client credentials, so we verify them
        let client = credentials
            .fetch(&mut repo)
            .await?
            .ok_or(RouteError::ClientNotFound)?;

        // Only confidential clients are allowed to introspect
        let method = match &client.token_endpoint_auth_method {
            None | Some(OAuthClientAuthenticationMethod::None) => {
                return Err(RouteError::NotAllowed(client.id));
            }
            Some(c) => c,
        };

        credentials
            .verify(
                http_client,
                encrypter,
                method,
                &client,
                &assertion_audience,
                clock.now(),
                assertion_replay,
            )
            .await?;
        introspection_service::ArkretAssociationDisclosure::Redacted
    };

    let Some(form) = form else {
        return Err(RouteError::BadRequest);
    };

    // Delegate the actual token lookup and validation to the service layer.
    let reply = introspection_service::introspect_token(
        &mut repo,
        &*clock,
        url_builder,
        &arkret_config,
        activity_tracker,
        &form.token,
        form.token_type_hint,
        disclosure,
    )
    .await?;

    // Record the counter for the active introspection result.
    let kind_value = match reply.token_type {
        Some(OAuthTokenTypeHint::RefreshToken) => "oauth_refresh_token",
        Some(OAuthTokenTypeHint::AccessToken) => "oauth_access_token",
        _ => "unknown",
    };
    // Distinguish personal access tokens by checking if there is no jti
    // (personal tokens don't have one in the current implementation).
    // This matches the original handler's counter labelling.
    let kind_value = if reply.jti.is_none()
        && matches!(reply.token_type, Some(OAuthTokenTypeHint::AccessToken))
    {
        "personal_access_token"
    } else {
        kind_value
    };
    INTROSPECTION_COUNTER.add(
        1,
        &[KeyValue::new(KIND, kind_value), KeyValue::new(ACTIVE, true)],
    );

    repo.save().await?;

    Ok(reply)
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
