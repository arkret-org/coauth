use std::sync::{Arc, LazyLock};

use coauth_config::ContrixConfig;
use coauth_data::{
    BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, SiteConfig, SystemClock, UrlBuilder,
};
use coauth_keystore::Keystore;
use coauth_matrix::HomeserverAdmin;
use coauth_policy::Policy;
use coauth_templates::Templates;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{AccessTokenRequest, AccessTokenResponse},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::{Extractible, prelude::*};
use thiserror::Error;
use ulid::Ulid;

use super::token_service::{
    self, AuthorizationCodeExchangeError, ClientCredentialsGrantError, DeviceCodeExchangeError,
    RefreshTokenExchangeError,
};
use crate::{
    routing::METER,
    salvo_utils::client_authorization::{ClientAuthorization, CredentialsVerificationError},
};

static TOKEN_REQUEST_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.oauth2.token_request")
        .with_description("How many OAuth 2.0 token requests have gone through")
        .with_unit("{request}")
        .build()
});
const GRANT_TYPE: Key = Key::from_static_str("grant_type");
const RESULT: Key = Key::from_static_str("successful");

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("pkce verification failed")]
    PkceVerification(#[from] oauth2_types::pkce::CodeChallengeError),

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed to use the token endpoint: {0}")]
    ClientNotAllowed(Ulid),

    #[error("invalid client credentials for client {client_id}")]
    InvalidClientCredentials {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("could not verify client credentials for client {client_id}")]
    ClientCredentialsVerification {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("grant not found")]
    GrantNotFound,

    #[error("invalid grant {0}")]
    InvalidGrant(Ulid),

    #[error("refresh token not found")]
    RefreshTokenNotFound,

    #[error("refresh token {0} is invalid")]
    RefreshTokenInvalid(Ulid),

    #[error("session {0} is invalid")]
    SessionInvalid(Ulid),

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIDMismatch { expected: Ulid, actual: Ulid },

    #[error("policy denied the request: {0}")]
    DeniedByPolicy(coauth_policy::EvaluationResult),

    #[error("unsupported grant type")]
    UnsupportedGrantType,

    #[error("client {0} is not authorized to use this grant type")]
    UnauthorizedClient(Ulid),

    #[error("unexpected client {was} (expected {expected})")]
    UnexptectedClient { was: Ulid, expected: Ulid },

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

    #[error("failed to load oauth session {0}")]
    NoSuchOAuthSession(Ulid),

    #[error(
        "failed to load the next refresh token ({next:?}) from the previous one ({previous:?})"
    )]
    NoSuchNextRefreshToken { next: Ulid, previous: Ulid },

    #[error(
        "failed to load the access token ({access_token:?}) associated with the next refresh token ({refresh_token:?})"
    )]
    NoSuchNextAccessToken {
        access_token: Ulid,
        refresh_token: Ulid,
    },

    #[error("no access token associated with the refresh token {refresh_token:?}")]
    NoAccessTokenOnRefreshToken { refresh_token: Ulid },

    #[error("device code grant expired")]
    DeviceCodeExpired,

    #[error("device code grant is still pending")]
    DeviceCodePending,

    #[error("device code grant was rejected")]
    DeviceCodeRejected,

    #[error("device code grant was already exchanged")]
    DeviceCodeExchanged,

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        TOKEN_REQUEST_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);

        match self {
            Self::Internal(_)
            | Self::ClientCredentialsVerification { .. }
            | Self::NoSuchBrowserSession(_)
            | Self::NoSuchOAuthSession(_)
            | Self::ProvisionDeviceFailed(_)
            | Self::NoSuchNextRefreshToken { .. }
            | Self::NoSuchNextAccessToken { .. }
            | Self::NoAccessTokenOnRefreshToken { .. } => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
            }

            Self::BadRequest => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRequest)));
            }

            Self::PkceVerification(ref err) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description(format!("PKCE verification failed: {err}")),
                ));
            }

            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidClient)));
            }

            Self::ClientNotAllowed(_)
            | Self::UnauthorizedClient(_)
            | Self::UnexptectedClient { .. } => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::UnauthorizedClient)));
            }

            Self::DeniedByPolicy(ref evaluation) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidScope).with_description(
                        evaluation
                            .violations
                            .iter()
                            .map(|violation| violation.msg.clone())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ));
            }

            Self::DeviceCodeRejected => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ClientError::from(ClientErrorCode::AccessDenied)));
            }

            Self::DeviceCodeExpired => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ClientError::from(ClientErrorCode::ExpiredToken)));
            }

            Self::DeviceCodePending => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ClientError::from(
                    ClientErrorCode::AuthorizationPending,
                )));
            }

            Self::InvalidGrant(_)
            | Self::DeviceCodeExchanged
            | Self::RefreshTokenNotFound
            | Self::RefreshTokenInvalid(_)
            | Self::SessionInvalid(_)
            | Self::ClientIDMismatch { .. }
            | Self::GrantNotFound => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidGrant)));
            }

            Self::UnsupportedGrantType => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(
                    ClientErrorCode::UnsupportedGrantType,
                )));
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::salvo_utils::client_authorization::ClientAuthorizationError);

// ---------------------------------------------------------------------------
// Map service-level errors into RouteError
// ---------------------------------------------------------------------------

impl From<AuthorizationCodeExchangeError> for RouteError {
    fn from(e: AuthorizationCodeExchangeError) -> Self {
        match e {
            AuthorizationCodeExchangeError::UnauthorizedClient(id) => Self::UnauthorizedClient(id),
            AuthorizationCodeExchangeError::GrantNotFound => Self::GrantNotFound,
            AuthorizationCodeExchangeError::InvalidGrant(id) => Self::InvalidGrant(id),
            AuthorizationCodeExchangeError::PkceVerification(err) => Self::PkceVerification(err),
            AuthorizationCodeExchangeError::BadRequest => Self::BadRequest,
            AuthorizationCodeExchangeError::UnexpectedClient { was, expected } => {
                Self::UnexptectedClient { was, expected }
            }
            AuthorizationCodeExchangeError::NoSuchBrowserSession(id) => {
                Self::NoSuchBrowserSession(id)
            }
            AuthorizationCodeExchangeError::NoSuchOAuthSession(id) => Self::NoSuchOAuthSession(id),
            AuthorizationCodeExchangeError::ProvisionDeviceFailed(err) => {
                Self::ProvisionDeviceFailed(err)
            }
            AuthorizationCodeExchangeError::Repository(err) => Self::Internal(Box::new(err)),
            AuthorizationCodeExchangeError::Internal(err) => Self::Internal(err),
        }
    }
}

impl From<RefreshTokenExchangeError> for RouteError {
    fn from(e: RefreshTokenExchangeError) -> Self {
        match e {
            RefreshTokenExchangeError::UnauthorizedClient(id) => Self::UnauthorizedClient(id),
            RefreshTokenExchangeError::RefreshTokenNotFound => Self::RefreshTokenNotFound,
            RefreshTokenExchangeError::RefreshTokenInvalid(id) => Self::RefreshTokenInvalid(id),
            RefreshTokenExchangeError::SessionInvalid(id) => Self::SessionInvalid(id),
            RefreshTokenExchangeError::ClientIdMismatch { expected, actual } => {
                Self::ClientIDMismatch { expected, actual }
            }
            RefreshTokenExchangeError::NoSuchOAuthSession(id) => Self::NoSuchOAuthSession(id),
            RefreshTokenExchangeError::NoSuchNextRefreshToken { next, previous } => {
                Self::NoSuchNextRefreshToken { next, previous }
            }
            RefreshTokenExchangeError::NoSuchNextAccessToken {
                access_token,
                refresh_token,
            } => Self::NoSuchNextAccessToken {
                access_token,
                refresh_token,
            },
            RefreshTokenExchangeError::NoAccessTokenOnRefreshToken { refresh_token } => {
                Self::NoAccessTokenOnRefreshToken { refresh_token }
            }
            RefreshTokenExchangeError::Repository(err) => Self::Internal(Box::new(err)),
        }
    }
}

impl From<ClientCredentialsGrantError> for RouteError {
    fn from(e: ClientCredentialsGrantError) -> Self {
        match e {
            ClientCredentialsGrantError::UnauthorizedClient(id) => Self::UnauthorizedClient(id),
            ClientCredentialsGrantError::DeniedByPolicy(res) => Self::DeniedByPolicy(res),
            ClientCredentialsGrantError::Repository(err) => Self::Internal(Box::new(err)),
            ClientCredentialsGrantError::Internal(err) => Self::Internal(err),
        }
    }
}

impl From<DeviceCodeExchangeError> for RouteError {
    fn from(e: DeviceCodeExchangeError) -> Self {
        match e {
            DeviceCodeExchangeError::UnauthorizedClient(id) => Self::UnauthorizedClient(id),
            DeviceCodeExchangeError::GrantNotFound => Self::GrantNotFound,
            DeviceCodeExchangeError::ClientIdMismatch { expected, actual } => {
                Self::ClientIDMismatch { expected, actual }
            }
            DeviceCodeExchangeError::DeviceCodeExpired => Self::DeviceCodeExpired,
            DeviceCodeExchangeError::DeviceCodePending => Self::DeviceCodePending,
            DeviceCodeExchangeError::DeviceCodeRejected => Self::DeviceCodeRejected,
            DeviceCodeExchangeError::DeviceCodeExchanged => Self::DeviceCodeExchanged,
            DeviceCodeExchangeError::NoSuchBrowserSession(id) => Self::NoSuchBrowserSession(id),
            DeviceCodeExchangeError::ProvisionDeviceFailed(err) => Self::ProvisionDeviceFailed(err),
            DeviceCodeExchangeError::Repository(err) => Self::Internal(Box::new(err)),
            DeviceCodeExchangeError::Internal(err) => Self::Internal(err),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

#[endpoint]
#[tracing::instrument(name = "routing.oauth2.token.post", skip_all)]
pub async fn post(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(reply) => {
            res.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            res.headers_mut().insert(
                http::header::PRAGMA,
                http::HeaderValue::from_static("no-cache"),
            );
            res.render(Json(reply));
        }
        Err(e) => {
            tracing::error!(error = %e, error_debug = ?e, "OAuth2 token endpoint failed");
            e.render(res);
        }
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<AccessTokenResponse, RouteError> {
    let client_authorization: ClientAuthorization<AccessTokenRequest> =
        ClientAuthorization::extract(req, depot).await?;

    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .expect("reqwest::Client not found in depot");
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let contrix_config = depot
        .get::<ContrixConfig>("contrix_config")
        .cloned()
        .unwrap_or_default();
    let homeserver = depot
        .get::<Arc<dyn HomeserverAdmin>>("homeserver_admin")
        .expect("HomeserverAdmin not found in depot");
    let site_config = depot
        .get::<SiteConfig>("site_config")
        .expect("SiteConfig not found in depot");
    let encrypter = depot
        .get::<coauth_keystore::Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let templates = depot
        .get::<Templates>("templates")
        .expect("Templates not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = crate::routing::account::extract_bound_activity_tracker(req, depot);
    let policy_factory = depot
        .get::<Arc<coauth_policy::PolicyFactory>>("policy_factory")
        .expect("PolicyFactory not found in depot");

    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng =
        Box::new(ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;
    let policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let user_agent: Option<String> = req.header("user-agent");

    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed(client.id))?;

    client_authorization
        .credentials
        .verify(http_client, encrypter, method, &client)
        .await
        .map_err(|err| {
            // Classify the error differently, depending on whether it's an 'internal'
            // error, or just because the client presented invalid credentials.
            if err.is_internal() {
                RouteError::ClientCredentialsVerification {
                    client_id: client.id,
                    source: err,
                }
            } else {
                RouteError::InvalidClientCredentials {
                    client_id: client.id,
                    source: err,
                }
            }
        })?;

    let form = client_authorization.form.ok_or(RouteError::BadRequest)?;

    let grant_type = form.grant_type().to_string();
    tracing::info!(
        oauth2_client.id = %client.id,
        grant_type = %grant_type,
        "Handling OAuth2 token request"
    );

    let (reply, repo) = match form {
        AccessTokenRequest::AuthorizationCode(grant) => {
            let (reply, repo) = token_service::exchange_authorization_code(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                key_store,
                url_builder,
                &contrix_config,
                site_config,
                repo,
                homeserver,
                templates,
                user_agent,
            )
            .await?;
            (reply, repo)
        }
        AccessTokenRequest::RefreshToken(grant) => {
            let (reply, repo) = token_service::handle_refresh_token(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                site_config,
                repo,
                user_agent,
            )
            .await?;
            (reply, repo)
        }
        AccessTokenRequest::ClientCredentials(grant) => {
            let (reply, repo) = token_service::handle_client_credentials(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                site_config,
                repo,
                policy,
                user_agent,
            )
            .await?;
            (reply, repo)
        }
        AccessTokenRequest::DeviceCode(grant) => {
            let (reply, repo) = token_service::exchange_device_code(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                key_store,
                url_builder,
                &contrix_config,
                site_config,
                repo,
                homeserver,
                user_agent,
            )
            .await?;
            (reply, repo)
        }
        _ => {
            tracing::warn!(
                oauth2_client.id = %client.id,
                grant_type = %grant_type,
                "Client requested an unsupported grant type at the token endpoint"
            );
            return Err(RouteError::UnsupportedGrantType);
        }
    };

    repo.save().await?;

    tracing::debug!(
        oauth2_client.id = %client.id,
        grant_type = %grant_type,
        "OAuth2 token request completed successfully"
    );

    TOKEN_REQUEST_COUNTER.add(
        1,
        &[
            KeyValue::new(GRANT_TYPE, grant_type),
            KeyValue::new(RESULT, "success"),
        ],
    );

    Ok(reply)
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
