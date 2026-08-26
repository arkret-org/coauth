use std::sync::Arc;

use coauth_data::{BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, SystemClock};
use coauth_keystore::Encrypter;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::requests::RevocationRequest;
use coauth_principal::ConnectorAdmin;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::Extractible;
use salvo::prelude::*;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::oauth::revocation_service;
use crate::salvo_utils::client_authorization::{ClientAuthorization, CredentialsVerificationError};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

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

    /// An error from the revocation service layer.
    #[error(transparent)]
    Revocation(#[from] revocation_service::RevocationError),
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            Self::Internal(_) | Self::ClientCredentialsVerification { .. } => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
            }

            Self::BadRequest => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRequest)));
            }

            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidClient)));
            }

            Self::ClientNotAllowed => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::UnauthorizedClient)));
            }

            Self::Revocation(ref inner) => {
                use revocation_service::RevocationError;
                match inner {
                    RevocationError::Repository(_) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
                    }
                    RevocationError::UnsupportedTokenType => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(ClientError::from(
                            ClientErrorCode::UnsupportedTokenType,
                        )));
                    }
                    RevocationError::UnknownToken => {
                        // If the token is unknown, we still return a 200 OK response.
                        res.status_code(StatusCode::OK);
                    }
                    RevocationError::UnauthorizedClient => {
                        res.status_code(StatusCode::UNAUTHORIZED);
                        res.render(Json(ClientError::from(ClientErrorCode::UnauthorizedClient)));
                    }
                }
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventId::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::salvo_utils::client_authorization::ClientAuthorizationError);

#[handler]
#[tracing::instrument(name = "handlers.oauth.revoke.post", skip_all)]
pub async fn post(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(()) => {
            res.status_code(StatusCode::OK);
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(req: &mut Request, depot: &mut Depot) -> Result<(), RouteError> {
    let client_authorization: ClientAuthorization<RevocationRequest> =
        ClientAuthorization::extract(req, depot).await?;

    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .expect("reqwest::Client not found in depot");
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let url_builder = depot
        .get::<coauth_data::UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let assertion_replay = depot
        .get::<crate::services::dpop::DpopVerifier>("dpop_verifier")
        .expect("DpopVerifier not found in depot");
    let assertion_audience = url_builder.oauth_revocation_endpoint().to_string();
    let principal_server = depot
        .get::<Arc<dyn ConnectorAdmin>>("principal_server_admin")
        .expect("ConnectorAdmin not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    #[allow(clippy::box_default)] // Box::default() doesn't apply to dyn Clock+Send
    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng =
        Box::new(ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;

    // Check if the caller authenticated with the PrincipalServer admin secret
    // (bearer token).  When that is the case, skip the client-ownership
    // check so that the PrincipalServer can revoke any token on behalf of a
    // client.
    let admin_mode = if let Some(token) = client_authorization.credentials.bearer_token() {
        principal_server
            .verify_token(token)
            .await
            .map_err(|e| RouteError::Internal(e.into()))?
    } else {
        false
    };

    let client_id = if admin_mode {
        // Admin-secret authenticated: no client-ownership check needed.
        None
    } else {
        let client = client_authorization
            .credentials
            .fetch(&mut repo)
            .await?
            .ok_or(RouteError::ClientNotFound)?;

        let method = client
            .token_endpoint_auth_method
            .as_ref()
            .ok_or(RouteError::ClientNotAllowed)?;

        client_authorization
            .credentials
            .verify(
                http_client,
                encrypter,
                method,
                &client,
                &assertion_audience,
                clock.now(),
                assertion_replay,
            )
            .await
            .map_err(|err| {
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

        Some(client.id)
    };

    let Some(form) = client_authorization.form else {
        return Err(RouteError::BadRequest);
    };

    // Delegate the actual token lookup, validation, and session termination
    // to the service layer.
    revocation_service::revoke_token(
        &mut repo,
        &mut rng,
        &*clock,
        &activity_tracker,
        &form.token,
        form.token_type_hint,
        client_id,
    )
    .await?;

    repo.save().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
