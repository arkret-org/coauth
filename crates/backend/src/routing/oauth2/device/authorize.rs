use chrono::Duration;
use coauth_data::oauth2::OAuth2DeviceCodeGrantParams;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{DeviceAuthorizationRequest, DeviceAuthorizationResponse, GrantType},
    scope::ScopeToken,
};
use rand::distr::{Alphanumeric, SampleString};
use salvo::{Extractible, prelude::*};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    routing::account::DepotExt,
    record_error,
    salvo_utils::client_authorization::{ClientAuthorization, CredentialsVerificationError},
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("client not found")]
    ClientNotFound,

    #[error("client {0} is not allowed to use the device code grant")]
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
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::routing::account::RouteError);
impl_from_error_for_route!(crate::salvo_utils::client_authorization::ClientAuthorizationError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(self, Self::Internal(_));

        let (status, body) = match self {
            Self::Internal(_) | Self::ClientCredentialsVerification { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ClientError::from(ClientErrorCode::ServerError),
            ),
            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => (
                StatusCode::UNAUTHORIZED,
                ClientError::from(ClientErrorCode::InvalidClient),
            ),
            Self::ClientNotAllowed(_) => (
                StatusCode::UNAUTHORIZED,
                ClientError::from(ClientErrorCode::UnauthorizedClient),
            ),
        };

        res.status_code(status);
        res.render(Json(body));

        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
    }
}

#[endpoint]
#[tracing::instrument(name = "routing.oauth2.device.request.post", skip_all)]
pub async fn post(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(response) => {
            res.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            res.headers_mut().insert(
                http::header::PRAGMA,
                http::HeaderValue::from_static("no-cache"),
            );
            res.render(Json(response));
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<DeviceAuthorizationResponse, RouteError> {
    let client_authorization: ClientAuthorization<DeviceAuthorizationRequest> =
        ClientAuthorization::extract(req, depot).await?;

    let url_builder = depot.url_builder()?;
    let http_client = depot.http_client()?;
    let encrypter = depot.encrypter()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = crate::routing::account::extract_bound_activity_tracker(req, depot);

    let mut rng = crate::routing::account::make_rng();
    let clock = crate::routing::account::make_clock();

    let user_agent: Option<String> = req.header("user-agent");

    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // Reuse the token endpoint auth method to verify the client
    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed(client.id))?;

    client_authorization
        .credentials
        .verify(&http_client, &encrypter, method, &client)
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

    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(RouteError::ClientNotAllowed(client.id));
    }

    let scope = client_authorization
        .form
        .and_then(|f| f.scope)
        // XXX: Is this really how we do empty scopes?
        .unwrap_or(std::iter::empty::<ScopeToken>().collect());

    let expires_in = Duration::microseconds(20 * 60 * 1000 * 1000);

    let ip_address = activity_tracker.ip();

    let device_code = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let user_code = Alphanumeric
        .sample_string(&mut rand::rng(), 6)
        .to_uppercase();

    let device_code = repo
        .oauth2_device_code_grant()
        .add(
            &mut rng,
            &clock,
            OAuth2DeviceCodeGrantParams {
                client: &client,
                scope,
                device_code,
                user_code,
                expires_in,
                user_agent,
                ip_address,
            },
        )
        .await?;

    repo.save().await?;

    let response = DeviceAuthorizationResponse {
        device_code: device_code.device_code,
        user_code: device_code.user_code.clone(),
        verification_uri: url_builder.device_code_link(),
        verification_uri_complete: Some(url_builder.device_code_link_full(device_code.user_code)),
        expires_in,
        interval: Some(Duration::microseconds(5 * 1000 * 1000)),
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use oauth2_types::{
        registration::ClientRegistrationResponse, requests::DeviceAuthorizationResponse,
    };

    use crate::routing::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_device_code_request() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let state = TestState::from_pool(pool.clone()).await.unwrap();

        // Provision a client
        let request = Request::post("/oauth2/registration").json(serde_json::json!({
            "client_uri": "https://example.com/",
            "token_endpoint_auth_method": "none",
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
            "response_types": [],
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;

        // Test the happy path: the client is allowed to use the device code grant type
        let request = Request::post("/oauth2/device").form(serde_json::json!({
            "client_id": client_id,
            "scope": "openid",
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: DeviceAuthorizationResponse = response.json();
        assert_eq!(response.device_code.len(), 32);
        assert_eq!(response.user_code.len(), 6);
    }
}
