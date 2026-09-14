use std::collections::HashMap;
use std::sync::LazyLock;

use coauth_data::oauth::OAuthClientRepository;
use coauth_data::{Client, JwksOrJwksUri, RepositoryAccess};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_jose::claims::{self, TimeOptions};
use coauth_jose::jwk::PublicJsonWebKeySet;
use coauth_jose::jwt::Jwt;
use coauth_keyring::Encrypter;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use headers::authorization::{Basic, Bearer, Credentials as _};
use http::StatusCode;
use salvo::extract::{Extractible, Metadata};
use salvo::prelude::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;

use crate::record_error;
use crate::services::dpop::{DpopError, DpopVerifier};

static JWT_BEARER_CLIENT_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Deserialize)]
struct AuthorizedForm<F = ()> {
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,

    #[serde(flatten)]
    inner: F,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Credentials {
    None {
        client_id: String,
    },
    ClientSecretBasic {
        client_id: String,
        client_secret: String,
    },
    ClientSecretPost {
        client_id: String,
        client_secret: String,
    },
    ClientAssertionJwtBearer {
        client_id: String,
        jwt: Box<Jwt<'static, HashMap<String, serde_json::Value>>>,
    },
    BearerToken {
        token: String,
    },
}

pub struct CredentialsVerificationParams<'a> {
    pub http_client: &'a reqwest::Client,
    pub encrypter: &'a Encrypter,
    pub method: &'a OAuthClientAuthenticationMethod,
    pub client: &'a Client,
    pub expected_audience: &'a str,
    pub now: chrono::DateTime<chrono::Utc>,
    pub replay_store: &'a DpopVerifier,
}

impl Credentials {
    /// Get the `client_id` of the credentials
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => Some(client_id),
            Credentials::BearerToken { .. } => None,
        }
    }

    /// Get the bearer token from the credentials.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        match self {
            Credentials::BearerToken { token } => Some(token),
            _ => None,
        }
    }

    /// Fetch the client from the database
    ///
    /// # Errors
    ///
    /// Returns an error if the client could not be found or if the underlying
    /// repository errored.
    pub async fn fetch<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<Option<Client>, E> {
        let client_id = match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => client_id,
            Credentials::BearerToken { .. } => return Ok(None),
        };

        repo.oauth_client().find_by_client_id(client_id).await
    }

    /// Verify credentials presented by the client for authentication
    ///
    /// # Errors
    ///
    /// Returns an error if the credentials are invalid.
    #[tracing::instrument(skip_all)]
    pub async fn verify(
        &self,
        params: CredentialsVerificationParams<'_>,
    ) -> Result<(), CredentialsVerificationError> {
        let CredentialsVerificationParams {
            http_client,
            encrypter,
            method,
            client,
            expected_audience,
            now,
            replay_store,
        } = params;
        match (self, method) {
            (Credentials::None { .. }, OAuthClientAuthenticationMethod::None) => {}

            (
                Credentials::ClientSecretPost { client_secret, .. },
                OAuthClientAuthenticationMethod::ClientSecretPost,
            )
            | (
                Credentials::ClientSecretBasic { client_secret, .. },
                OAuthClientAuthenticationMethod::ClientSecretBasic,
            ) => {
                // Decrypt the client_secret
                let encrypted_client_secret = client
                    .encrypted_client_secret
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let decrypted_client_secret = encrypter
                    .decrypt_string(encrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                let decrypted_client_secret = std::str::from_utf8(&decrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                if !crate::util::constant_time_token_eq(client_secret, decrypted_client_secret) {
                    return Err(CredentialsVerificationError::ClientSecretMismatch);
                }
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, .. },
                OAuthClientAuthenticationMethod::PrivateKeyJwt,
            ) => {
                // Get the client JWKS
                let jwks = client
                    .jwks
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let jwks = fetch_jwks(http_client, jwks)
                    .await
                    .map_err(CredentialsVerificationError::JwksFetchFailed)?;

                jwt.verify_with_jwks(&jwks)
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, .. },
                OAuthClientAuthenticationMethod::ClientSecretJwt,
            ) => {
                // Decrypt the client_secret
                let encrypted_client_secret = client
                    .encrypted_client_secret
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let decrypted_client_secret = encrypter
                    .decrypt_string(encrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                jwt.verify_with_shared_secret(decrypted_client_secret)
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
            }

            (..) => {
                return Err(CredentialsVerificationError::AuthenticationMethodMismatch);
            }
        }
        if let Credentials::ClientAssertionJwtBearer { client_id, jwt } = self {
            validate_client_assertion(jwt, client_id, expected_audience, now, replay_store).await?;
        }
        Ok(())
    }
}

async fn validate_client_assertion(
    jwt: &Jwt<'_, HashMap<String, Value>>,
    client_id: &str,
    expected_audience: &str,
    now: chrono::DateTime<chrono::Utc>,
    replay_store: &DpopVerifier,
) -> Result<(), CredentialsVerificationError> {
    let mut payload = jwt.payload().clone();
    let time_options = TimeOptions::new(now);
    claims::ISS
        .extract_required_with_options(&mut payload, client_id)
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    let subject = claims::SUB
        .extract_required(&mut payload)
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    if subject != client_id {
        return Err(CredentialsVerificationError::InvalidAssertionClaims);
    }
    claims::AUD
        .extract_required_with_options(&mut payload, &expected_audience.to_owned())
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    let expires_at = claims::EXP
        .extract_required_with_options(&mut payload, &time_options)
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    let issued_at = claims::IAT
        .extract_required_with_options(&mut payload, &time_options)
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    if *expires_at <= *issued_at || *expires_at - *issued_at > chrono::Duration::minutes(5) {
        return Err(CredentialsVerificationError::InvalidAssertionClaims);
    }
    let jti = claims::JTI
        .extract_required(&mut payload)
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    if jti.trim().is_empty() {
        return Err(CredentialsVerificationError::InvalidAssertionClaims);
    }
    let ttl = (*expires_at - now)
        .to_std()
        .map_err(|_| CredentialsVerificationError::InvalidAssertionClaims)?;
    let replay_key = format!("oauth-client-assertion:{client_id}:{jti}");
    replay_store
        .check_and_record_replay_key(&replay_key, now, ttl)
        .await
        .map_err(|error| match error {
            DpopError::JtiReplayed(_) => CredentialsVerificationError::AssertionReplayed,
            other => CredentialsVerificationError::AssertionReplayStore(other.to_string()),
        })?;
    Ok(())
}

async fn fetch_jwks(
    http_client: &reqwest::Client,
    jwks: &JwksOrJwksUri,
) -> Result<PublicJsonWebKeySet, Box<dyn std::error::Error + Send + Sync>> {
    let uri = match jwks {
        JwksOrJwksUri::Jwks(j) => return Ok(j.clone()),
        JwksOrJwksUri::JwksUri(u) => u,
    };
    Ok(crate::oidc_client::requests::jose::fetch_jwks(http_client, uri).await?)
}

#[derive(Debug, Error)]
pub enum CredentialsVerificationError {
    #[error("failed to decrypt client credentials")]
    DecryptionError,

    #[error("invalid client configuration")]
    InvalidClientConfig,

    #[error("client secret did not match")]
    ClientSecretMismatch,

    #[error("authentication method mismatch")]
    AuthenticationMethodMismatch,

    #[error("invalid assertion signature")]
    InvalidAssertionSignature,

    #[error("invalid client assertion claims")]
    InvalidAssertionClaims,

    #[error("client assertion was already used")]
    AssertionReplayed,

    #[error("client assertion replay store failed: {0}")]
    AssertionReplayStore(String),

    #[error("failed to fetch jwks")]
    JwksFetchFailed(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl CredentialsVerificationError {
    /// Returns true if the error is an internal error, not caused by the client
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::DecryptionError
                | Self::InvalidClientConfig
                | Self::JwksFetchFailed(_)
                | Self::AssertionReplayStore(_)
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientAuthorization<F = ()> {
    pub credentials: Credentials,
    pub form: Option<F>,
}

impl<F> ClientAuthorization<F> {
    /// Get the `client_id` from the credentials.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.credentials.client_id()
    }
}

#[derive(Debug, Error)]
pub enum ClientAuthorizationError {
    #[error("Invalid Authorization header")]
    InvalidHeader,

    #[error("Could not deserialize request body: {0}")]
    BadForm(String),

    #[error("client_id in form ({form:?}) does not match credential ({credential:?})")]
    ClientIdMismatch { credential: String, form: String },

    #[error("Unsupported client_assertion_type: {client_assertion_type}")]
    UnsupportedClientAssertion { client_assertion_type: String },

    #[error("No credentials were presented")]
    MissingCredentials,

    #[error("Invalid request")]
    InvalidRequest,

    #[error("Invalid client_assertion")]
    InvalidAssertion,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl Scribe for ClientAuthorizationError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(self, Self::Internal(_));

        let (status, body) = match &self {
            ClientAuthorizationError::InvalidHeader => (
                StatusCode::BAD_REQUEST,
                ClientError::new(
                    ClientErrorCode::InvalidRequest,
                    "Invalid Authorization header",
                ),
            ),

            ClientAuthorizationError::BadForm(err) => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidRequest).with_description(err.clone()),
            ),

            ClientAuthorizationError::ClientIdMismatch { .. } => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidGrant)
                    .with_description(format!("{self}")),
            ),

            ClientAuthorizationError::UnsupportedClientAssertion { .. } => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidRequest)
                    .with_description(format!("{self}")),
            ),

            ClientAuthorizationError::MissingCredentials => (
                StatusCode::BAD_REQUEST,
                ClientError::new(
                    ClientErrorCode::InvalidRequest,
                    "No credentials were presented",
                ),
            ),

            ClientAuthorizationError::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidRequest),
            ),

            ClientAuthorizationError::InvalidAssertion => (
                StatusCode::BAD_REQUEST,
                ClientError::new(ClientErrorCode::InvalidRequest, "Invalid client_assertion"),
            ),

            ClientAuthorizationError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ClientError::from(ClientErrorCode::ServerError).with_description(format!("{e}")),
            ),
        };

        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
        res.render(Json(body));
    }
}

impl<F: DeserializeOwned + Send> ClientAuthorization<F> {
    /// Extract client authorization from a Salvo request
    pub async fn extract_from_request(req: &mut Request) -> Result<Self, ClientAuthorizationError> {
        enum Authorization {
            Basic(String, String),
            Bearer(String),
        }

        // Sadly, the typed-header 'Authorization' doesn't let us check for both
        // Basic and Bearer at the same time, so we need to parse them manually
        let authorization = if let Some(header) = req.headers().get(http::header::AUTHORIZATION) {
            let bytes = header.as_bytes();
            if bytes.len() >= 6 && bytes[..6].eq_ignore_ascii_case(b"Basic ") {
                let Some(decoded) = Basic::decode(header) else {
                    return Err(ClientAuthorizationError::InvalidHeader);
                };

                Some(Authorization::Basic(
                    decoded.username().to_owned(),
                    decoded.password().to_owned(),
                ))
            } else if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
                let Some(decoded) = Bearer::decode(header) else {
                    return Err(ClientAuthorizationError::InvalidHeader);
                };

                Some(Authorization::Bearer(decoded.token().to_owned()))
            } else {
                return Err(ClientAuthorizationError::InvalidHeader);
            }
        } else {
            None
        };

        // Check content type to see if we should parse form
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let is_form = is_salvo_form_content_type(content_type);

        // Take the form value
        let (
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
            form,
        ) = if is_form {
            match req.parse_form::<AuthorizedForm<F>>().await {
                Ok(form) => (
                    form.client_id,
                    form.client_secret,
                    form.client_assertion_type,
                    form.client_assertion,
                    Some(form.inner),
                ),
                Err(e) => {
                    return Err(ClientAuthorizationError::BadForm(e.to_string()));
                }
            }
        } else {
            (None, None, None, None, None)
        };

        // And now, figure out the actual auth method
        let credentials = match (
            authorization,
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
        ) {
            (
                Some(Authorization::Basic(client_id, client_secret)),
                client_id_from_form,
                None,
                None,
                None,
            ) => {
                if let Some(client_id_from_form) = client_id_from_form {
                    // If the client_id was in the body, verify it matches with the header
                    if client_id != client_id_from_form {
                        return Err(ClientAuthorizationError::ClientIdMismatch {
                            credential: client_id,
                            form: client_id_from_form,
                        });
                    }
                }

                Credentials::ClientSecretBasic {
                    client_id,
                    client_secret,
                }
            }

            (None, Some(client_id), Some(client_secret), None, None) => {
                // Got both client_id and client_secret from the form
                Credentials::ClientSecretPost {
                    client_id,
                    client_secret,
                }
            }

            (None, Some(client_id), None, None, None) => {
                // Only got a client_id in the form
                Credentials::None { client_id }
            }

            (
                None,
                client_id_from_form,
                None,
                Some(client_assertion_type),
                Some(client_assertion),
            ) if client_assertion_type == JWT_BEARER_CLIENT_ASSERTION => {
                // Got a JWT bearer client_assertion
                let jwt: Jwt<'static, HashMap<String, Value>> = Jwt::try_from(client_assertion)
                    .map_err(|_| ClientAuthorizationError::InvalidAssertion)?;

                let client_id = if let Some(Value::String(client_id)) = jwt.payload().get("sub") {
                    client_id.clone()
                } else {
                    return Err(ClientAuthorizationError::InvalidAssertion);
                };

                if let Some(client_id_from_form) = client_id_from_form {
                    // If the client_id was in the body, verify it matches the one in the JWT
                    if client_id != client_id_from_form {
                        return Err(ClientAuthorizationError::ClientIdMismatch {
                            credential: client_id,
                            form: client_id_from_form,
                        });
                    }
                }

                Credentials::ClientAssertionJwtBearer {
                    client_id,
                    jwt: Box::new(jwt),
                }
            }

            (None, None, None, Some(client_assertion_type), Some(_client_assertion)) => {
                // Got another unsupported client_assertion
                return Err(ClientAuthorizationError::UnsupportedClientAssertion {
                    client_assertion_type,
                });
            }

            (Some(Authorization::Bearer(token)), None, None, None, None) => {
                // Got a bearer token
                Credentials::BearerToken { token }
            }

            (None, None, None, None, None) => {
                // Special case when there are no credentials anywhere
                return Err(ClientAuthorizationError::MissingCredentials);
            }

            _ => {
                // Every other combination is an invalid request
                return Err(ClientAuthorizationError::InvalidRequest);
            }
        };

        Ok(ClientAuthorization { credentials, form })
    }
}

fn is_salvo_form_content_type(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        || media_type.eq_ignore_ascii_case("multipart/form-data")
}

static CLIENT_AUTHORIZATION_METADATA: LazyLock<Metadata> =
    LazyLock::new(|| Metadata::new("ClientAuthorization"));

impl<'ex, F> Extractible<'ex> for ClientAuthorization<F>
where
    F: DeserializeOwned + Send,
{
    fn metadata() -> &'static Metadata {
        &CLIENT_AUTHORIZATION_METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
    ) -> Result<Self, ClientAuthorizationError> {
        Self::extract_from_request(req).await
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use chrono::{Duration, TimeZone as _, Utc};

    use super::*;

    fn assertion(claims: serde_json::Value) -> Jwt<'static, HashMap<String, Value>> {
        let header = Base64UrlUnpadded::encode_string(br#"{"alg":"HS256"}"#);
        let payload = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&claims).unwrap());
        Jwt::try_from(format!("{header}.{payload}.AA"))
            .unwrap()
            .into_owned()
    }

    #[tokio::test]
    async fn client_assertion_claims_are_endpoint_bound_and_single_use() {
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 4, 0, 0).unwrap();
        let jwt = assertion(serde_json::json!({
            "iss": "client-a",
            "sub": "client-a",
            "aud": "https://auth.example/oauth/token",
            "iat": now.timestamp(),
            "exp": (now + Duration::minutes(5)).timestamp(),
            "jti": "assertion-1"
        }));
        let replay = DpopVerifier::new();

        validate_client_assertion(
            &jwt,
            "client-a",
            "https://auth.example/oauth/token",
            now,
            &replay,
        )
        .await
        .unwrap();
        assert!(matches!(
            validate_client_assertion(
                &jwt,
                "client-a",
                "https://auth.example/oauth/token",
                now,
                &replay,
            )
            .await,
            Err(CredentialsVerificationError::AssertionReplayed)
        ));

        let wrong_endpoint = assertion(serde_json::json!({
            "iss": "client-a",
            "sub": "client-a",
            "aud": "https://auth.example/oauth/revoke",
            "iat": now.timestamp(),
            "exp": (now + Duration::minutes(5)).timestamp(),
            "jti": "assertion-2"
        }));
        assert!(matches!(
            validate_client_assertion(
                &wrong_endpoint,
                "client-a",
                "https://auth.example/oauth/token",
                now,
                &replay,
            )
            .await,
            Err(CredentialsVerificationError::InvalidAssertionClaims)
        ));
    }
}
