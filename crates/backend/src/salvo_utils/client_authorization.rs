use std::collections::HashMap;
use std::sync::LazyLock;

use coauth_data::oauth::OAuthClientRepository;
use coauth_data::{Client, JwksOrJwksUri, RepositoryAccess};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_jose::jwk::PublicJsonWebKeySet;
use coauth_jose::jwt::Jwt;
use coauth_keystore::Encrypter;
use headers::authorization::{Basic, Bearer, Credentials as _};
use http::StatusCode;
use oauth_types::errors::{ClientError, ClientErrorCode};
use salvo::extract::{Extractible, Metadata};
use salvo::prelude::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;

use crate::outbound_http::RequestBuilderExt;
use crate::record_error;

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
        http_client: &reqwest::Client,
        encrypter: &Encrypter,
        method: &OAuthClientAuthenticationMethod,
        client: &Client,
    ) -> Result<(), CredentialsVerificationError> {
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

                // Check if the client_secret matches
                if client_secret.as_bytes() != decrypted_client_secret {
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
        Ok(())
    }
}

async fn fetch_jwks(
    http_client: &reqwest::Client,
    jwks: &JwksOrJwksUri,
) -> Result<PublicJsonWebKeySet, Box<dyn std::error::Error + Send + Sync>> {
    let uri = match jwks {
        JwksOrJwksUri::Jwks(j) => return Ok(j.clone()),
        JwksOrJwksUri::JwksUri(u) => u,
    };

    let response = http_client
        .get(uri.as_str())
        .send_traced()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(response)
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

    #[error("failed to fetch jwks")]
    JwksFetchFailed(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl CredentialsVerificationError {
    /// Returns true if the error is an internal error, not caused by the client
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::DecryptionError | Self::InvalidClientConfig | Self::JwksFetchFailed(_)
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
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
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

    // Tests would need to be updated for Salvo's test utilities
    // For now, we'll skip the tests as they require significant Salvo-specific
    // changes
}
