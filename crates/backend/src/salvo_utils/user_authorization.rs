use std::collections::HashMap;
use std::error::Error;
use std::sync::LazyLock;

use coauth_data::oauth::{OAuthAccessTokenRepository, OAuthSessionRepository};
use coauth_data::{Clock, RepositoryAccess, Session};
use coauth_oauth_types::scope::ScopeToken;
use headers::authorization::{Bearer, Credentials};
use headers::{Header, HeaderMapExt, HeaderName};
use http::header::WWW_AUTHENTICATE;
use http::{HeaderMap, HeaderValue, StatusCode};
use salvo::extract::{Extractible, Metadata};
use salvo::prelude::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct AuthorizedForm<F> {
    #[serde(default)]
    access_token: Option<String>,

    #[serde(flatten)]
    inner: F,
}

#[derive(Debug)]
enum AccessToken {
    Form(String),
    Header(String),
    None,
}

impl AccessToken {
    async fn fetch<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<(coauth_data::AccessToken, Session), AuthorizationVerificationError<E>> {
        let token = match self {
            AccessToken::Form(t) | AccessToken::Header(t) => t,
            AccessToken::None => return Err(AuthorizationVerificationError::MissingToken),
        };

        let token = repo
            .oauth_access_token()
            .find_by_token(token.as_str())
            .await?
            .ok_or(AuthorizationVerificationError::InvalidToken)?;

        let session = repo
            .oauth_session()
            .lookup(token.session_id)
            .await?
            .ok_or(AuthorizationVerificationError::InvalidToken)?;

        Ok((token, session))
    }
}

#[derive(Debug)]
pub struct UserAuthorization<F = ()> {
    access_token: AccessToken,
    form: Option<F>,
}

impl<F: Send> UserAuthorization<F> {
    /// Verify a user authorization and return the session.
    ///
    /// `required_scopes` is an optional list of scopes the caller must have
    /// granted on the underlying session; an empty slice disables the check.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, if the user session ended,
    /// or if the session is missing any of the required scopes.
    pub async fn protected<E>(
        self,
        repo: &mut impl RepositoryAccess<Error = E>,
        clock: &impl Clock,
        required_scopes: &[&ScopeToken],
    ) -> Result<Session, AuthorizationVerificationError<E>> {
        let (token, session) = self.access_token.fetch(repo).await?;

        if !token.is_valid(clock.now()) || !session.is_valid() {
            return Err(AuthorizationVerificationError::InvalidToken);
        }

        ensure_required_scopes(&session, required_scopes)?;

        if !token.is_used() {
            // Mark the token as used
            repo.oauth_access_token().mark_used(clock, token).await?;
        }

        Ok(session)
    }
}

fn ensure_required_scopes<E>(
    session: &Session,
    required_scopes: &[&ScopeToken],
) -> Result<(), AuthorizationVerificationError<E>> {
    for scope in required_scopes {
        if !session.scope.contains(scope.as_str()) {
            return Err(AuthorizationVerificationError::InsufficientScope);
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum UserAuthorizationError {
    InvalidHeader,
    TokenInFormAndHeader,
    BadForm(String),
    Internal(Box<dyn Error + Send + Sync>),
}

#[derive(Debug, Error)]
pub enum AuthorizationVerificationError<E> {
    #[error("missing token")]
    MissingToken,

    #[error("invalid token")]
    InvalidToken,

    #[error("insufficient scope")]
    InsufficientScope,

    #[error("missing form")]
    MissingForm,

    #[error(transparent)]
    Internal(#[from] E),
}

enum BearerError {
    InvalidRequest,
    InvalidToken,
}

impl BearerError {
    fn error(&self) -> HeaderValue {
        match self {
            BearerError::InvalidRequest => HeaderValue::from_static("invalid_request"),
            BearerError::InvalidToken => HeaderValue::from_static("invalid_token"),
        }
    }
}

enum WwwAuthenticate {
    Bearer {
        realm: Option<HeaderValue>,
        error: BearerError,
        error_description: Option<HeaderValue>,
    },
}

impl Header for WwwAuthenticate {
    fn name() -> &'static HeaderName {
        &WWW_AUTHENTICATE
    }

    fn decode<'i, I>(_values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        Err(headers::Error::invalid())
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, values: &mut E) {
        let (scheme, params) = match self {
            WwwAuthenticate::Bearer {
                realm,
                error,
                error_description,
            } => {
                let mut params = HashMap::new();
                params.insert("error", error.error());

                if let Some(realm) = realm {
                    params.insert("realm", realm.clone());
                }

                if let Some(error_description) = error_description {
                    params.insert("error_description", error_description.clone());
                }

                ("Bearer", params)
            }
        };

        let params = params.into_iter().map(|(k, v)| format!(" {k}={v:?}"));
        let value: String = std::iter::once(scheme.to_owned()).chain(params).collect();
        let value = HeaderValue::from_str(&value).unwrap();
        values.extend(std::iter::once(value));
    }
}

impl Scribe for UserAuthorizationError {
    fn render(self, res: &mut Response) {
        match self {
            Self::BadForm(_) | Self::InvalidHeader | Self::TokenInFormAndHeader => {
                let mut headers = HeaderMap::new();
                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidRequest,
                    error_description: None,
                });
                res.status_code(StatusCode::BAD_REQUEST);
                for (name, value) in &headers {
                    res.headers_mut().insert(name.clone(), value.clone());
                }
            }
            Self::Internal(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(e.to_string()));
            }
        }
    }
}

impl<E> Scribe for AuthorizationVerificationError<E>
where
    E: ToString + Send,
{
    fn render(self, res: &mut Response) {
        match self {
            Self::MissingForm | Self::MissingToken => {
                let mut headers = HeaderMap::new();
                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidRequest,
                    error_description: None,
                });
                res.status_code(StatusCode::BAD_REQUEST);
                for (name, value) in &headers {
                    res.headers_mut().insert(name.clone(), value.clone());
                }
            }
            Self::InvalidToken | Self::InsufficientScope => {
                let mut headers = HeaderMap::new();
                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidToken,
                    error_description: None,
                });
                res.status_code(StatusCode::BAD_REQUEST);
                for (name, value) in &headers {
                    res.headers_mut().insert(name.clone(), value.clone());
                }
            }
            Self::Internal(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(e.to_string()));
            }
        }
    }
}

impl<F: DeserializeOwned + Send> UserAuthorization<F> {
    /// Extract user authorization from a Salvo request
    pub async fn extract_from_request(req: &mut Request) -> Result<Self, UserAuthorizationError> {
        // Take the Authorization header
        let token_from_header = if let Some(header) = req.headers().get(http::header::AUTHORIZATION)
        {
            let bytes = header.as_bytes();
            if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
                if let Some(decoded) = Bearer::decode(header) {
                    Some(decoded.token().to_owned())
                } else {
                    return Err(UserAuthorizationError::InvalidHeader);
                }
            } else {
                return Err(UserAuthorizationError::InvalidHeader);
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
        let (token_from_form, form) = if is_form {
            match req.parse_form::<AuthorizedForm<F>>().await {
                Ok(form) => (form.access_token, Some(form.inner)),
                Err(e) => {
                    return Err(UserAuthorizationError::BadForm(e.to_string()));
                }
            }
        } else {
            (None, None)
        };

        let access_token = match (token_from_header, token_from_form) {
            // Ensure the token should not be in both the form and the access token
            (Some(_), Some(_)) => return Err(UserAuthorizationError::TokenInFormAndHeader),
            (Some(t), None) => AccessToken::Header(t),
            (None, Some(t)) => AccessToken::Form(t),
            (None, None) => AccessToken::None,
        };

        Ok(UserAuthorization { access_token, form })
    }
}

fn is_salvo_form_content_type(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        || media_type.eq_ignore_ascii_case("multipart/form-data")
}

static USER_AUTHORIZATION_METADATA: LazyLock<Metadata> =
    LazyLock::new(|| Metadata::new("UserAuthorization"));

impl<'ex, F> Extractible<'ex> for UserAuthorization<F>
where
    F: DeserializeOwned + Send,
{
    fn metadata() -> &'static Metadata {
        &USER_AUTHORIZATION_METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
    ) -> Result<Self, UserAuthorizationError> {
        Self::extract_from_request(req).await
    }
}
