use oauth2_types::scope::OPENID;
use coauth_data::{
    BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, SystemClock, UrlBuilder,
    oauth2::OAuth2ClientRepository,
};
use coauth_jose::{
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use coauth_keystore::Keystore;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::{Extractible, prelude::*};
use serde::Serialize;
use serde_with::skip_serializing_none;
use thiserror::Error;
use ulid::Ulid;

use crate::salvo_utils::user_authorization::{AuthorizationVerificationError, UserAuthorization};

#[skip_serializing_none]
#[derive(Serialize)]
struct UserInfo {
    sub: String,
    username: String,
    preferred_username: String,
    name: Option<String>,
    picture: Option<String>,
    locale: Option<String>,
}

#[derive(Serialize)]
struct SignedUserInfo {
    iss: String,
    aud: String,
    #[serde(flatten)]
    user_info: UserInfo,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("failed to authenticate")]
    AuthorizationVerificationError(
        #[from] AuthorizationVerificationError<coauth_data::RepositoryError>,
    ),

    #[error("session is not allowed to access the userinfo endpoint")]
    Unauthorized,

    #[error("no suitable key found for signing")]
    InvalidSigningKey,

    #[error("failed to load client {0}")]
    NoSuchClient(Ulid),

    #[error("failed to load user {0}")]
    NoSuchUser(Ulid),
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(coauth_keystore::WrongAlgorithmError);
impl_from_error_for_route!(coauth_jose::jwt::JwtSignatureError);

impl From<crate::handlers::common::RouteError> for RouteError {
    fn from(e: crate::handlers::common::RouteError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            Self::Internal(_)
            | Self::InvalidSigningKey
            | Self::NoSuchClient(_)
            | Self::NoSuchUser(_) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(self.to_string()));
            }
            Self::AuthorizationVerificationError(_) | Self::Unauthorized => {
                res.status_code(StatusCode::UNAUTHORIZED);
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.userinfo.get", skip_all)]
pub async fn get(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    match handle_get(req, depot).await {
        Ok(response) => match response {
            UserinfoResponse::Json(user_info) => {
                res.render(Json(user_info));
            }
            UserinfoResponse::Jwt(token) => {
                res.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/jwt"),
                );
                res.render(Text::Plain(token));
            }
        },
        Err(e) => e.render(res),
    }
}

enum UserinfoResponse {
    Json(UserInfo),
    Jwt(String),
}

async fn handle_get(req: &mut Request, depot: &mut Depot) -> Result<UserinfoResponse, RouteError> {
    let user_authorization: UserAuthorization<()> = UserAuthorization::<()>::extract(req, depot)
        .await
        .map_err(|e| match e {
            crate::salvo_utils::user_authorization::UserAuthorizationError::Internal(e) => {
                RouteError::Internal(e)
            }
            _ => RouteError::Unauthorized,
        })?;

    use crate::handlers::common::DepotExt as _;

    // Pull infrastructure off the depot via the typed DepotExt so a
    // misconfigured server returns a 500 instead of panicking on the first
    // request. The `?` operator funnels the common `RouteError` into
    // `RouteError::Internal` via the `From` impl above.
    let url_builder = depot.url_builder()?;
    let key_store = depot.key_store()?;
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng =
        Box::new(ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed rng"));

    let mut repo: BoxRepository = depot.repo().await?;
    // The userinfo endpoint requires the `openid` scope (enforced by
    // `protected`).
    let session = user_authorization
        .protected(&mut repo, &clock, &[&OPENID])
        .await?;

    // Fail if the session is not associated with a user.
    let Some(user_id) = session.user_id else {
        return Err(RouteError::Unauthorized);
    };

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::NoSuchUser(user_id))?;

    let user_info = UserInfo {
        sub: user.sub.clone(),
        username: user.username.clone(),
        preferred_username: user.username.clone(),
        name: user.display_name.clone(),
        picture: user.avatar_url.clone(),
        locale: user.preferred_locale.clone(),
    };

    let client = repo
        .oauth2_client()
        .lookup(session.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(session.client_id))?;

    repo.save().await?;

    if let Some(alg) = client.userinfo_signed_response_alg {
        let key = key_store
            .signing_key_for_algorithm(&alg)
            .ok_or(RouteError::InvalidSigningKey)?;

        let signer = key.params().signing_key_for_alg(&alg)?;
        let header = JsonWebSignatureHeader::new(alg)
            .with_kid(key.kid().ok_or(RouteError::InvalidSigningKey)?);

        let signed_user_info = SignedUserInfo {
            iss: url_builder.oidc_issuer().to_string(),
            aud: client.client_id,
            user_info,
        };

        let token = Jwt::sign_with_rng(&mut rng, header, signed_user_info, &signer)?;
        Ok(UserinfoResponse::Jwt(token.into_string()))
    } else {
        Ok(UserinfoResponse::Json(user_info))
    }
}
