use coauth_config::CokretConfig;
use coauth_data::oauth::{
    OAuthAccessTokenRepository, OAuthRefreshTokenRepository, OAuthSessionRepository,
};
use coauth_data::personal::session::PersonalSessionOwner;
use coauth_data::personal::{PersonalAccessTokenRepository, PersonalSessionRepository};
use coauth_data::user::UserRepository;
use coauth_data::{
    BoxRepository, Clock, RepositoryAccess, RepositoryError, TokenFormatError, TokenType,
    UrlBuilder,
};
use coauth_iana::oauth::OAuthTokenTypeHint;
use oauth_types::requests::IntrospectionResponse;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::{ActivityTracker, cokret};

/// Errors that can occur during token introspection business logic.
#[derive(Debug, Error)]
pub enum IntrospectionError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error("unexpected token type")]
    UnexpectedTokenType,

    #[error("invalid token format")]
    InvalidTokenFormat(#[from] TokenFormatError),

    #[error("unknown {0}")]
    UnknownToken(TokenType),

    #[error("{0} is not valid")]
    InvalidToken(TokenType),

    #[error("invalid oauth session {0}")]
    InvalidOAuthSession(Ulid),

    #[error("unknown oauth session {0}")]
    CantLoadOAuthSession(Ulid),

    #[error("invalid personal access token session {0}")]
    InvalidPersonalSession(Ulid),

    #[error("unknown personal access token session {0}")]
    CantLoadPersonalSession(Ulid),

    #[error("invalid user {0}")]
    InvalidUser(Ulid),

    #[error("unknown user {0}")]
    CantLoadUser(Ulid),

    #[error("unknown OAuth client {0}")]
    CantLoadOAuthClient(Ulid),
}

/// Look up a token, check its validity, load associated session info, and
/// return an [`IntrospectionResponse`].
///
/// The caller is responsible for client authentication and HTTP-level
/// concerns. This function only touches the repository.
/// Whether the introspecting caller is entitled to the cokret
/// device/principal/session association fields.
///
/// RFC 7662 introspection defaults to `sub`/`scope`/`exp`-style claims.
/// The cokret extension fields (`cokret_principal_did`, `device_id`,
/// `cokret_device_id`, `cokret_session_id`) link a token to a concrete
/// device + principal + local session and materially widen the
/// de-anonymisation surface. They are S2S material for the trusted
/// Principal Server (which enforces the `/_cokret/self/*` surface), not
/// for arbitrary confidential OIDC clients. Callers pass
/// [`CokretAssociationDisclosure::Full`] only when authenticated as the
/// Principal Server (homeserver bearer) or for internal self-introspection;
/// untrusted confidential clients pass
/// [`CokretAssociationDisclosure::Redacted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CokretAssociationDisclosure {
    /// Return the full device/principal/session association.
    Full,
    /// Omit cokret association fields; only standard RFC 7662 claims.
    Redacted,
}

impl CokretAssociationDisclosure {
    fn is_full(self) -> bool {
        matches!(self, CokretAssociationDisclosure::Full)
    }
}

pub async fn introspect_token(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    activity_tracker: &ActivityTracker,
    token_str: &str,
    token_type_hint: Option<OAuthTokenTypeHint>,
    disclosure: CokretAssociationDisclosure,
) -> Result<IntrospectionResponse, IntrospectionError> {
    let token_type = TokenType::check(token_str)?;
    if let Some(hint) = token_type_hint
        && token_type != hint
    {
        return Err(IntrospectionError::UnexpectedTokenType);
    }

    // TODO(COA-HYG-02): we should get the IP from the client introspecting the token
    let ip = None;

    let reply = match token_type {
        TokenType::AccessToken => {
            let mut access_token = repo
                .oauth_access_token()
                .find_by_token(token_str)
                .await?
                .ok_or(IntrospectionError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(IntrospectionError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .oauth_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(IntrospectionError::CantLoadOAuthSession(
                    access_token.session_id,
                ))?;

            if !session.is_valid() {
                return Err(IntrospectionError::InvalidOAuthSession(session.id));
            }

            // If this is the first time we're using this token, mark it as used
            if !access_token.is_used() {
                access_token = repo
                    .oauth_access_token()
                    .mark_used(clock, access_token)
                    .await?;
            }

            // The session might not have a user on it (for Client Credentials
            // grants for example), so we're optionally fetching the user
            let (sub, username, principal_did) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(IntrospectionError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(IntrospectionError::InvalidUser(user.id));
                }

                let sub = principal_subject_for_user(url_builder, cokret_config, &user);
                let principal_did =
                    cokret::published_principal_did_for_user(repo, cokret_config, &user).await?;
                (Some(sub), Some(user.localpart), principal_did)
            } else {
                (None, None, None)
            };

            activity_tracker
                .record_oauth_session(clock, &session, ip)
                .await;

            let device_id = cokret::primary_device_id(&session.scope);
            let scope = session.scope;

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: sub.clone(),
                aud: None,
                iss: Some(url_builder.oidc_issuer().to_string()),
                jti: Some(access_token.jti()),
                device_id: disclosure.is_full().then(|| device_id.clone()).flatten(),
                cokret_principal_did: disclosure.is_full().then_some(principal_did).flatten(),
                cokret_device_id: disclosure.is_full().then_some(device_id).flatten(),
                cokret_session_id: disclosure.is_full().then(|| session.id.to_string()),
            }
        }

        TokenType::RefreshToken => {
            let refresh_token = repo
                .oauth_refresh_token()
                .find_by_token(token_str)
                .await?
                .ok_or(IntrospectionError::UnknownToken(TokenType::RefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(IntrospectionError::InvalidToken(TokenType::RefreshToken));
            }

            let session = repo
                .oauth_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(IntrospectionError::CantLoadOAuthSession(
                    refresh_token.session_id,
                ))?;

            if !session.is_valid() {
                return Err(IntrospectionError::InvalidOAuthSession(session.id));
            }

            // The session might not have a user on it (for Client Credentials
            // grants for example), so we're optionally fetching the user
            let (sub, username, principal_did) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(IntrospectionError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(IntrospectionError::InvalidUser(user.id));
                }

                let sub = principal_subject_for_user(url_builder, cokret_config, &user);
                let principal_did =
                    cokret::published_principal_did_for_user(repo, cokret_config, &user).await?;
                (Some(sub), Some(user.localpart), principal_did)
            } else {
                (None, None, None)
            };

            activity_tracker
                .record_oauth_session(clock, &session, ip)
                .await;

            let device_id = cokret::primary_device_id(&session.scope);
            let scope = session.scope;

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                expires_in: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub: sub.clone(),
                aud: None,
                iss: Some(url_builder.oidc_issuer().to_string()),
                jti: Some(refresh_token.jti()),
                device_id: disclosure.is_full().then(|| device_id.clone()).flatten(),
                cokret_principal_did: disclosure.is_full().then_some(principal_did).flatten(),
                cokret_device_id: disclosure.is_full().then_some(device_id).flatten(),
                cokret_session_id: disclosure.is_full().then(|| session.id.to_string()),
            }
        }

        TokenType::PersonalAccessToken => {
            let access_token = repo
                .personal_access_token()
                .find_by_token(token_str)
                .await?
                .ok_or(IntrospectionError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(IntrospectionError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .personal_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(IntrospectionError::CantLoadPersonalSession(
                    access_token.session_id,
                ))?;

            if !session.is_valid() {
                return Err(IntrospectionError::InvalidPersonalSession(session.id));
            }

            let actor_user = repo
                .user()
                .lookup(session.actor_user_id)
                .await?
                .ok_or(IntrospectionError::CantLoadUser(session.actor_user_id))?;

            if !actor_user.is_valid() {
                return Err(IntrospectionError::InvalidUser(actor_user.id));
            }

            let client_id = match session.owner {
                PersonalSessionOwner::User(owner_user_id) => {
                    let owner_user = repo
                        .user()
                        .lookup(owner_user_id)
                        .await?
                        .ok_or(IntrospectionError::CantLoadUser(owner_user_id))?;

                    if !owner_user.is_valid() {
                        return Err(IntrospectionError::InvalidUser(owner_user.id));
                    }

                    None
                }
                PersonalSessionOwner::OAuthClient(owner_client_id) => {
                    let owner_client = repo
                        .oauth_client()
                        .lookup(owner_client_id)
                        .await?
                        .ok_or(IntrospectionError::CantLoadOAuthClient(owner_client_id))?;

                    Some(owner_client.client_id.clone())
                }
            };

            activity_tracker
                .record_personal_session(clock, &session, ip)
                .await;

            let device_id = cokret::primary_device_id(&session.scope);
            let scope = session.scope;
            let actor_user_sub =
                principal_subject_for_user(url_builder, cokret_config, &actor_user);
            let actor_principal_did =
                cokret::published_principal_did_for_user(repo, cokret_config, &actor_user).await?;

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id,
                username: Some(actor_user.localpart),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: Some(actor_user_sub.clone()),
                aud: None,
                iss: Some(url_builder.oidc_issuer().to_string()),
                jti: None,
                device_id: disclosure.is_full().then(|| device_id.clone()).flatten(),
                cokret_principal_did: disclosure
                    .is_full()
                    .then_some(actor_principal_did)
                    .flatten(),
                cokret_device_id: disclosure.is_full().then_some(device_id).flatten(),
                cokret_session_id: disclosure.is_full().then(|| session.id.to_string()),
            }
        }
    };

    Ok(reply)
}

fn principal_subject_for_user(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    user: &coauth_data::User,
) -> String {
    cokret::oidc_subject_for_user(url_builder, cokret_config, user)
}
