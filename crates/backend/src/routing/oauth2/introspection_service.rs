use std::collections::BTreeSet;

use coauth_config::ContrixConfig;
use coauth_data::{
    BoxRepository, Clock, RepositoryAccess, RepositoryError, TokenFormatError, TokenType,
    UrlBuilder,
    oauth2::{OAuth2AccessTokenRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository},
    personal::{
        PersonalAccessTokenRepository, PersonalSessionRepository, session::PersonalSessionOwner,
    },
    user::UserRepository,
};
use coauth_iana::oauth::OAuthTokenTypeHint;
use oauth2_types::{
    requests::IntrospectionResponse,
    scope::{Scope, ScopeToken},
};
use thiserror::Error;
use ulid::Ulid;

use crate::routing::ActivityTracker;
use crate::routing::contrix;

const UNSTABLE_API_SCOPE: ScopeToken =
    ScopeToken::from_static("urn:matrix:org.matrix.msc2967.client:api:*");
const STABLE_API_SCOPE: ScopeToken = ScopeToken::from_static("urn:matrix:client:api:*");
const CONTRIX_CLIENT_DEVICE_SCOPE_PREFIX: &str = "urn:contrix:client:device:";
const LEGACY_MATRIX_CLIENT_DEVICE_SCOPE_PREFIX: &str = "urn:matrix:client:device:";
const LEGACY_MATRIX_MSC_DEVICE_SCOPE_PREFIX: &str = "urn:matrix:org.matrix.msc2967.client:device:";

/// Normalize a scope by adding the stable and unstable API scope equivalents
/// if missing.
fn normalize_scope(mut scope: Scope) -> Scope {
    let mut to_add = BTreeSet::new();
    for token in &*scope {
        if token == &STABLE_API_SCOPE {
            to_add.insert(UNSTABLE_API_SCOPE);
        } else if token == &UNSTABLE_API_SCOPE {
            to_add.insert(STABLE_API_SCOPE);
        } else {
            let s = token.as_str();
            let device_id = s
                .strip_prefix(CONTRIX_CLIENT_DEVICE_SCOPE_PREFIX)
                .or_else(|| s.strip_prefix(LEGACY_MATRIX_CLIENT_DEVICE_SCOPE_PREFIX))
                .or_else(|| s.strip_prefix(LEGACY_MATRIX_MSC_DEVICE_SCOPE_PREFIX));
            if let Some(device_id) = device_id {
                let device_scopes = [
                    format!("{CONTRIX_CLIENT_DEVICE_SCOPE_PREFIX}{device_id}"),
                    format!("{LEGACY_MATRIX_CLIENT_DEVICE_SCOPE_PREFIX}{device_id}"),
                    format!("{LEGACY_MATRIX_MSC_DEVICE_SCOPE_PREFIX}{device_id}"),
                ];

                for device_scope in device_scopes {
                    if let Ok(token) = device_scope.parse::<ScopeToken>() {
                        to_add.insert(token);
                    }
                }
            }
        }
    }
    scope.append(&mut to_add);
    scope
}

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

    #[error("unknown OAuth2 client {0}")]
    CantLoadOAuth2Client(Ulid),
}

/// Look up a token, check its validity, load associated session info, and
/// return an [`IntrospectionResponse`].
///
/// The caller is responsible for client authentication and HTTP-level
/// concerns. This function only touches the repository.
pub async fn introspect_token(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    activity_tracker: &ActivityTracker,
    token_str: &str,
    token_type_hint: Option<OAuthTokenTypeHint>,
) -> Result<IntrospectionResponse, IntrospectionError> {
    let token_type = TokenType::check(token_str)?;
    if let Some(hint) = token_type_hint
        && token_type != hint
    {
        return Err(IntrospectionError::UnexpectedTokenType);
    }

    // XXX: we should get the IP from the client introspecting the token
    let ip = None;

    let reply = match token_type {
        TokenType::AccessToken => {
            let mut access_token = repo
                .oauth2_access_token()
                .find_by_token(token_str)
                .await?
                .ok_or(IntrospectionError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(IntrospectionError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .oauth2_session()
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
                    .oauth2_access_token()
                    .mark_used(clock, access_token)
                    .await?;
            }

            // The session might not have a user on it (for Client Credentials
            // grants for example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(IntrospectionError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(IntrospectionError::InvalidUser(user.id));
                }

                (
                    Some(contrix::user_did_for(url_builder, contrix_config, &user)),
                    Some(user.username),
                )
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(clock, &session, ip)
                .await;

            let device_id = contrix::primary_device_id(&session.scope);
            let scope = normalize_scope(session.scope);

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
                device_id: device_id.clone(),
                contrix_principal_did: sub,
                contrix_device_id: device_id,
                contrix_session_id: Some(session.id.to_string()),
            }
        }

        TokenType::RefreshToken => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(token_str)
                .await?
                .ok_or(IntrospectionError::UnknownToken(TokenType::RefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(IntrospectionError::InvalidToken(TokenType::RefreshToken));
            }

            let session = repo
                .oauth2_session()
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
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(IntrospectionError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(IntrospectionError::InvalidUser(user.id));
                }

                (
                    Some(contrix::user_did_for(url_builder, contrix_config, &user)),
                    Some(user.username),
                )
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(clock, &session, ip)
                .await;

            let device_id = contrix::primary_device_id(&session.scope);
            let scope = normalize_scope(session.scope);

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
                device_id: device_id.clone(),
                contrix_principal_did: sub,
                contrix_device_id: device_id,
                contrix_session_id: Some(session.id.to_string()),
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
                PersonalSessionOwner::OAuth2Client(owner_client_id) => {
                    let owner_client = repo
                        .oauth2_client()
                        .lookup(owner_client_id)
                        .await?
                        .ok_or(IntrospectionError::CantLoadOAuth2Client(owner_client_id))?;

                    Some(owner_client.client_id.clone())
                }
            };

            activity_tracker
                .record_personal_session(clock, &session, ip)
                .await;

            let device_id = contrix::primary_device_id(&session.scope);
            let scope = normalize_scope(session.scope);
            let actor_user_sub = contrix::user_did_for(url_builder, contrix_config, &actor_user);

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id,
                username: Some(actor_user.username),
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
                device_id: device_id.clone(),
                contrix_principal_did: Some(actor_user_sub),
                contrix_device_id: device_id,
                contrix_session_id: Some(session.id.to_string()),
            }
        }
    };

    Ok(reply)
}
