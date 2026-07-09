// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use coauth_config::CokretConfig;
use coauth_data::personal::session::{PersonalSession, PersonalSessionOwner};
use coauth_data::{
    BoxClock, BoxRepository, RepositoryError, Session, TokenFormatError, TokenType, User,
};
use coauth_oauth_types::scope::Scope;
use salvo::http::StatusCode;
use salvo::prelude::*;
use ulid::Ulid;

use super::response::ErrorOutcome;
use crate::handlers::account::DepotExt;
use crate::record_error;

#[derive(Debug, thiserror::Error)]
pub enum Rejection {
    /// The authorization header is missing
    #[error("Missing authorization header")]
    MissingAuthorizationHeader,

    /// The authorization header is invalid
    #[error("Invalid authorization header")]
    InvalidAuthorizationHeader,

    /// Couldn't load the database repository
    #[error("Couldn't load the database repository")]
    RepositorySetup(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// A database operation failed
    #[error("Invalid repository operation")]
    Repository(#[from] RepositoryError),

    /// The access token was not of the correct type for the Admin API
    #[error("Invalid type of access token")]
    InvalidAccessTokenType(#[from] Option<TokenFormatError>),

    /// The access token could not be found in the database
    #[error("Unknown access token")]
    UnknownAccessToken,

    /// The access token provided expired
    #[error("Access token expired")]
    TokenExpired,

    /// The session associated with the access token was revoked
    #[error("Access token revoked")]
    SessionRevoked,

    /// The user associated with the session is locked
    #[error("User locked")]
    UserLocked,

    /// Failed to load the session
    #[error("Failed to load session {0}")]
    LoadSession(Ulid),

    /// Failed to load the user
    #[error("Failed to load user {0}")]
    LoadUser(Ulid),

    /// The session does not have the required admin scope
    #[error("Missing admin scope (expected urn:coauth:admin or urn:arkret:admin:*)")]
    MissingScope,

    /// The request was scoped to an organization this deployment does not
    /// serve.
    #[error("Invalid admin organization scope")]
    InvalidAdminOrg,
}

impl Scribe for Rejection {
    fn render(self, res: &mut Response) {
        let response = ErrorOutcome::from_error(&self);
        let sentry_event_id = record_error!(
            self,
            Self::RepositorySetup(_)
                | Self::Repository(_)
                | Self::LoadSession(_)
                | Self::LoadUser(_)
        );

        let status = match &self {
            Rejection::InvalidAuthorizationHeader | Rejection::MissingAuthorizationHeader => {
                StatusCode::BAD_REQUEST
            }

            Rejection::UnknownAccessToken
            | Rejection::TokenExpired
            | Rejection::SessionRevoked
            | Rejection::UserLocked
            | Rejection::InvalidAdminOrg
            | Rejection::MissingScope
            | Rejection::InvalidAccessTokenType(_) => StatusCode::UNAUTHORIZED,

            Rejection::RepositorySetup(_)
            | Rejection::Repository(_)
            | Rejection::LoadSession(_)
            | Rejection::LoadUser(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        res.status_code(status);
        if let Some(event_id) = sentry_event_id
            && let Ok(value) = http::HeaderValue::from_str(&event_id.to_string())
        {
            res.headers_mut().insert("x-sentry-event-id", value);
        }
        res.render(Json(response));
    }
}

/// An extractor which authorizes the request
///
/// Because we need to load the database repository and the clock, we keep them
/// in the context to avoid creating two instances for each request.
///
/// # Multi-tenant guard
///
/// The current coauth data model is deployment-scoped rather than true
/// multi-tenant: first-class entities do not carry per-row `org_id`.
/// To avoid pretending cross-tenant isolation exists, Admin API calls
/// support only a configured deployment org. If
/// `arkret.admin_org_id` is set, every admin request MUST carry the
/// matching `x-coauth-org-id`; a different value or missing header is
/// rejected before any resource lookup. Requests that carry an org
/// header when the deployment has no configured org are also rejected.
#[non_exhaustive]
pub struct CallContext {
    pub repo: BoxRepository,
    pub clock: BoxClock,
    pub user: Option<User>,
    pub session: CallerSession,
    pub org_id: Option<String>,
}

pub async fn extract_call_context(req: &Request, depot: &Depot) -> Result<CallContext, Rejection> {
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);
    let clock = crate::handlers::account::make_clock();

    // Load the database repository
    let repo_factory = depot
        .repo_factory()
        .map_err(|e| Rejection::RepositorySetup(Box::new(e)))?;
    let mut repo = repo_factory
        .create()
        .await
        .map_err(|e| Rejection::RepositorySetup(e.into()))?;

    // Extract the access token from the authorization header
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or(Rejection::MissingAuthorizationHeader)?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| Rejection::InvalidAuthorizationHeader)?;

    let token = auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .ok_or(Rejection::InvalidAuthorizationHeader)?;

    let token_type = TokenType::check(token)?;

    let session = match token_type {
        TokenType::AccessToken => {
            // Look for the access token in the database
            let access_token = repo
                .oauth_access_token()
                .find_by_token(token)
                .await?
                .ok_or(Rejection::UnknownAccessToken)?;

            // Look for the associated session in the database
            let session = repo
                .oauth_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or_else(|| Rejection::LoadSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(Rejection::SessionRevoked);
            }

            if !access_token.is_valid(clock.now()) {
                return Err(Rejection::TokenExpired);
            }

            // Record the activity on the session
            activity_tracker
                .record_oauth_session(&clock, &session)
                .await;

            CallerSession::OAuthSession(session)
        }
        TokenType::PersonalAccessToken => {
            // Look for the access token in the database
            let access_token = repo
                .personal_access_token()
                .find_by_token(token)
                .await?
                .ok_or(Rejection::UnknownAccessToken)?;

            // Look for the associated session in the database
            let session = repo
                .personal_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or_else(|| Rejection::LoadSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(Rejection::SessionRevoked);
            }

            if !access_token.is_valid(clock.now()) {
                return Err(Rejection::TokenExpired);
            }

            // Check the validity of the owner of the personal session
            match session.owner {
                PersonalSessionOwner::User(owner_user_id) => {
                    let owner_user = repo
                        .user()
                        .lookup(owner_user_id)
                        .await?
                        .ok_or_else(|| Rejection::LoadUser(owner_user_id))?;
                    if !owner_user.is_valid() {
                        return Err(Rejection::UserLocked);
                    }
                }
                PersonalSessionOwner::OAuthClient(_) => {
                    // nop: Client owners are always valid
                }
            }

            // Record the activity on the session
            activity_tracker
                .record_personal_session(&clock, &session)
                .await;

            CallerSession::PersonalSession(session)
        }
        _other => {
            return Err(Rejection::InvalidAccessTokenType(None));
        }
    };

    // Load the user if there is one
    let user = if let Some(user_id) = session.user_id() {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or_else(|| Rejection::LoadUser(user_id))?;

        match session {
            CallerSession::OAuthSession(_) => {
                // For OAuth sessions: check that the user is valid enough
                // to be a user.
                if !user.is_valid() {
                    return Err(Rejection::UserLocked);
                }
            }
            CallerSession::PersonalSession(_) => {
                // For personal sessions: check that the actor is valid enough
                // to be an actor.
                if !user.is_valid_actor() {
                    return Err(Rejection::UserLocked);
                }
            }
        }

        Some(user)
    } else {
        // Double check we're not using a PersonalSession
        assert!(matches!(session, CallerSession::OAuthSession(_)));
        None
    };

    // For now, we only check that the session has the admin scope
    // Later we might want to check other route-specific scopes
    if !super::has_admin_scope(session.scope()) {
        return Err(Rejection::MissingScope);
    }

    let configured_org_id = depot
        .get::<CokretConfig>("arkret_config")
        .ok()
        .and_then(|config| config.admin_org_id.clone());
    let presented_org_id = req
        .headers()
        .get("x-coauth-org-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let org_id = validate_admin_org(configured_org_id.as_deref(), presented_org_id)?;

    Ok(CallContext {
        repo,
        clock,
        user,
        session,
        org_id,
    })
}

fn validate_admin_org(
    configured_org_id: Option<&str>,
    presented_org_id: Option<&str>,
) -> Result<Option<String>, Rejection> {
    match (configured_org_id, presented_org_id) {
        (Some(expected), Some(actual)) if expected == actual => Ok(Some(expected.to_owned())),
        (Some(_), _) | (None, Some(_)) => Err(Rejection::InvalidAdminOrg),
        (None, None) => Ok(None),
    }
}

/// The session representing the caller of the Admin API;
/// could either be an OAuth session or a personal session.
pub enum CallerSession {
    OAuthSession(Session),
    PersonalSession(PersonalSession),
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn admin_org_guard_requires_exact_configured_org() {
        assert_eq!(
            validate_admin_org(Some("ak:org:alpha"), Some("ak:org:alpha")).unwrap(),
            Some("ak:org:alpha".to_owned())
        );
        assert!(validate_admin_org(Some("ak:org:alpha"), None).is_err());
        assert!(validate_admin_org(Some("ak:org:alpha"), Some("ak:org:beta")).is_err());
        assert!(validate_admin_org(None, Some("ak:org:alpha")).is_err());
        assert_eq!(validate_admin_org(None, None).unwrap(), None);
    }
}

impl CallerSession {
    pub fn scope(&self) -> &Scope {
        match self {
            CallerSession::OAuthSession(session) => &session.scope,
            CallerSession::PersonalSession(session) => &session.scope,
        }
    }

    pub fn user_id(&self) -> Option<Ulid> {
        match self {
            CallerSession::OAuthSession(session) => session.user_id,
            CallerSession::PersonalSession(session) => Some(session.actor_user_id),
        }
    }
}
