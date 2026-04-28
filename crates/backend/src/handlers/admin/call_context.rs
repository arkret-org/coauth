// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use oauth2_types::scope::Scope;
use coauth_data::{
    BoxClock, BoxRepository, RepositoryError, Session, TokenFormatError, TokenType, User,
    personal::session::{PersonalSession, PersonalSessionOwner},
};
use salvo::{http::StatusCode, prelude::*};
use ulid::Ulid;

use super::response::ErrorResponse;
use crate::{
    handlers::{BoundActivityTracker, account::DepotExt},
    record_error,
};

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
    #[error("Missing admin scope (expected urn:coauth:admin or urn:mas:admin)")]
    MissingScope,
}

impl Scribe for Rejection {
    fn render(self, res: &mut Response) {
        let response = ErrorResponse::from_error(&self);
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
            | Rejection::MissingScope
            | Rejection::InvalidAccessTokenType(_) => StatusCode::UNAUTHORIZED,

            Rejection::RepositorySetup(_)
            | Rejection::Repository(_)
            | Rejection::LoadSession(_)
            | Rejection::LoadUser(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(response));
    }
}

/// An extractor which authorizes the request
///
/// Because we need to load the database repository and the clock, we keep them
/// in the context to avoid creating two instances for each request.
#[non_exhaustive]
pub struct CallContext {
    pub repo: BoxRepository,
    pub clock: BoxClock,
    pub user: Option<User>,
    pub session: CallerSession,
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
                .oauth2_access_token()
                .find_by_token(token)
                .await?
                .ok_or(Rejection::UnknownAccessToken)?;

            // Look for the associated session in the database
            let session = repo
                .oauth2_session()
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
                .record_oauth2_session(&clock, &session)
                .await;

            CallerSession::OAuth2Session(session)
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
                PersonalSessionOwner::OAuth2Client(_) => {
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
            CallerSession::OAuth2Session(_) => {
                // For OAuth2 sessions: check that the user is valid enough
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
        assert!(matches!(session, CallerSession::OAuth2Session(_)));
        None
    };

    // For now, we only check that the session has the admin scope
    // Later we might want to check other route-specific scopes
    if !super::has_admin_scope(session.scope()) {
        return Err(Rejection::MissingScope);
    }

    Ok(CallContext {
        repo,
        clock,
        user,
        session,
    })
}

/// The session representing the caller of the Admin API;
/// could either be an OAuth session or a personal session.
pub enum CallerSession {
    OAuth2Session(Session),
    PersonalSession(PersonalSession),
}

impl CallerSession {
    pub fn scope(&self) -> &Scope {
        match self {
            CallerSession::OAuth2Session(session) => &session.scope,
            CallerSession::PersonalSession(session) => &session.scope,
        }
    }

    pub fn user_id(&self) -> Option<Ulid> {
        match self {
            CallerSession::OAuth2Session(session) => session.user_id,
            CallerSession::PersonalSession(session) => Some(session.actor_user_id),
        }
    }
}
