// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Session loading helpers.  When the account state prevents normal
//! operation (deactivated / locked / remotely ended) the caller receives
//! an error variant that it can translate into an SPA error page.

use coauth_data::{
    BoxRepository, BrowserSession, RepositoryError, User, oauth2::OAuth2SessionFilter,
    personal::PersonalSessionFilter,
};
use coauth_policy::model::SessionCounts;
use thiserror::Error;

use crate::salvo_utils::{SessionInfoExt, cookies::CookieJar};

/// Failures that can occur while loading a session.
#[derive(Debug, Error)]
#[error(transparent)]
pub enum SessionLoadError {
    Repository(#[from] RepositoryError),
}

/// The reason why the session could not be used.
#[derive(Debug, Clone)]
pub enum AccountError {
    /// The user's account has been deactivated.
    Deactivated { username: String },
    /// The user's account has been locked by an administrator.
    Locked { username: String },
    /// The browser session was ended remotely.
    SessionEnded,
}

/// Either a usable session (possibly absent) or an account-level error
/// that the caller should present to the user.
#[allow(clippy::large_enum_variant)]
pub enum SessionOrFallback {
    MaybeSession {
        cookie_jar: CookieJar,
        maybe_session: Option<BrowserSession>,
    },
    AccountError {
        cookie_jar: CookieJar,
        error: AccountError,
    },
}

/// Attempt to resolve a browser session from cookies.  When the
/// associated account is deactivated, locked, or the session has been
/// remotely ended, an [`AccountError`] is returned so the caller can
/// render the SPA shell with an injected error state.
pub async fn load_session_or_fallback(
    cookie_jar: CookieJar,
    repo: &mut BoxRepository,
) -> Result<SessionOrFallback, SessionLoadError> {
    let (sess_info, cookie_jar) = cookie_jar.session_info();

    // No session cookie at all.
    let Some(sid) = sess_info.current_session_id() else {
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session: None,
        });
    };

    // Cookie references a session that no longer exists.
    let Some(browser_session) = repo.browser_session().lookup(sid).await? else {
        let updated = sess_info.mark_session_ended();
        let jar = cookie_jar.update_session_info(&updated);
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar: jar,
            maybe_session: None,
        });
    };

    // Account deactivated.
    if browser_session.user.deactivated_at.is_some() {
        return Ok(SessionOrFallback::AccountError {
            cookie_jar,
            error: AccountError::Deactivated {
                username: browser_session.user.username.clone(),
            },
        });
    }

    // Account locked.
    if browser_session.user.locked_at.is_some() {
        return Ok(SessionOrFallback::AccountError {
            cookie_jar,
            error: AccountError::Locked {
                username: browser_session.user.username.clone(),
            },
        });
    }

    // Session remotely ended.
    if browser_session.finished_at.is_some() {
        return Ok(SessionOrFallback::AccountError {
            cookie_jar,
            error: AccountError::SessionEnded,
        });
    }

    Ok(SessionOrFallback::MaybeSession {
        cookie_jar,
        maybe_session: Some(browser_session),
    })
}

/// Count all active sessions belonging to the given user, for use in
/// session-limit enforcement.
pub(crate) async fn count_user_sessions_for_limiting(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<SessionCounts, RepositoryError> {
    let num_oauth2 = repo
        .oauth2_session()
        .count(OAuth2SessionFilter::new().active_only().for_user(user))
        .await? as u64;

    let num_personal = repo
        .personal_session()
        .count(
            PersonalSessionFilter::new()
                .active_only()
                .for_actor_user(user)
                .for_owner_user(user),
        )
        .await? as u64;

    Ok(SessionCounts {
        total: num_oauth2 + num_personal,
        oauth2: num_oauth2,
        personal: num_personal,
    })
}
