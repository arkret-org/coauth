// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Session loading helpers.  When the account state prevents normal
//! operation (deactivated / locked / remotely ended) the caller receives
//! an error variant that it can translate into an SPA error page.

use coauth_data::oauth::OAuthSessionFilter;
use coauth_data::personal::PersonalSessionFilter;
use coauth_data::{BoxRepository, RepositoryError, User};

use crate::policy::model::SessionCounts;

/// Count all active sessions belonging to the given user, for use in
/// session-limit enforcement.
pub(crate) async fn count_user_sessions_for_limiting(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<SessionCounts, RepositoryError> {
    let num_oauth = repo
        .oauth_session()
        .count(OAuthSessionFilter::new().active_only().for_user(user))
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
        total: num_oauth + num_personal,
        oauth: num_oauth,
        personal: num_personal,
    })
}
