// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Jobs that drive the user lifecycle -- deactivation and reactivation.
//!
//! Both jobs follow a two-phase pattern: mutate the local database first,
//! then propagate changes to the Matrix homeserver.

use anyhow::Context;
use async_trait::async_trait;
use coauth_data::{
    BoxRepository, Clock, RepositoryAccess,
    oauth2::OAuth2SessionFilter,
    personal::PersonalSessionFilter,
    queue::{DeactivateUserJob, ReactivateUserJob},
    user::{BrowserSessionFilter, User, UserEmailFilter, UserRepository},
};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

/// Terminate every active session that belongs to `target` and log the counts.
///
/// The function finishes browser sessions, OAuth 2.0 sessions, and both
/// the "actor" and "owner" flavours of personal sessions.
async fn terminate_all_sessions_for(
    repo: &mut BoxRepository,
    wall_clock: &dyn Clock,
    target: &User,
) -> Result<(), JobError> {
    // Browser sessions
    let browser_count = repo
        .browser_session()
        .finish_bulk(
            wall_clock,
            BrowserSessionFilter::new().for_user(target).active_only(),
        )
        .await
        .map_err(JobError::retry)?;
    info!(
        sessions = browser_count,
        kind = "browser",
        "sessions terminated"
    );

    // OAuth 2.0 sessions
    let oauth_count = repo
        .oauth2_session()
        .finish_bulk(
            wall_clock,
            OAuth2SessionFilter::new().for_user(target).active_only(),
        )
        .await
        .map_err(JobError::retry)?;
    info!(
        sessions = oauth_count,
        kind = "oauth2",
        "sessions terminated"
    );

    // Personal sessions where the user is the *actor*
    let actor_count = repo
        .personal_session()
        .revoke_bulk(
            wall_clock,
            PersonalSessionFilter::new()
                .for_actor_user(target)
                .active_only(),
        )
        .await
        .map_err(JobError::retry)?;
    info!(
        sessions = actor_count,
        kind = "personal/actor",
        "sessions revoked"
    );

    // Personal sessions where the user is the *owner*
    let owner_count = repo
        .personal_session()
        .revoke_bulk(
            wall_clock,
            PersonalSessionFilter::new()
                .for_owner_user(target)
                .active_only(),
        )
        .await
        .map_err(JobError::retry)?;
    info!(
        sessions = owner_count,
        kind = "personal/owner",
        "sessions revoked"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// DeactivateUserJob
// ---------------------------------------------------------------------------

#[async_trait]
impl RunnableJob for DeactivateUserJob {
    #[tracing::instrument(
        name = "job.deactivate_user",
        fields(user.id = %self.user_id(), erase = %self.hs_erase()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let wall_clock = state.clock();
        let hs = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // Fetch the target user record.
        let target = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("target user does not exist")
            .map_err(JobError::fail)?;

        // Flip the deactivated flag in our local store.
        let target = repo
            .user()
            .deactivate(wall_clock, target)
            .await
            .context("could not mark user as deactivated")
            .map_err(JobError::retry)?;

        // Revoke / finish every kind of session the user may hold.
        terminate_all_sessions_for(&mut repo, wall_clock, &target).await?;

        // Strip email addresses so they can be reclaimed.
        let email_count = repo
            .user_email()
            .remove_bulk(UserEmailFilter::new().for_user(&target))
            .await
            .map_err(JobError::retry)?;
        info!(removed = email_count, "email addresses purged");

        // Commit before talking to the homeserver -- if the HS call fails
        // the job will retry, but the local state is already consistent.
        repo.save().await.map_err(JobError::retry)?;

        // Finally, tell the homeserver to remove / erase the account.
        info!(username = %target.username, "requesting homeserver deactivation");
        hs.delete_user(&target.username, self.hs_erase())
            .await
            .map_err(JobError::retry)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReactivateUserJob
// ---------------------------------------------------------------------------

#[async_trait]
impl RunnableJob for ReactivateUserJob {
    #[tracing::instrument(
        name = "job.reactivate_user",
        fields(user.id = %self.user_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let hs = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let target = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("target user does not exist")
            .map_err(JobError::fail)?;

        // Re-enable the account on the homeserver *before* flipping the local
        // flag -- this way the user cannot authenticate until the HS is ready.
        info!(username = %target.username, "requesting homeserver reactivation");
        hs.reactivate_user(&target.username)
            .await
            .map_err(JobError::retry)?;

        let _reactivated = repo
            .user()
            .reactivate(target)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}
