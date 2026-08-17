// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Jobs that drive terminal user deactivation and erasure projection cleanup.
//!
//! Both jobs follow a two-phase pattern: mutate the local database first,
//! then propagate changes to the downstream principal system.

use anyhow::Context;
use async_trait::async_trait;
use coauth_data::oauth::{OAuthSessionFilter, SessionGrantFilter};
use coauth_data::personal::PersonalSessionFilter;
use coauth_data::queue::{AccountProjectionRewriteJob, DeactivateUserJob};
use coauth_data::user::{BrowserSessionFilter, User, UserEmailFilter, UserRepository, UserStatus};
use coauth_data::{BoxRepository, Clock, Pagination, RepositoryAccess};
use tracing::info;

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

/// Terminate every active session that belongs to `target` and log the counts.
///
/// The function finishes browser sessions, OAuth sessions, and both
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

    // OAuth sessions
    let oauth_count = repo
        .oauth_session()
        .finish_bulk(
            wall_clock,
            OAuthSessionFilter::new().for_user(target).active_only(),
        )
        .await
        .map_err(JobError::retry)?;
    info!(
        sessions = oauth_count,
        kind = "oauth",
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

async fn revoke_browser_bound_session_grants_for(
    repo: &mut BoxRepository,
    wall_clock: &dyn Clock,
    target: &User,
) -> Result<usize, JobError> {
    let now = wall_clock.now();
    let mut total = 0usize;
    let mut after = None;

    loop {
        let pagination = after.map_or_else(
            || Pagination::first(100),
            |cursor| Pagination::first(100).after(cursor),
        );
        let page = repo
            .browser_session()
            .list(BrowserSessionFilter::new().for_user(target), pagination)
            .await
            .map_err(JobError::retry)?;
        if page.edges.is_empty() {
            break;
        }

        for edge in &page.edges {
            let browser_session_id = edge.cursor;
            loop {
                let grants = repo
                    .oauth_session_grant()
                    .list(
                        SessionGrantFilter::new()
                            .for_browser_session(browser_session_id)
                            .active_at(now),
                        Pagination::first(100),
                    )
                    .await
                    .map_err(JobError::retry)?;
                if grants.edges.is_empty() {
                    break;
                }
                let has_next = grants.has_next_page;
                for grant in grants.edges {
                    repo.oauth_session_grant()
                        .revoke(wall_clock, grant.node)
                        .await
                        .map_err(JobError::retry)?;
                    total += 1;
                }
                if !has_next {
                    break;
                }
            }
        }

        if !page.has_next_page {
            break;
        }
        after = page.edges.last().map(|edge| edge.cursor);
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// DeactivateUserJob
// ---------------------------------------------------------------------------

#[async_trait]
impl RunnableJob for DeactivateUserJob {
    #[tracing::instrument(
        name = "job.deactivate_user",
        fields(user.id = %self.user_id(), erase = %self.principal_erase()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let wall_clock = state.clock();
        let principal = state.principal_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // Fetch the target user record.
        let target = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("target user does not exist")
            .map_err(JobError::fail)?;

        // The admin transaction may already have advanced the account to
        // erasure_pending. Never downgrade that terminal state back to
        // deactivated while executing the shared fanout job.
        let target = if target.status == UserStatus::ErasurePending {
            target
        } else {
            repo.user()
                .deactivate(wall_clock, target)
                .await
                .context("could not mark user as deactivated")
                .map_err(JobError::retry)?
        };

        // Revoke / finish every kind of session the user may hold.
        terminate_all_sessions_for(&mut repo, wall_clock, &target).await?;

        // Strip email addresses so they can be reclaimed.
        let email_count = repo
            .user_email()
            .remove_bulk(UserEmailFilter::new().for_user(&target))
            .await
            .map_err(JobError::retry)?;
        info!(removed = email_count, "email addresses purged");

        // Commit before talking to the principal -- if the downstream call fails
        // the job will retry, but the local state is already consistent.
        repo.save().await.map_err(JobError::retry)?;

        // Hard erasure is driven exclusively by the signed erasure_pending
        // AccountStatusRecord and its publication job. Never issue a second
        // connector command for the same physical operation.
        if !self.principal_erase() {
            info!(handle = %target.localpart, "requesting principal deactivation");
            principal
                .delete_user(&target.localpart, false)
                .await
                .map_err(JobError::retry)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AccountProjectionRewriteJob
// ---------------------------------------------------------------------------

#[async_trait]
impl RunnableJob for AccountProjectionRewriteJob {
    #[tracing::instrument(
        name = "job.account_projection_rewrite",
        fields(user.id = %self.user_id(), erase_private_state = %self.erase_private_state()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let wall_clock = state.clock();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let target = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("target user does not exist")
            .map_err(JobError::fail)?;

        terminate_all_sessions_for(&mut repo, wall_clock, &target).await?;

        let revoked_grants =
            revoke_browser_bound_session_grants_for(&mut repo, wall_clock, &target).await?;
        info!(
            session_grants = revoked_grants,
            "browser-bound session grants revoked"
        );

        if self.erase_private_state() {
            let email_count = repo
                .user_email()
                .remove_bulk(UserEmailFilter::new().for_user(&target))
                .await
                .map_err(JobError::retry)?;
            info!(removed = email_count, "email addresses purged");
        }

        repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}
