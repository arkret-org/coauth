// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Background jobs for principal principal integration:
//! user provisioning and device synchronization.

use std::collections::HashSet;

use anyhow::Context;
use async_trait::async_trait;
use coauth_data::oauth::OAuthSessionFilter;
use coauth_data::personal::PersonalSessionFilter;
use coauth_data::queue::{ProvisionUserJob, QueueJobRepositoryExt as _, SyncDevicesJob};
use coauth_data::user::{UserEmailRepository, UserRepository};
use coauth_data::{Pagination, RepositoryAccess};
use coauth_principal::PrincipalProvisionRequest;
use tracing::info;

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

// ── Provision user ───────────────────────────────────────────────────

/// Provisions (creates or updates) a user on the principal principal via
/// the admin API, then schedules a device sync.
#[async_trait]
impl RunnableJob for ProvisionUserJob {
    #[tracing::instrument(
        name = "job.provision_user",
        fields(user.id = %self.user_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let principal = state.principal_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let mut rng = state.rng();
        let clock = state.clock();

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("user not found")
            .map_err(JobError::fail)?;

        // Collect verified email addresses
        let emails: Vec<String> = repo
            .user_email()
            .all(&user)
            .await
            .map_err(JobError::retry)?
            .into_iter()
            .map(|e| e.email)
            .collect();

        let mut req = PrincipalProvisionRequest::new(user.localpart.clone(), user.sub.clone())
            .set_emails(emails);

        if let Some(name) = self.display_name_to_set() {
            req = req.set_displayname(name.to_owned());
        }

        if let Some(avatar_url) = self.avatar_url_to_set() {
            req = req.set_avatar_url(avatar_url.to_owned());
        }

        if self.is_admin() {
            req = req.set_admin();
        }

        let created = principal
            .provision_user(&req)
            .await
            .map_err(JobError::retry)?;

        let principal_id = principal.principal_id(&user.localpart);
        if created {
            info!(%user.id, %principal_id, "user created on principal");
        } else {
            info!(%user.id, %principal_id, "user updated on principal");
        }

        // Follow up with a device sync
        repo.queue_job()
            .schedule_job(&mut rng, clock, SyncDevicesJob::new(&user))
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}

// ── Sync devices ─────────────────────────────────────────────────────

/// Collects every active device ID from OAuth and personal sessions,
/// then pushes the canonical set to the principal.
#[async_trait]
impl RunnableJob for SyncDevicesJob {
    #[tracing::instrument(
        name = "job.sync_devices",
        fields(user.id = %self.user_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let principal = state.principal_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("user not found")
            .map_err(JobError::fail)?;

        // Acquire an advisory lock so concurrent syncs don't race.
        repo.user()
            .acquire_lock_for_sync(&user)
            .await
            .map_err(JobError::retry)?;

        let mut devices = HashSet::new();

        // ── Gather device IDs from OAuth sessions ────────────────
        collect_devices_from_oauth(&mut repo, &user, &mut devices).await?;

        // ── Gather device IDs from personal sessions ─────────────────
        collect_devices_from_personal(&mut repo, &user, &mut devices).await?;

        // ── Push the full set to the principal ──────────────────────
        principal
            .sync_devices(&user.localpart, devices)
            .await
            .map_err(JobError::retry)?;

        // Release the advisory lock by saving the connection.
        repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Stable and unstable principal device-scope prefixes.
const DEVICE_SCOPE_PREFIXES: &[&str] = &[
    "urn:principal:client:device:",
    "urn:principal:org.principal.msc2967.client:device:",
];

/// Extract a device ID from a scope token if it has a known device prefix.
fn extract_device_id(token: &oauth_types::scope::ScopeToken) -> Option<&str> {
    let s = token.as_str();
    DEVICE_SCOPE_PREFIXES
        .iter()
        .find_map(|prefix| s.strip_prefix(prefix))
}

/// Paginate through all active OAuth sessions and collect device IDs.
async fn collect_devices_from_oauth(
    repo: &mut impl RepositoryAccess,
    user: &coauth_data::User,
    devices: &mut HashSet<String>,
) -> Result<(), JobError> {
    let mut cursor = Pagination::first(5000);
    loop {
        let page = repo
            .oauth_session()
            .list(
                OAuthSessionFilter::new().for_user(user).active_only(),
                cursor,
            )
            .await
            .map_err(JobError::retry)?;

        for edge in &page.edges {
            for scope_token in &*edge.node.scope {
                if let Some(id) = extract_device_id(scope_token) {
                    devices.insert(id.to_owned());
                }
            }
            cursor = cursor.after(edge.cursor);
        }

        if !page.has_next_page {
            break;
        }
    }
    Ok(())
}

/// Paginate through all active personal sessions and collect device IDs.
async fn collect_devices_from_personal(
    repo: &mut impl RepositoryAccess,
    user: &coauth_data::User,
    devices: &mut HashSet<String>,
) -> Result<(), JobError> {
    let mut cursor = Pagination::first(5000);
    loop {
        let page = repo
            .personal_session()
            .list(
                PersonalSessionFilter::new()
                    .for_actor_user(user)
                    .active_only(),
                cursor,
            )
            .await
            .map_err(JobError::retry)?;

        for edge in &page.edges {
            let (session, _) = &edge.node;
            for scope_token in &*session.scope {
                if let Some(id) = extract_device_id(scope_token) {
                    devices.insert(id.to_owned());
                }
            }
            cursor = cursor.after(edge.cursor);
        }

        if !page.has_next_page {
            break;
        }
    }
    Ok(())
}
