//! Cascade-revoke active session grants when a device is revoked.
//!
//! A device-revoke MUST atomically:
//!   1. Mark the device record as revoked (today: emit an admin-audit log
//!      entry — there is no `devices` table yet, so the device identity is
//!      the device DID/identifier supplied by the caller).
//!   2. Revoke every still-active `oauth2_session_grant` whose
//!      `device_id` column equals the revoked device.
//!
//! Both writes share a Diesel `BoxRepository` transaction so a partial
//! failure rolls the entire batch back. This protects against the
//! "device looks revoked but a grant is still being honoured" race.

use chrono::{DateTime, Utc};
use coauth_data::{
    BoxClock, BoxRepository, Pagination, RepositoryAccess,
    oauth2::SessionGrantFilter,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceRevokeError {
    #[error("repository error: {0}")]
    Repository(#[from] coauth_data::RepositoryError),
}

/// Outcome of a device-revoke cascade.
#[derive(Debug, Clone)]
pub struct DeviceRevokeOutcome {
    /// The device id passed in.
    pub device_id: String,
    /// Number of session grants revoked.
    pub revoked_session_grants: usize,
    /// Time the cascade was applied.
    pub revoked_at: DateTime<Utc>,
}

/// Iterate every active session grant for `device_id` and revoke it.
/// Caller is responsible for `repo.save()` (so the device-mutation and
/// the cascade share one commit).
pub async fn cascade_revoke_session_grants(
    repo: &mut BoxRepository,
    clock: &dyn coauth_data::Clock,
    device_id: &str,
) -> Result<DeviceRevokeOutcome, DeviceRevokeError> {
    let now = clock.now();
    let mut total = 0usize;

    loop {
        let filter = SessionGrantFilter::new()
            .for_device(device_id)
            .active_at(now);
        let page = repo
            .oauth2_session_grant()
            .list(filter, Pagination::first(100))
            .await?;

        let edges = page.edges;
        if edges.is_empty() {
            break;
        }

        let has_next = page.has_next_page;
        for edge in edges {
            // Filter is `active_at(now)` so this grant has no `revoked_at`
            // and hasn't expired.
            repo.oauth2_session_grant().revoke(clock, edge.node).await?;
            total += 1;
        }

        if !has_next {
            break;
        }
    }

    Ok(DeviceRevokeOutcome {
        device_id: device_id.to_owned(),
        revoked_session_grants: total,
        revoked_at: now,
    })
}

/// Convenience wrapper that loads its own clock from the supplied
/// [`BoxClock`]. Same semantics as
/// [`cascade_revoke_session_grants`].
pub async fn cascade_revoke_with_box_clock(
    repo: &mut BoxRepository,
    clock: &BoxClock,
    device_id: &str,
) -> Result<DeviceRevokeOutcome, DeviceRevokeError> {
    cascade_revoke_session_grants(repo, &**clock, device_id).await
}
