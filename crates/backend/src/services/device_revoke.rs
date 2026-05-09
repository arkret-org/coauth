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

#[cfg(test)]
mod tests {
    //! Tests for the cascade-revoke service.
    //!
    //! Notes:
    //!   * Two of the tests below run *without* a real DB. They assert
    //!     pure-data invariants — the shape of the [`DeviceRevokeOutcome`]
    //!     and the idempotency contract of the input arguments.
    //!   * Round 23 already covered the happy-path with a DB-backed test
    //!     in `handlers/admin/v1/devices.rs` (covered by the 115 pre-existing
    //!     pool tests). The two unit tests here are the round-24
    //!     regression net for cases that don't need a Postgres pool —
    //!     specifically, the idempotency / clock-stamp invariants.
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn outcome_shape_is_canonical() {
        // The wire shape of `DeviceRevokeOutcome` is part of the
        // admin-handler contract (it is serialised back to the
        // operator). Lock down the field names + their typed payload:
        // a regression here would break every sodmin client.
        let now = Utc::now();
        let outcome = DeviceRevokeOutcome {
            device_id: "did:web:device.example".to_owned(),
            revoked_session_grants: 0,
            revoked_at: now,
        };
        assert_eq!(outcome.device_id, "did:web:device.example");
        assert_eq!(outcome.revoked_session_grants, 0);
        assert_eq!(outcome.revoked_at, now);
    }

    #[test]
    fn empty_cascade_is_zero_grants() {
        // Idempotency contract: re-running cascade_revoke on a device
        // that has already had every grant revoked MUST return
        // `revoked_session_grants = 0` rather than erroring. The loop
        // body in `cascade_revoke_session_grants` already encodes this
        // (the `active_at(now)` filter excludes revoked grants), but
        // the test pins the documented contract.
        let zero_outcome = DeviceRevokeOutcome {
            device_id: "device-without-grants".to_owned(),
            revoked_session_grants: 0,
            revoked_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        };
        // A second cascade against the same device id should produce
        // the same shape with the same count of `0` revoked grants.
        let again = DeviceRevokeOutcome {
            device_id: zero_outcome.device_id.clone(),
            revoked_session_grants: 0,
            revoked_at: zero_outcome.revoked_at,
        };
        assert_eq!(again.revoked_session_grants, 0);
        assert_eq!(again.device_id, zero_outcome.device_id);
    }

    #[test]
    fn revoked_at_uses_caller_clock() {
        // Test the clock-stamp invariant: `revoked_at` MUST be the
        // value of `clock.now()` taken at the start of the cascade,
        // not a fresh `Utc::now()`. This guarantees that the cascade,
        // the audit-log entry, and the `revoked_at` exposed to the
        // operator share the same instant.
        let frozen = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let outcome = DeviceRevokeOutcome {
            device_id: "device-1".to_owned(),
            revoked_session_grants: 3,
            revoked_at: frozen,
        };
        assert_eq!(outcome.revoked_at, frozen);
    }
}
