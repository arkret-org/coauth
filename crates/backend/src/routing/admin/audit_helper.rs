//! Unified helper for writing admin audit log entries.
//!
//! This module provides [`record_admin_operation`], a single function that
//! encapsulates the repeated pattern of conditionally writing an admin
//! operation audit log when the caller is an authenticated admin user.

use coauth_data::{
    BoxRepository, RepositoryAccess, RepositoryError,
    audit::{AdminOperation, NewAdminOperationLog},
};
use rand_core::RngCore;
use ulid::Ulid;

/// Record an admin operation in the audit log, if the caller is an
/// authenticated admin user.
///
/// When `admin_user` is `None` (e.g. the request was made with a
/// service-level token that has no associated user), the function is a
/// no-op.
pub async fn record_admin_operation(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn coauth_data::Clock,
    admin_user: Option<&coauth_data::User>,
    operation: AdminOperation,
    resource_type: &str,
    resource_id: Option<Ulid>,
    details: serde_json::Value,
) -> Result<(), RepositoryError> {
    if let Some(admin) = admin_user {
        let mut params = NewAdminOperationLog::new(admin.id, operation, resource_type, details);
        if let Some(id) = resource_id {
            params = params.with_resource_id(id);
        }
        repo.audit().add_admin_operation(rng, clock, params).await?;
    }
    Ok(())
}
