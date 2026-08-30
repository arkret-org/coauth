//! Admin endpoint for retrieving recent admin audit operations.
//!
//! Returns a feed of admin operations, optionally filtered by admin user or
//! resource type. Queries the [`AuditRepository`] for persisted admin
//! operation log entries.

use coauth_admin_types::{AuditEntry, AuditFeedOutcome};
use coauth_data::RepositoryAccess;
use coauth_data::audit::{AdminOperation, AdminOperationFilter, AdminOperationLog};
use salvo::prelude::*;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::audit_helper::{
    AuditSignatureStatus, verify_admin_operation_signature,
};
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::arkret::owning_station_did_for;
use crate::handlers::common::DepotExt;
use crate::{AppError, JsonResult};

/// Convert an [`AdminOperation`] enum variant into a human-readable
/// dot-separated operation string for the API response.
fn format_operation(op: &AdminOperation) -> String {
    match op {
        AdminOperation::UserCreated => "user.create".to_owned(),
        AdminOperation::UserLocked => "user.lock".to_owned(),
        AdminOperation::UserUnlocked => "user.unlock".to_owned(),
        AdminOperation::UserDeactivated => "user.deactivate".to_owned(),
        AdminOperation::UserReactivated => "user.reactivate".to_owned(),
        AdminOperation::UserPasswordSet => "user.set_password".to_owned(),
        AdminOperation::UserAdminSet => "user.set_admin".to_owned(),
        AdminOperation::UserUpdated => "user.update".to_owned(),
        AdminOperation::UserEmailAdded => "user_email.add".to_owned(),
        AdminOperation::UserEmailUpdated => "user_email.update".to_owned(),
        AdminOperation::UserEmailRemoved => "user_email.remove".to_owned(),
        AdminOperation::SessionTerminated => "session.finish".to_owned(),
        AdminOperation::RegistrationTokenCreated => "registration_token.create".to_owned(),
        AdminOperation::RegistrationTokenRevoked => "registration_token.revoke".to_owned(),
        AdminOperation::PolicyDataUpdated => "policy_data.update".to_owned(),
        AdminOperation::UpstreamProviderModified => "upstream_provider.modify".to_owned(),
        AdminOperation::UpstreamLinkCreated => "upstream_link.create".to_owned(),
        AdminOperation::UpstreamLinkUpdated => "upstream_link.update".to_owned(),
        AdminOperation::UpstreamLinkDeleted => "upstream_link.delete".to_owned(),
        AdminOperation::OAuthClientLocalizedMetadataUpdated => {
            "oauth_client.localized_metadata.update".to_owned()
        }
        AdminOperation::Other(s) => s.clone(),
    }
}

fn audit_entry_from_log(
    log: AdminOperationLog,
    signature_status: AuditSignatureStatus,
) -> AuditEntry {
    let details = if log.details.is_null() || log.details == serde_json::json!({}) {
        None
    } else {
        Some(log.details)
    };

    AuditEntry {
        id: log.id.to_string(),
        admin_user_id: Some(log.admin_user_id.to_string()),
        operation: format_operation(&log.operation),
        resource_kind: log.resource_type,
        resource_id: log.resource_id.map(|id| id.to_string()).unwrap_or_default(),
        details,
        created_at: log.created_at,
        signature_status,
    }
}

/// Query parameters accepted by the audit feed endpoint.
#[derive(Deserialize, Default)]
pub struct AuditFeedQuery {
    /// Maximum number of entries to return (default: 50).
    pub limit: Option<usize>,

    /// If provided, only return entries for this admin user.
    pub admin_user_id: Option<String>,

    /// If provided, only return entries matching this resource type.
    pub resource_type: Option<String>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.audit_feed", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> JsonResult<AuditFeedOutcome> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;

    let query: AuditFeedQuery = req
        .parse_queries()
        .map_err(|error| AppError::bad_request(format!("Invalid filter parameters: {error}")))?;
    let key_store = depot.key_store()?;
    let arkret_config = depot.arkret_config()?;
    let service_did = owning_station_did_for(&arkret_config);

    let mut filter = AdminOperationFilter::new().with_limit(query.limit.unwrap_or(50));

    if let Some(ref admin_id_str) = query.admin_user_id
        && let Ok(admin_id) = admin_id_str.parse::<Ulid>()
    {
        filter = filter.for_admin_user(admin_id);
    }

    if let Some(ref resource_type) = query.resource_type {
        filter = filter.for_resource_type(resource_type);
    }

    let logs = repo.audit().list_admin_operations(filter).await?;

    repo.cancel().await?; // read-only, no save needed

    let data: Vec<AuditEntry> = logs
        .into_iter()
        .map(|log| {
            let signature_status = verify_admin_operation_signature(&log, &key_store, &service_did);
            audit_entry_from_log(log, signature_status)
        })
        .collect();

    Ok(Json(AuditFeedOutcome { data }))
}
