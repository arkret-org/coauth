//! Contrix device administration endpoints.

use chrono::{DateTime, Utc};
use coauth_data::{RepositoryAccess, audit::AdminOperation};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AppError, JsonResult,
    handlers::admin::{audit_helper::record_admin_operation, call_context::extract_call_context},
    services::device_revoke::cascade_revoke_session_grants,
};

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMfaState {
    Verified,
    Required,
    Unknown,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DeviceRecord {
    /// Device identifier.
    id: String,

    /// Owning account ULID.
    account_id: Option<String>,

    /// Device DID, when the device has been bound to a DID.
    device_did: Option<String>,

    /// Human-facing device label.
    display_name: Option<String>,

    /// Current device risk level.
    risk_level: DeviceRiskLevel,

    /// MFA/passkey state for this device.
    mfa_state: DeviceMfaState,

    /// When the device was registered.
    registered_at: Option<DateTime<Utc>>,

    /// When the device was revoked.
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DeviceListResponse {
    data: Vec<DeviceRecord>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "RevokeDeviceRequest")]
pub struct RevokeDeviceRequest {
    /// Operator-supplied reason for audit.
    pub reason: String,

    /// Optional approval proof for high-risk revocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_proof: Option<String>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DeviceRevokeResponse {
    /// The device that was revoked.
    pub device: DeviceRecord,

    /// How many active session grants were cascade-revoked atomically.
    pub revoked_session_grants: usize,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.devices.list", skip_all)]
pub async fn list_devices(req: &mut Request, depot: &Depot) -> JsonResult<DeviceListResponse> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): derive device records from device DID registration and
    // session bindings instead of legacy Matrix device scopes.
    Err(AppError::not_implemented(
        "device administration list is not implemented yet",
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.devices.revoke", skip_all)]
pub async fn revoke_device(req: &mut Request, depot: &Depot) -> JsonResult<DeviceRevokeResponse> {
    let device_id = req
        .param::<String>("id")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("missing device id"))?;
    let body: RevokeDeviceRequest = req.parse_json().await.map_err(AppError::internal)?;
    let reason = body.reason.trim().to_owned();
    if reason.is_empty() {
        return Err(AppError::bad_request("reason is required"));
    }

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();

    // Cascade-revoke every active session grant tied to this device, in
    // the same repository transaction as the audit-log entry. Either both
    // succeed (`repo.save()` below) or both roll back.
    let outcome = cascade_revoke_session_grants(&mut repo, &*clock, &device_id)
        .await
        .map_err(AppError::internal)?;

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::Other("device.revoke".to_owned()),
        "device",
        None,
        serde_json::json!({
            "device_id": device_id,
            "reason": reason,
            "approval_proof_present": body.approval_proof.is_some(),
            "revoked_session_grants": outcome.revoked_session_grants,
            "revoked_at": outcome.revoked_at,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(DeviceRevokeResponse {
        device: DeviceRecord {
            id: device_id.clone(),
            account_id: None,
            device_did: Some(device_id),
            display_name: None,
            risk_level: DeviceRiskLevel::Unknown,
            mfa_state: DeviceMfaState::Unknown,
            registered_at: None,
            revoked_at: Some(outcome.revoked_at),
        },
        revoked_session_grants: outcome.revoked_session_grants,
    }))
}
