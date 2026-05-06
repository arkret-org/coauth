//! Contrix device administration endpoints.

use chrono::{DateTime, Utc};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AppError, JsonResult, routing::admin::call_context::extract_call_context};

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
#[allow(dead_code)]
pub struct RevokeDeviceRequest {
    /// Operator-supplied reason for audit.
    reason: String,

    /// Optional approval proof for high-risk revocations.
    approval_proof: Option<String>,
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
pub async fn revoke_device(req: &mut Request, depot: &Depot) -> JsonResult<DeviceRecord> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): revoke device binding and cascade active session grants.
    Err(AppError::not_implemented(
        "device revocation is not implemented yet",
    ))
}
