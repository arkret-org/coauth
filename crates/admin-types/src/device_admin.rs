//! Shared wire DTOs for the coauth device-administration surface.
//!
//! These types are serialized by `coauth-backend` and deserialized by
//! operator clients such as `sodmin`. Keeping both sides on this crate turns a
//! field or enum drift into a compile error instead of a runtime serde mismatch.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMfaState {
    Verified,
    Required,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct DeviceRecord {
    /// Device identifier.
    pub id: String,
    /// Owning account ULID.
    pub account_id: Option<String>,
    /// Human-facing device label.
    pub display_name: Option<String>,
    /// Current device risk level.
    pub risk_level: DeviceRiskLevel,
    /// MFA/passkey state for this device.
    pub mfa_state: DeviceMfaState,
    /// When the device was registered.
    pub registered_at: Option<DateTime<Utc>>,
    /// When the device was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl DeviceRecord {
    #[must_use]
    pub fn is_revocable(&self) -> bool {
        !self.id.is_empty() && self.revoked_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct DeviceListResBody {
    /// Devices visible to the current admin query.
    pub data: Vec<DeviceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename = "RevokeDeviceRequestBody")]
pub struct RevokeDeviceRequestBody {
    /// Operator-supplied reason for audit.
    pub reason: String,
    /// Optional approval proof for high-risk revocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_proof: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct DeviceRevokeOutcome {
    /// The device that was revoked.
    pub device: DeviceRecord,
    /// How many active session grants were cascade-revoked atomically.
    pub revoked_session_grants: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_record_round_trips_the_admin_wire_shape() {
        let row: DeviceRecord = serde_json::from_value(serde_json::json!({
            "id": "device-1",
            "account_id": "01JZ9PK6HKFY0MM7C0TMZ1X8N7",
            "display_name": "Laptop",
            "risk_level": "high",
            "mfa_state": "required",
            "registered_at": "2026-05-09T12:00:00Z",
            "revoked_at": null
        }))
        .unwrap();

        assert_eq!(row.risk_level, DeviceRiskLevel::High);
        assert_eq!(row.mfa_state, DeviceMfaState::Required);
        assert!(row.is_revocable());
        assert_eq!(
            serde_json::to_value(&row).unwrap()["account_id"],
            "01JZ9PK6HKFY0MM7C0TMZ1X8N7"
        );
    }
}
