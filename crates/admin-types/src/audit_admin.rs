use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum AuditSignatureStatus {
    Verified,
    Unsigned,
    Invalid,
    KeyUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AuditEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user_id: Option<String>,
    pub operation: String,
    pub resource_type: String,
    pub resource_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub signature_status: AuditSignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AuditFeedOutcome {
    pub data: Vec<AuditEntry>,
}
