use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, ToSchema)]
pub struct StartRecoveryInput {
    pub email: String,
    /// Solved CAPTCHA token, supplied when the deployment has a CAPTCHA
    /// provider configured (`site.captcha`). Verified before the
    /// rate-limited recovery session is allocated.
    #[serde(default)]
    pub captcha_token: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct StartRecoveryResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the flow engine is enabled, the frontend should use this ID
    /// with the flow session API (`/api/v1/flow/session/:id`) instead of
    /// the legacy recovery step endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_session_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryStatusResponse {
    pub id: String,
    pub email: String,
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ResendRecoveryResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
