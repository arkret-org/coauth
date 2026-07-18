pub use coauth_account_types::RecoveryStatusOutcome;
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
pub struct StartRecoveryOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ResendRecoveryOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
