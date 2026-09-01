pub use coauth_account_types::{
    AppSession, BootstrapAdminStatus, BrowserSession, ChangeRegistrationEmailOutcome,
    ChannelAvailability, ChannelPreference, DeviceLinkOutcome, DeviceType, LinkedAccount,
    LinkedAccountsOutcome, NotificationPreferencesOutcome, OAuthSession, PrincipalUser,
    RecoveryStatusOutcome, RecoveryTicketStatusOutcome, RegisterInput, RegisterOutcome, Session,
    SiteConfigOutcome as SiteConfig, UnlinkOutcome, UpdateNotificationPreferencesOutcome,
    UserEmail, ViewerOutcome, ViewerUserProfile as UserProfile,
};
use serde::{Deserialize, Serialize};

// ── Mutation payloads ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SetPasswordPayload {
    pub status: SetPasswordStatus,
    #[serde(default)]
    pub trust_boundary: Option<PasswordRecoveryTrustBoundary>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetPasswordStatus {
    Allowed,
    WrongPassword,
    InvalidNewPassword,
    NotFound,
    NoCurrentPassword,
    PasswordChangesDisabled,
    AccountLocked,
    ExpiredRecoveryTicket,
    NoSuchRecoveryTicket,
    RecoveryTicketAlreadyUsed,
    DeviceTrustRecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PasswordRecoveryTrustBoundary {
    pub recovery_credential_kind: String,
    pub account_password_reset: bool,
    pub device_trust_reset: bool,
    pub trusted_recovery_service_used: bool,
    pub device_trust_recovery_required: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PatchViewerProfileOutcome {
    pub profile: UserProfile,
    pub principal: PrincipalUser,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AddEmailPayload {
    pub status: AddEmailStatus,
    pub email: Option<UserEmail>,
    pub violations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AddEmailStatus {
    Added,
    Exists,
    Invalid,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RemoveEmailPayload {
    pub status: RemoveEmailStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoveEmailStatus {
    Removed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EndSessionPayload {
    pub status: EndSessionStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndSessionStatus {
    Ended,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CompleteEmailAuthPayload {
    pub status: CompleteEmailAuthStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompleteEmailAuthStatus {
    Completed,
    InvalidCode,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DeactivateUserPayload {
    pub status: DeactivateUserStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeactivateUserStatus {
    Deactivated,
    NotFound,
    IncorrectPassword,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct OAuthClientDetail {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResendRecoveryEmailPayload {
    pub status: String,
    #[serde(default)]
    pub progress_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UserEmailAuthentication {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResendEmailAuthCodePayload {
    pub status: String,
}

// ── Auth API types ────────────────────────────────────────────

pub use coauth_account_types::passkey::{
    PasskeyListOutcome, PasskeyMutationOutcome, PasskeySummary,
};
pub use coauth_account_types::{CurrentAccountInfo, LoginOutcome, ProvidersOutcome};

// ── Registration API types ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RegisterStatusOutcome {
    pub id: String,
    pub handle: String,
    #[serde(default)]
    pub email_pending: bool,
    #[serde(default)]
    pub pending_email: Option<String>,
    pub next_step: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StepOutcome {
    pub status: String,
    #[serde(default)]
    pub next_step: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Set when the registration was started as part of another strand
    /// (e.g. an OAuth authorization grant continuation). The frontend
    /// uses this to resume the original strand after the account is created.
    #[serde(default)]
    pub post_auth_action: Option<coauth_account_types::PostAuthAction>,
}

// ── Recovery API types ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStartOutcome {
    pub status: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

// ── OAuth Approval API types ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ApprovalClientInfo {
    pub id: String,
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ApprovalUserInfo {
    pub principal_address: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ApprovalDataOutcome {
    pub grant_id: String,
    pub client: ApprovalClientInfo,
    pub scope: String,
    pub user: ApprovalUserInfo,
    #[serde(default)]
    pub policy_violation: bool,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct OAuthApprovalSubmitOutcome {
    pub status: String,
    #[serde(default)]
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Device Code API types ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DeviceApprovalOutcome {
    pub status: String,
}

// ── Security summary (GET /_coauth/self/viewer/security) ───────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SecuritySummaryOutcome {
    pub has_password: bool,
    pub active_sessions_count: usize,
    pub linked_providers_count: usize,
    pub verified_emails_count: usize,
    pub verified_phones_count: usize,
}

// ── Linked accounts list (GET /_coauth/self/linked-accounts) ───────
