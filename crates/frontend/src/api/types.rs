#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ── Viewer & User ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
pub enum Viewer {
    User(User),
    Anonymous(Anonymous),
}

impl Viewer {
    pub fn as_user(&self) -> Option<&User> {
        match self {
            Viewer::User(u) => Some(u),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Anonymous {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub can_request_admin: bool,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    #[serde(default)]
    pub principal: Option<PrincipalUser>,
    #[serde(default)]
    pub has_password: Option<bool>,
    #[serde(default)]
    pub emails: Option<EmailConnection>,
    #[serde(default)]
    pub linked_accounts: Option<Vec<LinkedAccount>>,
    #[serde(default)]
    pub browser_sessions: Option<BrowserSessionConnection>,
    #[serde(default)]
    pub app_sessions: Option<AppSessionConnection>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PrincipalUser {
    pub principal_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserProfile {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub preferred_locale: Option<String>,
    pub updated_at: String,
}

// ── Linked accounts ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LinkedAccount {
    pub id: String,
    pub provider_id: String,
    #[serde(default)]
    pub provider_name: Option<String>,
    #[serde(default)]
    pub provider_brand: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub human_account_name: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UnlinkOutcome {
    pub status: String,
}

// ── Session types ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
pub enum ViewerSession {
    BrowserSession(BrowserSession),
    Anonymous(Anonymous),
}

impl ViewerSession {
    pub fn as_browser_session(&self) -> Option<&BrowserSession> {
        match self {
            ViewerSession::BrowserSession(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BrowserSession {
    pub id: String,
    #[serde(default)]
    pub user: Option<User>,
    #[serde(default)]
    pub user_agent: Option<UserAgent>,
    #[serde(default)]
    pub last_active_ip: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_authentication: Option<Authentication>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserAgent {
    pub name: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub device_type: DeviceType,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceType {
    Pc,
    Mobile,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Authentication {
    pub id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
pub enum AppSession {
    OAuthSession(OAuthSession),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct OAuthSession {
    pub id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub client: Option<OAuthClient>,
    #[serde(default)]
    pub user_agent: Option<UserAgent>,
    #[serde(default)]
    pub last_active_ip: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct OAuthClient {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
pub enum Session {
    BrowserSession(BrowserSession),
    OAuthSession(OAuthSession),
}

// ── Email ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserEmail {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub confirmed_at: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EmailConnection {
    pub total_count: i32,
    #[serde(default)]
    pub edges: Vec<EmailEdge>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EmailEdge {
    pub cursor: String,
    pub node: UserEmail,
}

// ── Session connections / pagination ───────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PageInfo {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    pub start_cursor: Option<String>,
    pub end_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BrowserSessionConnection {
    pub total_count: i32,
    pub edges: Vec<BrowserSessionEdge>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BrowserSessionEdge {
    pub cursor: String,
    pub node: BrowserSession,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AppSessionConnection {
    pub total_count: i32,
    pub edges: Vec<AppSessionEdge>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AppSessionEdge {
    pub cursor: String,
    pub node: AppSession,
}

// ── Site Config ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SiteConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub email_change_allowed: bool,
    #[serde(default)]
    pub password_login_enabled: bool,
    #[serde(default)]
    pub account_deactivation_allowed: bool,
    #[serde(default)]
    pub display_name_change_allowed: bool,
    #[serde(default)]
    pub password_registration_enabled: bool,
    #[serde(default)]
    pub bootstrap_admin_token_enabled: bool,
    #[serde(default)]
    pub minimum_password_complexity: i32,
    #[serde(default)]
    pub imprint: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
    #[serde(default)]
    pub admin_portal_url: Option<String>,
    #[serde(default)]
    pub plan_management_iframe_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BootstrapAdminStatus {
    #[serde(default)]
    pub has_admin: bool,
    #[serde(default)]
    pub token_configured: bool,
    #[serde(default)]
    pub setup_required: bool,
}

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
    pub cross_signing_reset: bool,
    pub trusted_recovery_service_used: bool,
    pub device_trust_recovery_required: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SetDisplayNamePayload {
    pub status: SetDisplayNameStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetDisplayNameStatus {
    Set,
    Invalid,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ProfilePatchRequestBody {
    #[serde(default)]
    pub display_name: Option<Option<String>>,
    #[serde(default)]
    pub avatar_url: Option<Option<String>>,
    #[serde(default)]
    pub preferred_locale: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PatchViewerProfileOutcome {
    pub profile: UserProfile,
    pub principal: PrincipalUser,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AdminUserPatchRequestBody {
    #[serde(default)]
    pub display_name: Option<Option<String>>,
    #[serde(default)]
    pub avatar_url: Option<Option<String>>,
    #[serde(default)]
    pub preferred_locale: Option<Option<String>>,
    #[serde(default)]
    pub admin: Option<bool>,
    #[serde(default)]
    pub locked: Option<bool>,
    #[serde(default)]
    pub deactivated: Option<bool>,
    #[serde(default)]
    pub principal_erase: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserEmailPatchRequestBody {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub confirmed: Option<bool>,
    #[serde(default)]
    pub is_primary: Option<bool>,
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

// ── Combined viewer response from REST /_coauth/self/viewer ──────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ViewerOutcome {
    pub viewer: Viewer,
    pub viewer_session: ViewerSession,
    pub site_config: SiteConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum ClientNode {
    OAuthClient(OAuthClientDetail),
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
pub struct SetSessionNamePayload {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UserEmailAuthentication {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum EmailAuthNode {
    UserEmailAuthentication(UserEmailAuthentication),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResendEmailAuthCodePayload {
    pub status: String,
}

// ── Auth API types ────────────────────────────────────────────

pub use coauth_account_types::{CurrentAccountInfo, LoginOutcome, ProvidersOutcome};

// ── Registration API types ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RegisterRequestBody {
    pub handle: String,
    #[serde(default)]
    pub email: Option<String>,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RegisterOutcome {
    pub status: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub next_step: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

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
pub struct VerifyEmailRequestBody {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DisplayNameRequestBody {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub skip: Option<bool>,
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
    pub post_auth_action: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ChangeRegistrationEmailOutcome {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Recovery API types ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStartRequestBody {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStartOutcome {
    pub status: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStatusOutcome {
    pub id: String,
    pub email: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryTicketStatusOutcome {
    pub status: String,
    #[serde(default)]
    pub email: Option<String>,
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
    pub principal_id: String,
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
pub struct DeviceLinkOutcome {
    pub status: String,
    #[serde(default)]
    pub grant_id: Option<String>,
}

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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LinkedAccountsOutcome {
    pub accounts: Vec<LinkedAccount>,
}

// ── Workflow inbox (GET /_coauth/self/viewer/workflow-inbox) ───────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WorkflowInboxItem {
    pub session_id: String,
    pub strand_slug: String,
    pub strand_title: String,
    pub current_stage: String,
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WorkflowInboxOutcome {
    pub pending: Vec<WorkflowInboxItem>,
    pub total: usize,
}

// ── Notification preferences (GET/PATCH /_coauth/self/viewer/preferences)

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ChannelAvailability {
    pub channel: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ChannelPreference {
    pub channel: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct NotificationPreferencesOutcome {
    pub available_channels: Vec<ChannelAvailability>,
    pub preferences: Vec<ChannelPreference>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateNotificationPreferencesOutcome {
    pub preferences: Vec<ChannelPreference>,
}
