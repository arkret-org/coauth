#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ── Viewer & User ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
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
    pub username: String,
    #[serde(default)]
    pub can_request_admin: bool,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    #[serde(default)]
    pub matrix: Option<MatrixUser>,
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
pub struct MatrixUser {
    pub mxid: String,
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
pub struct UnlinkResponse {
    pub status: String,
}

// ── Session types ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
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
    Oauth2Session(Oauth2Session),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Oauth2Session {
    pub id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub client: Option<Oauth2Client>,
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
pub struct Oauth2Client {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
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

// ── Mutation payloads ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SetPasswordPayload {
    pub status: SetPasswordStatus,
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
pub struct ProfilePatchRequest {
    #[serde(default)]
    pub display_name: Option<Option<String>>,
    #[serde(default)]
    pub avatar_url: Option<Option<String>>,
    #[serde(default)]
    pub preferred_locale: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PatchViewerProfileResponse {
    pub profile: UserProfile,
    pub matrix: MatrixUser,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AdminUserPatchRequest {
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
    pub hs_erase: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserEmailPatchRequest {
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

// ── Combined viewer response from REST /api/v1/viewer ──────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ViewerResponse {
    pub viewer: Viewer,
    pub viewer_session: ViewerSession,
    pub site_config: SiteConfig,
}

// ── Backward-compatible aliases for page data ──────────────────

pub type CurrentUserGreetingData = ViewerResponse;
pub type UserProfileData = ViewerResponse;
pub type SessionsOverviewData = ViewerResponse;
pub type AppSessionsListData = ViewerResponse;
pub type BrowserSessionListData = ViewerResponse;
pub type PasswordChangeData = ViewerResponse;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FooterData {
    pub site_config: SiteConfig,
}

// REST API returns payloads directly, but keep wrapper types for compat
pub type SetPasswordResult = SetPasswordPayload;
pub type SetDisplayNameResult = SetDisplayNamePayload;
pub type AddEmailResult = AddEmailPayload;
pub type EndBrowserSessionResult = EndSessionPayload;
pub type EndOauth2SessionResult = EndSessionPayload;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PlanManagementData {
    pub site_config: SiteConfig,
}

// REST API returns session directly (it IS the node)
pub type SessionDetailData = SessionNode;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum SessionNode {
    BrowserSession(BrowserSession),
    Oauth2Session(Oauth2Session),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UserEmailListData {
    pub viewer_session: ViewerSession,
}

pub type CompleteEmailAuthResult = CompleteEmailAuthPayload;
pub type DeactivateUserResult = DeactivateUserPayload;

// ── Client detail ──────────────────────────────────────────────

// REST returns client directly
pub type ClientDetailData = Oauth2ClientDetail;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum ClientNode {
    Oauth2Client(Oauth2ClientDetail),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Oauth2ClientDetail {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub logo_uri: Option<String>,
}

// ── Device redirect ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DeviceRedirectData {
    pub viewer: Viewer,
}

// ── Password recovery ─────────────────────────────────────────

pub type PasswordRecoveryData = ViewerResponse;

// ── Cross-signing reset ───────────────────────────────────────

pub type CurrentViewerData = ViewerResponse;
pub type AllowCrossSigningResetResult = AllowCrossSigningResetPayload;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AllowCrossSigningResetPayload {
    pub user: Option<User>,
}

// ── Resend recovery email ─────────────────────────────────────

pub type ResendRecoveryEmailResult = ResendRecoveryEmailPayload;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResendRecoveryEmailPayload {
    pub status: String,
    #[serde(default, alias = "progressUrl")]
    pub progress_url: Option<String>,
}

// ── Remove email result ───────────────────────────────────────

pub type RemoveEmailResult = RemoveEmailPayload;

// ── Session name mutation results ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SetSessionNamePayload {
    pub status: String,
}

pub type SetOauth2SessionNameResult = SetSessionNamePayload;

// ── Email verification query/mutation types ───────────────────

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

// REST returns the email auth directly
pub type VerifyEmailData = UserEmailAuthentication;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResendEmailAuthCodePayload {
    pub status: String,
}

pub type ResendEmailAuthCodeResult = ResendEmailAuthCodePayload;

// ── Auth API types ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LoginResponse {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub redirect: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LogoutResponse {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpstreamProvider {
    pub id: String,
    #[serde(default)]
    pub human_name: Option<String>,
    #[serde(default)]
    pub brand_name: Option<String>,
    pub authorize_url: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ProvidersResponse {
    pub providers: Vec<UpstreamProvider>,
    pub password_login_enabled: bool,
    pub password_registration_enabled: bool,
    #[serde(default, alias = "accountRecoveryAllowed")]
    pub account_recovery_allowed: bool,
}

// ── Registration API types ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RegisterResponse {
    pub status: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub next_step: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Set when the flow engine is enabled; the frontend can use this to
    /// switch to the flow session API.
    #[serde(default)]
    pub flow_session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RegisterStatusResponse {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email_pending: bool,
    #[serde(default)]
    pub pending_email: Option<String>,
    pub next_step: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct VerifyEmailRequest {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DisplayNameRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub skip: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StepResponse {
    pub status: String,
    #[serde(default)]
    pub next_step: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Set when the registration was started as part of another flow
    /// (e.g. an OAuth2 authorization grant continuation). The frontend
    /// uses this to resume the original flow after the account is created.
    #[serde(default)]
    pub post_auth_action: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ChangeRegistrationEmailResponse {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Recovery API types ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStartRequest {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStartResponse {
    pub status: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryStatusResponse {
    pub id: String,
    pub email: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RecoveryTicketStatusResponse {
    pub status: String,
    #[serde(default)]
    pub email: Option<String>,
}

// ── OAuth2 Consent API types ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ConsentClientInfo {
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
pub struct ConsentUserInfo {
    pub mxid: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ConsentDataResponse {
    pub grant_id: String,
    pub client: ConsentClientInfo,
    pub scope: String,
    pub user: ConsentUserInfo,
    #[serde(default)]
    pub policy_violation: bool,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ConsentSubmitResponse {
    pub status: String,
    #[serde(default)]
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

// ── Device Code API types ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DeviceLinkResponse {
    pub status: String,
    #[serde(default)]
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DeviceConsentResponse {
    pub status: String,
}

// ── Security summary (GET /api/v1/viewer/security) ───────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SecuritySummaryResponse {
    pub has_password: bool,
    pub active_sessions_count: usize,
    pub linked_providers_count: usize,
    pub verified_emails_count: usize,
    pub verified_phones_count: usize,
}

// ── Linked accounts list (GET /api/v1/linked-accounts) ───────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LinkedAccountsResponse {
    pub accounts: Vec<LinkedAccount>,
}

// ── Workflow inbox (GET /api/v1/viewer/workflow-inbox) ───────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WorkflowInboxItem {
    pub session_id: String,
    pub flow_slug: String,
    pub flow_title: String,
    pub current_stage: String,
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WorkflowInboxResponse {
    pub pending: Vec<WorkflowInboxItem>,
    pub total: usize,
}

// ── Notification preferences (GET/PATCH /api/v1/viewer/preferences)

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
pub struct NotificationPreferencesResponse {
    pub available_channels: Vec<ChannelAvailability>,
    pub preferences: Vec<ChannelPreference>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateNotificationPreferencesResponse {
    pub preferences: Vec<ChannelPreference>,
}
