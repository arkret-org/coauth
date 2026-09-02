//! Shared serde types for the coauth account UI API surface.
//!
//! Scope: coauth-private browser/account REST endpoints served under
//! `/_coauth`, such as `/_coauth/gate/account/auth/login`. Protocol-level
//! Arkret endpoints served under `/_arkret` continue to use types from
//! `arkret-rust-sdk`.

pub mod passkey;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Describes what should happen after a user completes authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PostAuthAction {
    ContinueAuthorizationGrant {
        id: Ulid,
    },
    ContinueDeviceCodeGrant {
        id: Ulid,
    },
    ChangePassword,
    LinkUpstream {
        id: Ulid,
    },
    ManageAccount {
        #[serde(flatten)]
        action: Option<AccountAction>,
    },
}

impl PostAuthAction {
    #[must_use]
    pub const fn continue_grant(id: Ulid) -> Self {
        Self::ContinueAuthorizationGrant { id }
    }
}

/// Account-management destination carried by [`PostAuthAction::ManageAccount`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AccountAction {
    Profile,
    SessionsList,
    SessionView { device_id: String },
    SessionEnd { device_id: String },
}

/// Field-specific validation failures returned by upstream account linking.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct UpstreamLinkFieldErrors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_terms: Option<String>,
    #[serde(default, rename = "_form", skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
}

impl UpstreamLinkFieldErrors {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.handle.is_none() && self.accept_terms.is_none() && self.form.is_none()
    }
}

/// Closed response for the upstream account-link action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UpstreamLinkActionOutcome {
    Success {
        redirect_url: String,
    },
    Error {
        error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field_errors: Option<UpstreamLinkFieldErrors>,
    },
}

/// Current state returned by `GET /_coauth/self/upstream-oauth/link/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "schema", salvo(schema(name = LinkState)))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpstreamLinkState {
    Redirect {
        redirect_url: String,
    },
    SuggestLink {
        provider_name: Option<String>,
        upstream_subject: Option<String>,
    },
    LinkMismatch {
        existing_handle: String,
    },
    Register {
        suggested_handle: Option<String>,
        handle_forced: bool,
        suggested_display_name: Option<String>,
        display_name_forced: bool,
        suggested_email: Option<String>,
        email_forced: bool,
        provider_name: Option<String>,
        has_tos: bool,
    },
    AccountDeactivated {
        handle: String,
    },
    AccountLocked {
        handle: String,
    },
    Error {
        code: String,
        description: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LoginReqBody {
    pub handle: String,
    pub password: String,
    /// Audience the client wants the issued session grant to be bound to.
    /// Must exactly match a configured station audience. When
    /// omitted, the caller is implicitly accepting the deployment's only
    /// configured server name.
    #[serde(default)]
    pub audience: Option<String>,
    /// Solved CAPTCHA token, supplied when the deployment has a CAPTCHA
    /// provider configured.
    #[serde(default)]
    pub captcha_token: Option<String>,
    /// Device the issued station session grant is bound to. Required
    /// when password-login session grants are enabled.
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LoginOutcome {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer: Option<ViewerInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<SessionGrantOneShotInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl LoginOutcome {
    pub fn success(
        viewer: Option<ViewerInfo>,
        session_grant: Option<SessionGrantOneShotInfo>,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            status: "success".to_owned(),
            error: None,
            viewer,
            session_grant,
            warnings,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self {
            status: "error".to_owned(),
            error: Some(error.into()),
            viewer: None,
            session_grant: None,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ViewerInfo {
    pub id: String,
    pub handle: String,
    pub federated_handle: String,
    pub principal_address: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

// ── Combined viewer response ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ViewerOutcome {
    pub viewer: Viewer,
    pub viewer_session: ViewerSession,
    pub site_config: SiteConfigOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
pub enum Viewer {
    User(ViewerUser),
    Anonymous(AnonymousViewer),
}

impl Viewer {
    #[must_use]
    pub const fn as_user(&self) -> Option<&ViewerUser> {
        match self {
            Self::User(user) => Some(user),
            Self::Anonymous(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct AnonymousViewer {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ViewerUser {
    pub id: String,
    pub username: String,
    pub principal_id: String,
    pub handle: String,
    pub can_request_admin: bool,
    pub has_password: bool,
    pub profile: ViewerUserProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emails: Option<EmailConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_accounts: Option<Vec<LinkedAccount>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_sessions: Option<BrowserSessionConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_sessions: Option<AppSessionConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PrincipalUser {
    pub principal_address: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ViewerUserProfile {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub preferred_locale: Option<String>,
    pub updated_at: String,
}

/// Response from `PATCH /_coauth/self/viewer/profile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PatchViewerProfileOutcome {
    pub profile: ViewerUserProfile,
    pub principal: PrincipalUser,
}

/// Response from `GET /_coauth/account/email-auth/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct EmailAuthStatusOutcome {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

/// Response from `GET /_coauth/self/oauth-clients/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "schema", salvo(schema(name = OAuthClientOutcome)))]
pub struct OAuthClientDetail {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub logo_uri: Option<String>,
}

/// Response from `GET /_coauth/self/viewer/security` and the same security
/// projection embedded in the viewer overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "schema", salvo(schema(name = SecuritySummaryData)))]
pub struct SecuritySummaryOutcome {
    pub has_password: bool,
    pub active_sessions_count: usize,
    pub linked_providers_count: usize,
    pub verified_emails_count: usize,
    pub verified_phones_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
pub enum ViewerSession {
    BrowserSession(BrowserSession),
    Anonymous(AnonymousViewer),
}

impl ViewerSession {
    #[must_use]
    pub const fn as_browser_session(&self) -> Option<&BrowserSession> {
        match self {
            Self::BrowserSession(session) => Some(session),
            Self::Anonymous(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct BrowserSession {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<ViewerUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<UserAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_authentication: Option<AuthenticationInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct UserAgent {
    pub name: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub device_type: DeviceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceType {
    Pc,
    Mobile,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct AuthenticationInfo {
    pub id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(tag = "__typename")]
pub enum AppSession {
    OAuthSession(OAuthSession),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct OAuthSession {
    pub id: String,
    pub scope: Option<String>,
    pub client: Option<OAuthClient>,
    pub user_agent: Option<UserAgent>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct OAuthClient {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
pub enum Session {
    BrowserSession(BrowserSession),
    OAuthSession(OAuthSession),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct UserEmail {
    pub id: String,
    pub email: String,
    pub confirmed_at: Option<String>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct EmailConnection {
    pub total_count: i32,
    pub edges: Vec<EmailEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct EmailEdge {
    pub cursor: String,
    pub node: UserEmail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct BrowserSessionConnection {
    pub total_count: i32,
    pub edges: Vec<BrowserSessionEdge>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct BrowserSessionEdge {
    pub cursor: String,
    pub node: BrowserSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct AppSessionConnection {
    pub total_count: i32,
    pub edges: Vec<AppSessionEdge>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct AppSessionEdge {
    pub cursor: String,
    pub node: AppSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct SiteConfigOutcome {
    pub id: Option<String>,
    pub email_change_allowed: bool,
    pub password_login_enabled: bool,
    pub account_deactivation_allowed: bool,
    pub display_name_change_allowed: bool,
    pub password_registration_enabled: bool,
    pub registration_email_delivery_bypass_allowed: bool,
    pub bootstrap_admin_token_enabled: bool,
    pub minimum_password_complexity: u8,
    pub imprint: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub admin_portal_url: Option<String>,
    pub plan_management_iframe_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct BootstrapAdminStatus {
    pub has_admin: bool,
    pub token_configured: bool,
    pub setup_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantKind {
    PrincipalSession,
    PushRegister,
    DevicePairing,
    AdminBridge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantOneShotInfo {
    pub kind: SessionGrantKind,
    pub id: String,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub expires_at: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub station: Option<SessionGrantStationInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantStationInfo {
    pub name: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LogoutOutcome {
    pub status: String,
}

impl LogoutOutcome {
    pub fn success() -> Self {
        Self {
            status: "success".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ProvidersOutcome {
    pub providers: Vec<ProviderInfo>,
    pub password_login_enabled: bool,
    #[serde(default)]
    pub passkey_login_enabled: bool,
    pub password_registration_enabled: bool,
    #[serde(default)]
    pub account_recovery_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_account: Option<CurrentAccountInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct CurrentAccountInfo {
    pub id: String,
    pub username: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ProviderInfo {
    pub id: String,
    #[serde(default)]
    pub human_name: Option<String>,
    #[serde(default)]
    pub brand_name: Option<String>,
    pub authorize_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LinkedAccount {
    pub id: String,
    pub provider_id: String,
    pub provider_name: Option<String>,
    pub provider_brand: Option<String>,
    pub subject: String,
    pub human_account_name: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct LinkedAccountsOutcome {
    pub accounts: Vec<LinkedAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct UnlinkOutcome {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ChannelAvailability {
    pub channel: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ChannelPreference {
    pub channel: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct NotificationPreferencesOutcome {
    pub available_channels: Vec<ChannelAvailability>,
    pub preferences: Vec<ChannelPreference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct UpdateNotificationPreferencesOutcome {
    pub preferences: Vec<ChannelPreference>,
}

/// Start a password registration while durably preserving the authenticated
/// strand that must resume after the account is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct RegisterInput {
    pub handle: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    pub password: String,
    pub password_confirm: String,
    #[serde(default)]
    pub captcha_token: Option<String>,
    #[serde(default)]
    pub post_auth_action: Option<PostAuthAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct RegisterOutcome {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct ChangeRegistrationEmailOutcome {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct RecoveryStatusOutcome {
    pub id: String,
    pub email: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct RecoveryTicketStatusOutcome {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct DeviceLinkOutcome {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PageInfo {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    pub start_cursor: Option<String>,
    pub end_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_login_without_session_grant_decodes() {
        let outcome: LoginOutcome = serde_json::from_value(serde_json::json!({
            "status": "success",
            "viewer": {
                "id": "user:01KVVVKSMNEAFSMKH4HCXD1E7T",
                "handle": "alice",
                "federated_handle": "alice:auth.local.host",
                "principal_address": "alice@auth.local.host",
                "display_name": "alice"
            },
            "session_grant": null,
            "warnings": [
                "password_login_session_grants_disabled; use the OIDC/passkey bridge"
            ]
        }))
        .expect("password login response decodes");

        assert_eq!(outcome.status, "success");
        assert_eq!(
            outcome.viewer.as_ref().expect("viewer").handle.as_str(),
            "alice"
        );
        assert!(outcome.session_grant.is_none());
        assert_eq!(outcome.warnings.len(), 1);
    }

    #[test]
    fn registration_request_preserves_typed_oauth_continuation() {
        let grant_id = Ulid::from_string("01K00000000000000000000000").unwrap();
        let request = RegisterInput {
            handle: "alice".to_owned(),
            email: Some("alice@example.test".to_owned()),
            phone: None,
            password: "correct horse battery staple".to_owned(),
            password_confirm: "correct horse battery staple".to_owned(),
            captcha_token: None,
            post_auth_action: Some(PostAuthAction::ContinueAuthorizationGrant { id: grant_id }),
        };

        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: RegisterInput = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn viewer_user_rejects_a_missing_password_contract_field() {
        let mut value = serde_json::json!({
            "id": "user:01KVVVKSMNEAFSMKH4HCXD1E7T",
            "username": "alice",
            "principal_id": "ak:did_core:webvh:z6mkfixturealice",
            "handle": "alice:auth.example",
            "can_request_admin": false,
            "has_password": true,
            "profile": {
                "display_name": "Alice",
                "avatar_url": null,
                "preferred_locale": "en",
                "updated_at": "2026-09-01T00:00:00.000Z"
            }
        });
        serde_json::from_value::<ViewerUser>(value.clone()).expect("complete viewer user");

        value.as_object_mut().unwrap().remove("has_password");
        assert!(serde_json::from_value::<ViewerUser>(value).is_err());
    }

    #[test]
    fn shared_account_responses_keep_required_fields_strict() {
        let value = serde_json::json!({ "id": "oauth_client:01K", "client_id": "web" });
        serde_json::from_value::<OAuthClientDetail>(value.clone()).expect("complete client");

        let mut missing_client_id = value;
        missing_client_id
            .as_object_mut()
            .unwrap()
            .remove("client_id");
        assert!(serde_json::from_value::<OAuthClientDetail>(missing_client_id).is_err());
    }

    #[test]
    fn upstream_link_account_state_uses_handle() {
        let state = serde_json::json!({ "state": "account_deactivated", "handle": "alice" });
        assert_eq!(
            serde_json::from_value::<UpstreamLinkState>(state).unwrap(),
            UpstreamLinkState::AccountDeactivated {
                handle: "alice".to_owned()
            }
        );
        assert!(
            serde_json::from_value::<UpstreamLinkState>(
                serde_json::json!({ "state": "account_locked", "username": "alice" })
            )
            .is_err()
        );
    }
}
