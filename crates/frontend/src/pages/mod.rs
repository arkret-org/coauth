pub mod account;
pub mod account_overview;
pub mod account_settings;
pub mod browser_sessions;
pub mod client_detail;
pub mod consent;
pub mod device_consent;
pub mod device_link;
pub mod device_redirect;
pub mod email_in_use;
pub mod email_verify;
pub mod error_pages;
pub mod identity_bindings;
pub mod login;
pub mod notification_preferences;
pub mod password_change;
pub mod password_change_success;
pub mod password_recovery;
pub mod plan;
pub mod recovery_progress;
pub mod recovery_start;
pub mod register;
pub mod reset_cross_signing;
pub mod security_center;
pub mod session_detail;
pub mod sessions;
pub mod upstream_link;
pub mod workflow_inbox;

// Re-export page components for the router
use account_overview::AccountOverview;
use account_settings::AccountSettings;
use browser_sessions::BrowserSessions;
use client_detail::ClientDetail;
use consent::Consent;
use device_consent::DeviceConsent;
use device_link::DeviceLink;
use device_redirect::DeviceRedirect;
use dioxus::prelude::*;
use email_in_use::EmailInUse;
use email_verify::EmailVerify;
use identity_bindings::IdentityBindings;
use login::Login;
use notification_preferences::NotificationPreferences;
use password_change::PasswordChange;
use password_change_success::PasswordChangeSuccess;
use password_recovery::PasswordRecovery;
use plan::Plan;
use recovery_progress::RecoveryProgress;
use recovery_start::RecoveryStart;
use register::{
    Register, RegisterDisplayName, RegisterFinish, RegisterVerifyEmail, RegisterVerifyPhone,
};
use reset_cross_signing::ResetCrossSigning;
use security_center::SecurityCenter;
use session_detail::SessionDetail;
use sessions::Sessions;
use upstream_link::UpstreamLink;
use workflow_inbox::WorkflowInbox;

use crate::components::{error::NotFound, layout::Layout};

/// Application route definition.
#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    // Auth pages (public)
    #[route("/login")]
    Login {},
    #[route("/register")]
    Register {},
    #[route("/register/steps/:id/verify-email")]
    RegisterVerifyEmail { id: String },
    #[route("/register/steps/:id/verify-phone")]
    RegisterVerifyPhone { id: String },
    #[route("/register/steps/:id/display-name")]
    RegisterDisplayName { id: String },
    #[route("/register/steps/:id/finish")]
    RegisterFinish { id: String },
    #[route("/recover")]
    RecoveryStart {},
    #[route("/recover/progress/:id")]
    RecoveryProgress { id: String },

    // OAuth2 consent & device code (public, require session)
    #[route("/consent/:grant_id")]
    Consent { grant_id: String },
    #[route("/link")]
    DeviceLink {},
    #[route("/device/:id")]
    DeviceConsent { id: String },

    // Account layout with nested routes (authenticated)
    #[layout(AccountLayout)]
        #[route("/")]
        AccountOverview {},
        #[route("/settings")]
        AccountSettings {},
        #[route("/sessions")]
        Sessions {},
        #[route("/sessions/browsers")]
        BrowserSessions {},
        #[route("/plan")]
        Plan {},
        #[route("/security")]
        SecurityCenter {},
        #[route("/notifications")]
        NotificationPreferences {},
        #[route("/identities")]
        IdentityBindings {},
        #[route("/workflows")]
        WorkflowInbox {},
    #[end_layout]

    // Standalone pages
    #[route("/password/change")]
    PasswordChange {},
    #[route("/password/change/success")]
    PasswordChangeSuccess {},
    #[route("/password/recovery")]
    PasswordRecovery {},
    #[route("/emails/:id/verify")]
    EmailVerify { id: String },
    #[route("/emails/:id/in-use")]
    EmailInUse { id: String },
    #[route("/sessions/:id")]
    SessionDetail { id: String },
    #[route("/reset-cross-signing")]
    ResetCrossSigning {},
    #[route("/clients/:id")]
    ClientDetail { id: String },
    #[route("/devices/:..route")]
    DeviceRedirect { route: Vec<String> },

    // Upstream OAuth2 link
    #[route("/upstream/link/:id")]
    UpstreamLink { id: String },

    // Catch-all 404
    #[route("/:..route")]
    PageNotFound { route: Vec<String> },
}

/// Account layout wrapping the account-related pages (settings, sessions,
/// plan).
#[component]
fn AccountLayout() -> Element {
    rsx! {
        account::AccountPage {}
    }
}

/// 404 page component.
#[component]
fn PageNotFound(route: Vec<String>) -> Element {
    rsx! {
        Layout {
            NotFound {}
        }
    }
}
