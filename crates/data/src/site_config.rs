use std::num::NonZeroU64;

use chrono::Duration;
use serde::Serialize;
use url::Url;

/// Which Captcha service is being used
#[derive(Debug, Clone, Copy)]
pub enum CaptchaService {
    RecaptchaV2,
    CloudflareTurnstile,
    HCaptcha,
}

/// Captcha configuration
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// Which Captcha service is being used
    pub service: CaptchaService,

    /// The site key used by the instance
    pub site_key: String,

    /// The secret key used by the instance
    pub secret_key: String,
}

/// Pasion-original: automatic session expiration configuration
#[derive(Debug, Clone)]
pub struct SessionExpirationConfig {
    pub user_session_inactivity_ttl: Option<Duration>,
    pub oauth_session_inactivity_ttl: Option<Duration>,
}

/// Pasion-original: limits on the number of application sessions per user
#[derive(Serialize, Debug, Clone)]
pub struct SessionLimitConfig {
    pub soft_limit: NonZeroU64,
    pub hard_limit: NonZeroU64,
}

/// Random site configuration we want accessible in various places.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// Time-to-live of access tokens.
    pub access_token_ttl: Duration,

    /// The server name, e.g. "matrix.org".
    pub server_name: String,

    /// The URL to the privacy policy.
    pub policy_uri: Option<Url>,

    /// The URL to the terms of service.
    pub tos_uri: Option<Url>,

    /// Imprint to show in the footer.
    pub imprint: Option<String>,

    /// Whether password login is enabled.
    pub password_login_enabled: bool,

    /// Whether password registration is enabled.
    pub password_registration_enabled: bool,

    /// Pasion-original: whether at least one contact method (email or phone) is
    /// required for password registrations.
    pub password_registration_contact_required: bool,

    /// Pasion-original: whether registration tokens are required for password
    /// registrations.
    pub registration_token_required: bool,

    /// Optional bootstrap token that allows one registration to claim the
    /// first administrator role while no admin users exist.
    pub bootstrap_admin_token: Option<String>,

    /// Whether users can change their email.
    pub email_change_allowed: bool,

    /// Whether users can change their display name.
    pub displayname_change_allowed: bool,

    /// Whether users can change their password.
    pub password_change_allowed: bool,

    /// Whether users can recover their account via email.
    pub account_recovery_allowed: bool,

    /// Pasion-original: whether users can delete their own account.
    pub account_deactivation_allowed: bool,

    /// Captcha configuration
    pub captcha: Option<CaptchaConfig>,

    /// Minimum password complexity, between 0 and 4.
    /// This is a score from zxcvbn.
    pub minimum_password_complexity: u8,

    /// Pasion-original: automatic session expiration
    pub session_expiration: Option<SessionExpirationConfig>,

    /// Pasion-original: whether users can log in with their email address.
    pub login_with_email_allowed: bool,

    /// URL of the external admin portal shown to eligible users.
    pub admin_portal_url: Option<Url>,

    /// Pasion-original: the iframe URL to show in the plan tab of the UI
    pub plan_management_iframe_uri: Option<String>,

    /// Pasion-original: limits on the number of application sessions that each
    /// user can have
    pub session_limit: Option<SessionLimitConfig>,

    /// Pasion-original: when true, registration/recovery/password-change use
    /// the flow engine instead of the legacy service modules.
    pub flow_engine_enabled: bool,

    /// Whether phone number verification is available (i.e. a real SMS
    /// transport is configured).  When `false`, phone fields submitted during
    /// registration are silently ignored so that the flow does not get stuck
    /// on a verification step that can never complete.
    pub phone_verification_enabled: bool,
}
