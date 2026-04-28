use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ConfigurationSection;

// --- Boolean default helpers (const-fn based) ---

const ENABLED_BY_DEFAULT: bool = true;
const DISABLED_BY_DEFAULT: bool = false;

const fn enabled_default() -> bool {
    ENABLED_BY_DEFAULT
}

const fn disabled_default() -> bool {
    DISABLED_BY_DEFAULT
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn matches_enabled(val: &bool) -> bool {
    *val == ENABLED_BY_DEFAULT
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn matches_disabled(val: &bool) -> bool {
    *val == DISABLED_BY_DEFAULT
}

/// Knobs for user-facing account management features
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct AccountConfig {
    /// Whether users can update their own email address (default: `true`)
    #[serde(default = "enabled_default", skip_serializing_if = "matches_enabled")]
    pub email_change_allowed: bool,

    /// Whether users can update their display name (default: `true`).
    /// Keep in sync with the homeserver policy.
    #[serde(default = "enabled_default", skip_serializing_if = "matches_enabled")]
    pub displayname_change_allowed: bool,

    /// Enable self-service password-based registration (default: `false`).
    /// Ignored when password login is disabled entirely.
    #[serde(default = "disabled_default", skip_serializing_if = "matches_disabled")]
    pub password_registration_enabled: bool,

    /// Require at least one verified contact method for password-based
    /// registrations (default: `true`). Has no effect when registration is off.
    #[serde(
        default = "enabled_default",
        skip_serializing_if = "matches_enabled",
        alias = "password_registration_email_required"
    )]
    pub password_registration_contact_required: bool,

    /// Allow users to change their password (default: `true`). Irrelevant when
    /// password login is disabled.
    #[serde(default = "enabled_default", skip_serializing_if = "matches_enabled")]
    pub password_change_allowed: bool,

    /// Permit email-based password recovery (default: `false`). Irrelevant when
    /// password login is disabled.
    #[serde(default = "disabled_default", skip_serializing_if = "matches_disabled")]
    pub password_recovery_enabled: bool,

    /// Allow users to deactivate (delete) their own account (default: `true`)
    #[serde(default = "enabled_default", skip_serializing_if = "matches_enabled")]
    pub account_deactivation_allowed: bool,

    /// Permit logging in via email address rather than username
    /// (default: `false`). Irrelevant when password login is disabled.
    #[serde(default = "disabled_default", skip_serializing_if = "matches_disabled")]
    pub login_with_email_allowed: bool,

    /// Optional URL of the external admin portal.
    ///
    /// When set, users with administrative access will see a link to the
    /// portal in the account UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_portal_url: Option<Url>,

    /// Require a registration token for new password-based accounts
    /// (default: `false`). Has no effect when registration is off.
    #[serde(default = "disabled_default", skip_serializing_if = "matches_disabled")]
    pub registration_token_required: bool,

    /// Optional bootstrap token that allows one registration to claim the
    /// first administrator role while no admin users exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_admin_token: Option<String>,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            email_change_allowed: ENABLED_BY_DEFAULT,
            displayname_change_allowed: ENABLED_BY_DEFAULT,
            password_registration_enabled: DISABLED_BY_DEFAULT,
            password_registration_contact_required: ENABLED_BY_DEFAULT,
            password_change_allowed: ENABLED_BY_DEFAULT,
            password_recovery_enabled: DISABLED_BY_DEFAULT,
            account_deactivation_allowed: ENABLED_BY_DEFAULT,
            login_with_email_allowed: DISABLED_BY_DEFAULT,
            admin_portal_url: None,
            registration_token_required: DISABLED_BY_DEFAULT,
            bootstrap_admin_token: None,
        }
    }
}

impl AccountConfig {
    /// Returns `true` when every field matches its default value
    pub(crate) fn is_default(&self) -> bool {
        matches_disabled(&self.password_registration_enabled)
            && matches_enabled(&self.email_change_allowed)
            && matches_enabled(&self.displayname_change_allowed)
            && matches_enabled(&self.password_change_allowed)
            && matches_disabled(&self.password_recovery_enabled)
            && matches_enabled(&self.account_deactivation_allowed)
            && matches_disabled(&self.login_with_email_allowed)
            && self.admin_portal_url.is_none()
            && matches_disabled(&self.registration_token_required)
            && self.bootstrap_admin_token.is_none()
    }
}

impl ConfigurationSection for AccountConfig {
    const PATH: &'static str = "account";
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment,
        providers::{Env, Format, Yaml},
    };
    use url::Url;

    use super::AccountConfig;

    #[test]
    fn loads_bootstrap_admin_token_from_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PASION_ACCOUNT__BOOTSTRAP_ADMIN_TOKEN", "bootstrap-secret");

            let figment = Figment::new()
                .merge(Env::prefixed("PASION_").split("__"))
                .merge(Yaml::string(""));

            let config = figment.extract_inner::<AccountConfig>("account")?;

            assert_eq!(
                config.bootstrap_admin_token.as_deref(),
                Some("bootstrap-secret")
            );

            Ok(())
        });
    }

    #[test]
    fn loads_admin_portal_url_from_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env(
                "PASION_ACCOUNT__ADMIN_PORTAL_URL",
                "https://admin.example.com/",
            );

            let figment = Figment::new()
                .merge(Env::prefixed("PASION_").split("__"))
                .merge(Yaml::string(""));

            let config = figment.extract_inner::<AccountConfig>("account")?;

            assert_eq!(
                config.admin_portal_url.as_ref().map(Url::as_str),
                Some("https://admin.example.com/")
            );

            Ok(())
        });
    }
}
