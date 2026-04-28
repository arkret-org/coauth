// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    handlers::{account::DepotExt, admin::call_context::extract_call_context},
    salvo_utils::InternalError,
};

/// Response payload describing the current site-level settings.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct SiteConfig {
    /// Matrix homeserver name that this deployment serves
    server_name: String,

    /// Whether authenticating with a password is allowed
    pub password_login_enabled: bool,

    /// Whether new accounts can be created with a password
    pub password_registration_enabled: bool,

    /// Whether a contact method (email/phone) must be provided during
    /// password-based sign-up
    pub password_registration_contact_required: bool,

    /// Whether a registration token is mandatory for sign-up
    pub registration_token_required: bool,

    /// Whether a bootstrap admin token is configured
    pub bootstrap_admin_token_enabled: bool,

    /// Whether users may update their email address
    pub email_change_allowed: bool,

    /// Whether users may update their display name
    pub displayname_change_allowed: bool,

    /// Whether users may update their password
    pub password_change_allowed: bool,

    /// Whether account recovery via email is permitted
    pub account_recovery_allowed: bool,

    /// Whether users may self-deactivate their account
    pub account_deactivation_allowed: bool,

    /// URL of the external admin portal shown to eligible users
    pub admin_portal_url: Option<String>,

    /// Whether CAPTCHA verification is active during registration
    pub captcha_enabled: bool,

    /// Required minimum password strength (0-4, per zxcvbn scoring)
    #[schemars(range(min = 0, max = 4))]
    pub minimum_password_complexity: u8,
}

/// Retrieve the current site configuration.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.site_config", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> Result<Json<SiteConfig>, InternalError> {
    let _ctx = extract_call_context(req, depot).await?;
    let cfg = depot.site_config()?;

    let resp = SiteConfig {
        server_name: cfg.server_name,
        password_login_enabled: cfg.password_login_enabled,
        password_registration_enabled: cfg.password_registration_enabled,
        password_registration_contact_required: cfg.password_registration_contact_required,
        registration_token_required: cfg.registration_token_required,
        bootstrap_admin_token_enabled: cfg.bootstrap_admin_token.is_some(),
        email_change_allowed: cfg.email_change_allowed,
        displayname_change_allowed: cfg.displayname_change_allowed,
        password_change_allowed: cfg.password_change_allowed,
        account_recovery_allowed: cfg.account_recovery_allowed,
        account_deactivation_allowed: cfg.account_deactivation_allowed,
        admin_portal_url: cfg.admin_portal_url.as_ref().map(|url| url.to_string()),
        captcha_enabled: cfg.captcha.is_some(),
        minimum_password_complexity: cfg.minimum_password_complexity,
    };

    Ok(Json(resp))
}
