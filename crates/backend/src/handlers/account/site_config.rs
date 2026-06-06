use coauth_data::SiteConfig;
use salvo::{oapi::ToSchema, prelude::*};
use serde::Serialize;

use super::{DepotExt, RouteError};

#[derive(Serialize, ToSchema)]
pub struct SiteConfigResponse {
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

/// Build a [`SiteConfigResponse`] from the domain [`SiteConfig`].
#[must_use]
pub fn from_site_config(config: &SiteConfig) -> SiteConfigResponse {
    SiteConfigResponse {
        id: Some("site_config".to_owned()),
        email_change_allowed: config.email_change_allowed,
        password_login_enabled: config.password_login_enabled,
        account_deactivation_allowed: config.account_deactivation_allowed,
        display_name_change_allowed: config.displayname_change_allowed,
        password_registration_enabled: config.password_registration_enabled,
        registration_email_delivery_bypass_allowed: config
            .registration_email_delivery_bypass_allowed,
        bootstrap_admin_token_enabled: config.bootstrap_admin_token.is_some(),
        minimum_password_complexity: config.minimum_password_complexity,
        imprint: config.imprint.clone(),
        tos_uri: config
            .tos_uri
            .as_ref()
            .map(std::string::ToString::to_string),
        policy_uri: config
            .policy_uri
            .as_ref()
            .map(std::string::ToString::to_string),
        admin_portal_url: config
            .admin_portal_url
            .as_ref()
            .map(std::string::ToString::to_string),
        plan_management_iframe_uri: config.plan_management_iframe_uri.clone(),
    }
}

/// GET /_coauth/self/site-config
#[endpoint]
pub async fn get(depot: &Depot) -> Result<Json<SiteConfigResponse>, RouteError> {
    let config = depot.site_config()?;

    Ok(Json(from_site_config(&config)))
}

#[cfg(test)]
mod tests {
    use super::from_site_config;
    use crate::handlers::test_utils::test_site_config;

    #[test]
    fn includes_admin_portal_url() {
        let mut config = test_site_config();
        config.admin_portal_url = Some("https://admin.example.com/".parse().unwrap());

        let response = from_site_config(&config);

        assert_eq!(
            response.admin_portal_url.as_deref(),
            Some("https://admin.example.com/")
        );
    }
}
