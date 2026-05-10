//! Admin endpoint for checking notification channel status.
//!
//! Returns a list of configured notification channels and their status.
//! Since the [`NotificationCenter`] is not available in the HTTP depot,
//! channel availability is inferred from the site configuration flags.
//!
//! Wire shape lives in `coauth-admin-types::notification_admin` so sodmin
//! and any other admin client deserialize against the same typed
//! definition rustc enforces here.

use coauth_admin_types::{NotificationChannelStatus, NotificationChannelsResponse};
use salvo::prelude::*;

use crate::{
    JsonResult,
    handlers::{admin::call_context::extract_call_context, common::DepotExt},
};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.notification_channels", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> JsonResult<NotificationChannelsResponse> {
    let _call_context = extract_call_context(req, depot).await?;
    let site_config = depot.site_config()?;

    // Email is considered configured when account recovery (which requires
    // sending emails) is enabled or when email changes are allowed.
    let email_configured = site_config.account_recovery_allowed || site_config.email_change_allowed;

    // SMS availability cannot be directly determined from the site config;
    // contact-required registration is the closest signal (it implies at
    // least one of email or SMS is expected to be available).
    let sms_configured = site_config.password_registration_contact_required && !email_configured;

    let channels = vec![
        NotificationChannelStatus {
            channel: "email".to_string(),
            configured: email_configured,
        },
        NotificationChannelStatus {
            channel: "sms".to_string(),
            configured: sms_configured,
        },
    ];

    Ok(Json(NotificationChannelsResponse { channels }))
}
