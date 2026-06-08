//! Admin endpoints for notification template management.
//!
//! - `GET  /_coauth/admin/notification-templates` — list known template keys
//! - `POST /_coauth/admin/notification-templates/publish` — publish a new
//!   template version
//!
//! Wire shapes (request + response bodies) live in
//! `coauth-admin-types::notification_admin` so sodmin and any other
//! admin client deserialize against the same typed definition rustc
//! enforces here.

use coauth_admin_types::{
    NotificationTemplateEntry, NotificationTemplatesOutcome, PublishTemplateRequestBody,
    PublishedTemplateOutcome,
};
use coauth_data::RepositoryAccess;
use salvo::prelude::*;

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::admin::{CreatedJson, call_context::extract_call_context},
};

/// List all known notification template keys.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<NotificationTemplatesOutcome> {
    let _call_context = extract_call_context(req, depot).await?;

    let templates = vec![
        NotificationTemplateEntry {
            key: "verification".to_owned(),
            description: "Email or phone verification code".to_owned(),
        },
        NotificationTemplateEntry {
            key: "recovery".to_owned(),
            description: "Account recovery / password reset".to_owned(),
        },
        NotificationTemplateEntry {
            key: "enrollment_invitation".to_owned(),
            description: "Enrollment invitation for batch-invited users".to_owned(),
        },
        NotificationTemplateEntry {
            key: "password_reset".to_owned(),
            description: "Password reset notification".to_owned(),
        },
    ];

    Ok(Json(NotificationTemplatesOutcome { templates }))
}

/// Publish a new notification template version.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.publish", skip_all)]
pub async fn publish_handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<PublishedTemplateOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;

    let body: PublishTemplateRequestBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("Invalid request body: {e}")))?;

    body.validate().map_err(AppError::bad_request)?;

    let mut rng = crate::handlers::account::make_rng();

    let record = repo
        .notification_template()
        .publish(
            &mut rng,
            &*clock,
            body.template_key,
            body.channel,
            body.locale,
            body.subject_template,
            body.body_template,
        )
        .await?;

    repo.save().await?;

    let channel_str = format!("{:?}", record.channel).to_lowercase();

    let response = PublishedTemplateOutcome {
        id: record.id.to_string(),
        template_key: record.template_key,
        version: record.version,
        channel: channel_str,
        locale: "en".to_owned(),
        subject_template: record.subject_template,
        body_template: record.body_template,
        created_at: record.created_at,
        published_at: record.published_at,
    };

    Ok(CreatedJson(response))
}
