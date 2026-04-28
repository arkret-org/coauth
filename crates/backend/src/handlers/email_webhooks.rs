use salvo::prelude::*;

use crate::{
    handlers::common::{DepotExt, RouteError, make_clock, make_rng},
    services::email_webhook::{EmailWebhookService, Error as EmailWebhookError},
};

const WEBHOOK_BODY_MAX_SIZE: usize = 256 * 1024;

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, RouteError> {
    let provider = req.param::<String>("provider").unwrap_or_default();
    let body = req
        .payload_with_max_size(WEBHOOK_BODY_MAX_SIZE)
        .await
        .map_err(|error| RouteError::BadRequest(error.to_string()))?
        .clone();
    let service = depot
        .get::<EmailWebhookService>("email_webhook_service")
        .cloned()
        .map_err(|_| RouteError::NotFound)?;

    let mut repo = depot.repo().await?;
    let clock = make_clock();
    let mut rng = make_rng();

    let result = service
        .process(
            &provider,
            req.headers(),
            body.as_ref(),
            &mut repo,
            &mut *rng,
            &*clock,
        )
        .await
        .map_err(map_email_webhook_error)?;

    repo.save().await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "processed": result.processed,
        "ignored": result.ignored,
        "subscription_confirmed": result.subscription_confirmed,
    })))
}

fn map_email_webhook_error(error: EmailWebhookError) -> RouteError {
    match error {
        EmailWebhookError::NotConfigured | EmailWebhookError::ProviderMismatch(_) => {
            RouteError::NotFound
        }
        EmailWebhookError::BadRequest(message) => RouteError::BadRequest(message),
        EmailWebhookError::Unauthorized(_) => RouteError::Unauthorized,
        EmailWebhookError::Internal(error) => RouteError::Internal(error.into()),
    }
}
