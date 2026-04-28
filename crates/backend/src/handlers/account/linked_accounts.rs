//! REST API endpoints for managing linked upstream OAuth accounts.
//!
//! These endpoints allow authenticated users to view and unlink their
//! connected external accounts (GitHub, Google, etc.).

use salvo::{oapi::ToSchema, prelude::*};
use serde::Serialize;
use ulid::Ulid;

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock,
};
use crate::handlers::account::service::connections::{
    LinkedAccountError, list_linked_accounts as list_linked_accounts_service, unlink_linked_account,
};

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct LinkedAccountsResponse {
    pub accounts: Vec<LinkedAccount>,
}

#[derive(Serialize, ToSchema)]
pub struct LinkedAccount {
    pub id: String,
    pub provider_id: String,
    pub provider_name: Option<String>,
    pub provider_brand: Option<String>,
    pub subject: String,
    pub human_account_name: Option<String>,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct UnlinkResponse {
    pub status: &'static str,
}

// ── GET /api/v1/linked-accounts ─────────────────────────────────

/// Returns the list of upstream OAuth providers linked to the current user.
#[endpoint]
pub async fn list_linked_accounts(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<LinkedAccountsResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let accounts: Vec<LinkedAccount> = list_linked_accounts_service(repo, &requester, 100)
        .await
        .map_err(map_linked_account_error)?
        .into_iter()
        .map(|link| LinkedAccount {
            id: link.id.to_string(),
            provider_id: link.provider_id.to_string(),
            provider_name: link.provider_name,
            provider_brand: link.provider_brand,
            subject: link.subject,
            human_account_name: link.human_account_name,
            created_at: link.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(LinkedAccountsResponse { accounts }))
}

// ── DELETE /api/v1/linked-accounts/{id} ─────────────────────────

/// Unlink an upstream OAuth provider from the current user.
#[endpoint]
pub async fn unlink_account(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<UnlinkResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    unlink_linked_account(repo, &requester, &clock, id)
        .await
        .map_err(map_linked_account_error)?;

    Ok(Json(UnlinkResponse { status: "unlinked" }))
}

fn map_linked_account_error(error: LinkedAccountError) -> RouteError {
    match error {
        LinkedAccountError::NotFound => RouteError::NotFound,
        LinkedAccountError::Unauthorized => RouteError::Unauthorized,
        LinkedAccountError::Repository(error) => RouteError::from(error),
    }
}
