//! REST API endpoints for managing linked upstream OAuth accounts.
//!
//! These endpoints allow authenticated users to view and unlink their
//! connected external accounts (GitHub, Google, etc.).

use coauth_account_types::{LinkedAccount, LinkedAccountsOutcome, UnlinkOutcome};
use salvo::prelude::*;
use ulid::Ulid;

use super::{RouteError, make_clock};
use crate::handlers::account::service::connections::{
    LinkedAccountError, list_linked_accounts as list_linked_accounts_service, unlink_linked_account,
};

// ── GET /_coauth/self/linked-accounts ─────────────────────────────────

/// Returns the list of upstream OAuth providers linked to the current user.
#[endpoint]
pub async fn list_linked_accounts(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<LinkedAccountsOutcome>, RouteError> {
    let clock = make_clock();
    let (requester, repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

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
            created_at: arkret_canonical::format_timestamp_canonical(link.created_at),
        })
        .collect();

    Ok(Json(LinkedAccountsOutcome { accounts }))
}

// ── DELETE /_coauth/self/linked-accounts/{id} ─────────────────────────

/// Unlink an upstream OAuth provider from the current user.
#[endpoint]
pub async fn unlink_account(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<UnlinkOutcome>, RouteError> {
    let clock = make_clock();
    let (requester, repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    unlink_linked_account(repo, &requester, &clock, id)
        .await
        .map_err(map_linked_account_error)?;

    Ok(Json(UnlinkOutcome {
        status: "unlinked".to_owned(),
    }))
}

fn map_linked_account_error(error: LinkedAccountError) -> RouteError {
    match error {
        LinkedAccountError::NotFound => RouteError::NotFound,
        LinkedAccountError::Unauthorized => RouteError::Unauthorized,
        LinkedAccountError::Repository(error) => RouteError::from(error),
    }
}
