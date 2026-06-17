use coauth_data::NewUserPrimaryHandlePreference;
use salvo::prelude::*;

use super::*;
use crate::handlers::cokret::*;

/// `PATCH /_coauth/root/identity/primary-handle` — self-service holder
/// preference for DID `metadata.primary_handle`.
///
/// Body shape: `{ "primary_handle": "alice:example.com" }` to set, or
/// `{ "primary_handle": null }` to clear. Setting requires a current
/// `claim_issued` handle-audit event for the same holder and handle.
#[handler]
pub async fn patch_primary_handle_preference(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PrimaryHandlePreferenceOutcome>, CokretRouteError> {
    let body: PatchPrimaryHandlePreferenceRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let requested = body
        .primary_handle
        .ok_or_else(|| CokretRouteError::BadRequest("missing primary_handle".to_owned()))?;

    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);
    let session_info = crate::handlers::account::extract_session_info(req, depot);
    let repo = depot.repo().await?;
    let (requester, mut repo) =
        crate::handlers::account::get_requester(&clock, &activity_tracker, repo, &session_info)
            .await?;

    let user = requester
        .entity
        .browser_session()
        .map(|session| session.user.clone())
        .ok_or_else(|| CokretRouteError::Unauthorized("browser session required".to_owned()))?;

    let claim = if let Some(handle) = requested.as_deref() {
        require_canonical_handle(handle)?;
        Some(
            repo.user_primary_handle_preference()
                .verified_handle_claim(user.id, handle, clock.now())
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    CokretRouteError::BadRequest(
                        "primary_handle_not_verified_for_holder".to_owned(),
                    )
                })?,
        )
    } else {
        None
    };

    let preference = repo
        .user_primary_handle_preference()
        .set(
            &mut rng,
            &*clock,
            NewUserPrimaryHandlePreference::self_service(
                user.id,
                requested.clone(),
                claim.as_ref(),
                user.id,
            ),
        )
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(PrimaryHandlePreferenceOutcome {
        primary_handle: preference.handle,
        effective_at: preference.effective_at,
        source_claim_id: preference.source_claim_id.map(|id| id.to_string()),
        source_claim_digest: preference.source_claim_digest,
    }))
}
