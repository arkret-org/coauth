//! Admin endpoints for managing CXP-0007 `cx.circle.*` capability grants.
//!
//! Surfaces three routes consumed by sodmin and any other admin client:
//!
//! - `GET    /api/admin/v1/circles/capabilities` — list grants
//! - `POST   /api/admin/v1/circles/capabilities` — create a grant
//! - `DELETE /api/admin/v1/circles/capabilities/{id}` — revoke a grant
//!
//! Wire shape lives in
//! [`coauth_admin_types::circle_capability_admin`].
//!
//! TODO(circle-rollout-followup-A.2): the in-process `Mutex<Vec<…>>`
//! store below is functionally complete for sodmin integration but is
//! still in-memory. Migrating to a `coauth-data` repository pattern
//! requires a fresh diesel migration that adds a
//! `circle_capability_grants` table (and a matching repository trait /
//! Postgres implementation) so the grants survive coauth-backend
//! restarts. coauth uses diesel + diesel-async (not sqlx) — the original
//! P2B.2 marker mentioning a "sqlx migration" was inaccurate. Tracked
//! out-of-band because the additional ~400 LoC of repo plumbing did not
//! fit inside the circle-rollout P1 closeout window.

use std::sync::{LazyLock, Mutex};

use chrono::Utc;
use coauth_admin_types::circle_capability_admin::{
    CircleCapabilityGrant, CreateCircleCapabilityGrant, ListCircleCapabilityGrantsResponse,
    RiskTier,
};
use salvo::{http::StatusCode, oapi::extract::PathParam, prelude::*};
use ulid::Ulid;

use crate::{
    JsonResult,
    error::AppError,
    handlers::{admin::call_context::extract_call_context, common::DepotExt},
};

/// In-memory grant store. See module TODO.
static GRANTS: LazyLock<Mutex<Vec<CircleCapabilityGrant>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCircleCapabilityGrantsResponse> {
    let call_context = extract_call_context(req, depot).await?;
    call_context.repo.cancel().await?; // read-only

    let data = GRANTS
        .lock()
        .expect("circle capability grant mutex poisoned")
        .iter()
        .filter(|g| g.revoked_at.is_none())
        .cloned()
        .collect();

    Ok(Json(ListCircleCapabilityGrantsResponse { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.create", skip_all)]
pub async fn create_handler(req: &mut Request, depot: &Depot) -> JsonResult<CircleCapabilityGrant> {
    let call_context = extract_call_context(req, depot).await?;

    let body: CreateCircleCapabilityGrant = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid grant body: {e}")))?;

    if let Err(msg) = body.validate() {
        return Err(AppError::bad_request(msg));
    }

    // CXP-0007 P2B.5: High-risk Circle capability grants
    // (cx.circle.member.add.others, cx.circle.audit) MUST be preceded by
    // an N-of-M approved RiskActionProposal. The propose / approve
    // workflow lives in `admin/v1/accounts/risk_action.rs` and persists
    // each approval as an `ApprovalProof` row inside the proposal's
    // `approval_proofs` JSONB column. We bind the proposal id via the
    // `risk_action_proposal_id` query parameter or
    // `x-coauth-risk-action-proposal-id` header. The proposal is marked
    // `executed` after the grant is persisted so it cannot be replayed.
    let tier = body.action.risk_tier();
    let approved_proposal = if tier == RiskTier::High {
        let proposal_id_raw = req
            .query::<String>("risk_action_proposal_id")
            .or_else(|| req.header::<String>("x-coauth-risk-action-proposal-id"))
            .ok_or_else(|| {
                AppError::bad_request(
                    "high-risk Circle capability grants require an approved \
                     risk_action_proposal_id (query parameter or \
                     x-coauth-risk-action-proposal-id header)",
                )
            })?;
        let proposal_ulid = Ulid::from_string(proposal_id_raw.trim())
            .map_err(|err| AppError::bad_request(format!("invalid proposal_id: {err}")))?;
        let proposals = depot.risk_action_proposals_service()?;
        let existing = proposals
            .get(proposal_ulid)
            .await
            .map_err(|err| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("risk_action lookup: {err}"),
                )
            })?
            .ok_or_else(|| AppError::not_found("risk_action proposal not found"))?;
        if existing.state != crate::services::risk_action_proposals::ProposalState::Approved {
            return Err(AppError::bad_request(format!(
                "risk_action proposal state {:?} is not 'approved'; need at \
                 least {} signed admin approvals before issuing this \
                 high-risk Circle capability grant",
                existing.state.as_str(),
                existing.required_approvals
            )));
        }
        Some((proposal_ulid, existing.approval_proofs.len()))
    } else {
        None
    };

    let actor_did = call_context
        .user
        .as_ref()
        .map_or_else(|| "service".to_owned(), |u| format!("user:{}", u.id));

    let grant = CircleCapabilityGrant {
        id: Ulid::new().to_string(),
        subject: body.subject,
        realm_id: body.realm_id,
        action: body.action,
        allowed_circle_refs: body.allowed_circle_refs,
        granted_by: actor_did,
        granted_at: Utc::now().to_rfc3339(),
        revoked_at: None,
    };

    GRANTS
        .lock()
        .expect("circle capability grant mutex poisoned")
        .push(grant.clone());

    // Mark the proposal `executed` so the approval set can't be replayed
    // for a second grant.
    if let Some((proposal_ulid, _approval_count)) = approved_proposal {
        let proposals = depot.risk_action_proposals_service()?;
        let _ = proposals
            .mark_executed(proposal_ulid, Utc::now())
            .await
            .map_err(|err| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("risk_action mark_executed: {err}"),
                )
            })?;
    }

    call_context.repo.cancel().await?; // no DB writes for in-memory grant store

    Ok(Json(grant))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.revoke", skip_all)]
pub async fn revoke_handler(
    req: &mut Request,
    depot: &Depot,
    grant_id: PathParam<String>,
) -> Result<StatusCode, AppError> {
    let call_context = extract_call_context(req, depot).await?;
    let grant_id = grant_id.into_inner();

    let revoked = {
        let mut grants = GRANTS
            .lock()
            .expect("circle capability grant mutex poisoned");
        match grants.iter_mut().find(|g| g.id == grant_id) {
            Some(g) if g.revoked_at.is_none() => {
                g.revoked_at = Some(Utc::now().to_rfc3339());
                Ok(StatusCode::NO_CONTENT)
            }
            Some(_) => Err(AppError::new(
                StatusCode::NOT_FOUND,
                "grant already revoked",
            )),
            None => Err(AppError::new(StatusCode::NOT_FOUND, "grant not found")),
        }
    };

    let _ = call_context.repo.cancel().await;
    revoked
}

/// Test-only: clear the in-memory grant store between tests.
#[cfg(test)]
pub fn _reset_for_tests() {
    GRANTS
        .lock()
        .expect("circle capability grant mutex poisoned")
        .clear();
}

#[cfg(test)]
mod tests {
    use coauth_admin_types::circle_capability_admin::CircleCapabilityAction;

    use super::*;

    #[test]
    fn create_then_revoke_lifecycle() {
        _reset_for_tests();

        // Simulate what the handler bodies do, sans HTTP plumbing.
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "cx:realm:demo".into(),
            action: CircleCapabilityAction::Create,
            allowed_circle_refs: vec![],
        };
        assert!(req.validate().is_ok());

        let grant = CircleCapabilityGrant {
            id: Ulid::new().to_string(),
            subject: req.subject,
            realm_id: req.realm_id,
            action: req.action,
            allowed_circle_refs: req.allowed_circle_refs,
            granted_by: "service".into(),
            granted_at: Utc::now().to_rfc3339(),
            revoked_at: None,
        };
        GRANTS.lock().unwrap().push(grant.clone());

        // List should contain it.
        let listed: Vec<_> = GRANTS
            .lock()
            .unwrap()
            .iter()
            .filter(|g| g.revoked_at.is_none())
            .cloned()
            .collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, grant.id);

        // Revoke.
        for g in GRANTS.lock().unwrap().iter_mut() {
            if g.id == grant.id {
                g.revoked_at = Some(Utc::now().to_rfc3339());
            }
        }

        let listed_after: Vec<_> = GRANTS
            .lock()
            .unwrap()
            .iter()
            .filter(|g| g.revoked_at.is_none())
            .cloned()
            .collect();
        assert!(listed_after.is_empty());

        _reset_for_tests();
    }
}
