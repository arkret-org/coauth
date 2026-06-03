//! Admin endpoints for managing CXP-0007 `ck.circle.*` capability grants.
//!
//! Surfaces three routes consumed by sodmin and any other admin client:
//!
//! - `GET    /_cokret/local/admin/circles/capabilities` — list grants
//! - `POST   /_cokret/local/admin/circles/capabilities` — create a grant
//! - `DELETE /_cokret/local/admin/circles/capabilities/{id}` — revoke a grant
//!
//! Wire shape lives in
//! [`coauth_admin_types::circle_capability_admin`]. Grants are durable:
//! the handlers below use `circle_capability_grants` through the normal
//! repository transaction boundary, so they survive restarts and are
//! visible across horizontally scaled replicas that share Postgres.

use coauth_admin_types::circle_capability_admin::{
    CircleCapabilityGrant, CreateCircleCapabilityGrant, ListCircleCapabilityGrantsResponse,
    RiskTier,
};
use coauth_data::{NewCircleCapabilityGrant, RepositoryAccess};
use salvo::{http::StatusCode, oapi::extract::PathParam, prelude::*};
use ulid::Ulid;

use crate::{
    JsonResult,
    error::AppError,
    handlers::{
        admin::call_context::extract_call_context,
        common::{DepotExt, make_clock, make_rng},
    },
};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCircleCapabilityGrantsResponse> {
    let mut repo = extract_call_context(req, depot).await?.repo;
    let data = repo.circle_capability_grant().list_active().await?;
    repo.cancel().await?;

    Ok(Json(ListCircleCapabilityGrantsResponse { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.create", skip_all)]
pub async fn create_handler(req: &mut Request, depot: &Depot) -> JsonResult<CircleCapabilityGrant> {
    let call_context = extract_call_context(req, depot).await?;

    let mut body: CreateCircleCapabilityGrant = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid grant body: {e}")))?;

    if let Err(msg) = body.validate() {
        return Err(AppError::bad_request(msg));
    }

    // CXP-0007 P2B.5: High-risk Circle capability grants
    // (ck.circle.member.add.others, ck.circle.audit) MUST be preceded by
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
        Some(proposal_ulid)
    } else {
        None
    };

    let actor_id = call_context
        .user
        .as_ref()
        .map_or_else(|| "service".to_owned(), |u| format!("user:{}", u.id));

    canonicalize_circle_ids(&mut body.allowed_circle_ids);
    let mut rng = make_rng();
    let mut repo = call_context.repo;
    let grant = repo
        .circle_capability_grant()
        .add(
            &mut *rng,
            &*call_context.clock,
            NewCircleCapabilityGrant {
                subject: body.subject,
                realm_id: body.realm_id,
                action: body.action,
                allowed_circle_ids: body.allowed_circle_ids,
                granted_by: actor_id,
            },
        )
        .await?;

    if let Some(proposal_ulid) = approved_proposal {
        let proposals = depot.risk_action_proposals_service()?;
        proposals
            .mark_executed(proposal_ulid, chrono::Utc::now())
            .await
            .map_err(|err| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("risk_action mark_executed: {err}"),
                )
            })?;
    }

    repo.save().await?;

    Ok(Json(grant))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.revoke", skip_all)]
pub async fn revoke_handler(
    req: &mut Request,
    depot: &Depot,
    grant_id: PathParam<String>,
) -> Result<StatusCode, AppError> {
    let mut repo = extract_call_context(req, depot).await?.repo;
    let grant_id = grant_id.into_inner();
    let clock = make_clock();

    let revoked = {
        let mut grants = repo.circle_capability_grant();
        grants.revoke_by_id(&*clock, &grant_id).await?
    };

    match revoked {
        Some(_) => {
            repo.save().await?;
            Ok(StatusCode::NO_CONTENT)
        }
        None => {
            repo.cancel().await?;
            Err(AppError::new(StatusCode::NOT_FOUND, "grant not found"))
        }
    }
}

fn canonicalize_circle_ids(ids: &mut Vec<String>) {
    ids.sort();
    ids.dedup();
}

#[cfg(test)]
mod tests {
    use coauth_admin_types::circle_capability_admin::CircleCapabilityAction;

    use super::*;

    #[test]
    fn canonicalize_circle_ids_sorts_and_deduplicates() {
        let mut ids = vec![
            "ck:circle:c".to_owned(),
            "ck:circle:a".to_owned(),
            "ck:circle:c".to_owned(),
        ];
        canonicalize_circle_ids(&mut ids);
        assert_eq!(ids, vec!["ck:circle:a", "ck:circle:c"]);
    }

    #[test]
    fn create_request_validation_still_mirrors_registry_constraints() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ck:realm:demo".into(),
            action: CircleCapabilityAction::Manage,
            allowed_circle_ids: vec![],
        };
        assert!(req.validate().is_err());
    }
}
