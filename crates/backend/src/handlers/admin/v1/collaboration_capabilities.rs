//! Admin endpoints for managing collaboration capability grants.
//!
//! Surfaces four routes consumed by sodmin and other admin clients:
//!
//! - `GET    /_coauth/admin/collaboration/capabilities/templates`
//! - `GET    /_coauth/admin/collaboration/capabilities`
//! - `POST   /_coauth/admin/collaboration/capabilities`
//! - `DELETE /_coauth/admin/collaboration/capabilities/{id}`

use coauth_admin_types::collaboration_capability_admin::{
    CollaborationCapabilityGrant, CreateCollaborationCapabilityGrant,
    ListCollaborationCapabilityGrantsOutcome, ListCollaborationCapabilityTemplatesOutcome,
    RiskTier, collaboration_capability_templates,
};
use coauth_data::{NewCollaborationCapabilityGrant, RepositoryAccess};
use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use ulid::Ulid;

use crate::JsonResult;
use crate::error::AppError;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::common::{DepotExt, make_clock, make_rng};

#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.collaboration_capabilities.templates",
    skip_all
)]
pub async fn templates_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCollaborationCapabilityTemplatesOutcome> {
    let repo = extract_call_context(req, depot).await?.repo;
    repo.cancel().await?;
    Ok(Json(ListCollaborationCapabilityTemplatesOutcome {
        data: collaboration_capability_templates(),
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.collaboration_capabilities.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCollaborationCapabilityGrantsOutcome> {
    let mut repo = extract_call_context(req, depot).await?.repo;
    let data = repo.collaboration_capability_grant().list_active().await?;
    repo.cancel().await?;

    Ok(Json(ListCollaborationCapabilityGrantsOutcome { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.collaboration_capabilities.create", skip_all)]
pub async fn create_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<CollaborationCapabilityGrant> {
    let call_context = extract_call_context(req, depot).await?;

    let body: CreateCollaborationCapabilityGrant = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid grant body: {e}")))?;

    if let Err(msg) = body.validate() {
        return Err(AppError::bad_request(msg));
    }

    let tier = body.action.risk_tier();
    let approved_proposal = if tier == RiskTier::High {
        let proposal_id_raw = req
            .query::<String>("risk_action_proposal_id")
            .or_else(|| req.header::<String>("x-coauth-risk-action-proposal-id"))
            .ok_or_else(|| {
                AppError::bad_request(
                    "high-risk collaboration capability grants require an approved \
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
                 high-risk collaboration capability grant",
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

    let mut rng = make_rng();
    let mut repo = call_context.repo;
    let grant = repo
        .collaboration_capability_grant()
        .add(
            &mut *rng,
            &*call_context.clock,
            NewCollaborationCapabilityGrant {
                subject: body.subject,
                realm_id: body.realm_id,
                action: body.action,
                expires_at: body.expires_at,
                approval_evidence_ref: body.approval_evidence_ref,
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
#[tracing::instrument(name = "handler.admin.v1.collaboration_capabilities.revoke", skip_all)]
pub async fn revoke_handler(
    req: &mut Request,
    depot: &Depot,
    grant_id: PathParam<String>,
) -> Result<StatusCode, AppError> {
    let mut repo = extract_call_context(req, depot).await?.repo;
    let grant_id = grant_id.into_inner();
    let clock = make_clock();

    let revoked = {
        let mut grants = repo.collaboration_capability_grant();
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

#[cfg(test)]
mod tests {
    use coauth_admin_types::collaboration_capability_admin::CollaborationCapabilityAction;

    use super::*;

    #[test]
    fn high_risk_request_validation_stays_in_body_shape() {
        let req = CreateCollaborationCapabilityGrant {
            subject: "did:web:alice.example".into(),
            realm_id: "ck:realm:demo".into(),
            action: CollaborationCapabilityAction::RealmSearchPolicy,
            expires_at: None,
            approval_evidence_ref: None,
        };
        assert!(req.validate().is_err());
    }
}
