//! Admin endpoints for managing collaboration capability grants.
//!
//! Surfaces four routes consumed by sodmin and other admin clients:
//!
//! - `GET    /_coauth/admin/collaboration/capabilities/templates`
//! - `GET    /_coauth/admin/collaboration/capabilities`
//! - `POST   /_coauth/admin/collaboration/capabilities`
//! - `DELETE /_coauth/admin/collaboration/capabilities/{id}`

use chrono::{DateTime, Utc};
use coauth_admin_types::collaboration_capability_admin::{
    CollaborationCapabilityGrant, CreateCollaborationCapabilityGrant,
    ListCollaborationCapabilityGrantsOutcome, ListCollaborationCapabilityTemplatesOutcome,
    RiskTier, collaboration_capability_templates,
};
use coauth_config::CokretConfig;
use coauth_data::queue::{CollaborationCapabilityFanoutJob, QueueJobRepositoryExt as _};
use coauth_data::{
    CollaborationCapabilityAction, CollaborationCapabilityRevokeFanout,
    NewCollaborationCapabilityGrant, RepositoryAccess,
};
use cokret_core::canonical::canonical_sha256;
use cokret_core::identifiers::{EventId, GrantId, new_prefixed_uuid7};
use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::{Value, json};
use ulid::Ulid;

use crate::JsonResult;
use crate::error::AppError;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::cokret::service_did_for;
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

    let cokret_config = depot.cokret_config()?;
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &cokret_config);
    let capability_grant_id = GrantId::new(new_prefixed_uuid7("ck:grant:"))
        .map_err(|err| AppError::internal_box(Box::new(err)))?
        .into_string();
    let grant_event_id = EventId::new(new_prefixed_uuid7("ck:event:"))
        .map_err(|err| AppError::internal_box(Box::new(err)))?
        .into_string();
    let issued_at = call_context.clock.now();
    let grant_fanout_payload = build_grant_fanout_payload(
        &grant_event_id,
        &capability_grant_id,
        &body.subject,
        &body.realm_id,
        body.action,
        body.expires_at,
        body.approval_evidence_ref.as_deref(),
        issued_at,
        &service_did,
        &cokret_config,
    );
    let grant_raw_payload_digest = canonical_sha256(&grant_fanout_payload).map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("grant fanout canonical digest: {err}"),
        )
    })?;
    let grant_fanout_idempotency_key =
        format!("coauth:collaboration_capability_grant:{capability_grant_id}");

    let mut rng = make_rng();
    let mut repo = call_context.repo;
    let grant = repo
        .collaboration_capability_grant()
        .add(
            &mut *rng,
            &*call_context.clock,
            NewCollaborationCapabilityGrant {
                capability_grant_id: capability_grant_id.clone(),
                grant_event_id: grant_event_id.clone(),
                subject: body.subject,
                realm_id: body.realm_id,
                action: body.action,
                expires_at: body.expires_at,
                approval_evidence_ref: body.approval_evidence_ref,
                granted_by: actor_id,
                grant_raw_payload_digest: grant_raw_payload_digest.clone(),
                grant_fanout_idempotency_key: grant_fanout_idempotency_key.clone(),
            },
        )
        .await?;

    repo.queue_job()
        .schedule_job(
            &mut *rng,
            &*call_context.clock,
            CollaborationCapabilityFanoutJob::grant(
                grant_fanout_idempotency_key,
                capability_grant_id,
                grant_event_id,
                grant_raw_payload_digest,
                grant_fanout_payload,
            ),
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
    let revoke_event_id = EventId::new(new_prefixed_uuid7("ck:event:"))
        .map_err(|err| AppError::internal_box(Box::new(err)))?
        .into_string();

    let revoked = {
        let mut grants = repo.collaboration_capability_grant();
        grants
            .revoke_by_id(
                &*clock,
                &grant_id,
                CollaborationCapabilityRevokeFanout {
                    revoke_event_id: revoke_event_id.clone(),
                },
            )
            .await?
    };

    match revoked {
        Some(revoked) => {
            let cokret_config = depot.cokret_config()?;
            let url_builder = depot.url_builder()?;
            let service_did = service_did_for(&url_builder, &cokret_config);
            let revoke_fanout_payload = build_revoke_fanout_payload(
                &revoke_event_id,
                &revoked.capability_grant_id,
                &revoked.realm_id,
                revoked.revoked_at.unwrap_or_else(|| clock.now()),
                &service_did,
                &cokret_config,
            );
            let revoke_raw_payload_digest =
                canonical_sha256(&revoke_fanout_payload).map_err(|err| {
                    AppError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("revoke fanout canonical digest: {err}"),
                    )
                })?;
            let revoke_fanout_idempotency_key = format!(
                "coauth:collaboration_capability_revoke:{}",
                revoked.capability_grant_id
            );
            let mut rng = make_rng();
            repo.queue_job()
                .schedule_job(
                    &mut *rng,
                    &*clock,
                    CollaborationCapabilityFanoutJob::revoke(
                        revoke_fanout_idempotency_key,
                        revoked.capability_grant_id,
                        revoke_event_id,
                        revoke_raw_payload_digest,
                        revoke_fanout_payload,
                    ),
                )
                .await?;
            repo.save().await?;
            Ok(StatusCode::NO_CONTENT)
        }
        None => {
            repo.cancel().await?;
            Err(AppError::new(StatusCode::NOT_FOUND, "grant not found"))
        }
    }
}

fn build_grant_fanout_payload(
    grant_event_id: &str,
    capability_grant_id: &str,
    subject: &str,
    realm_id: &str,
    action: CollaborationCapabilityAction,
    expires_at: Option<DateTime<Utc>>,
    approval_evidence_ref: Option<&str>,
    issued_at: DateTime<Utc>,
    service_did: &str,
    cokret_config: &CokretConfig,
) -> Value {
    let mut grant = json!({
        "id": capability_grant_id,
        "schema": "ck.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": service_did,
        "subject": subject,
        "actions": [action.as_action_str()],
        "resources": [{ "kind": "realm", "realm_id": realm_id }],
        "issued_at": issued_at,
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{service_did}#service-signing"),
            "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": issued_at,
            "jws": "queued-for-service-signature"
        }],
    });
    if let Some(expires_at) = expires_at {
        grant["expires_at"] = json!(expires_at);
    }
    if let Some(approval_evidence_ref) = approval_evidence_ref {
        grant["constraints"] = json!([{
            "constraint_type": "approval",
            "effect": "allow",
            "approval_evidence_ref": approval_evidence_ref,
        }]);
    }

    json!({
        "kind": "ck.coauth.collaboration_capability.fanout.v1",
        "operation": "grant",
        "issuer_service_did": service_did,
        "event_kind": "ck.capability.grant",
        "event_id": grant_event_id,
        "capability_grant_id": capability_grant_id,
        "payload": {
            "grant_id": capability_grant_id,
            "grant": grant,
        },
        "principal_servers": principal_servers(cokret_config),
    })
}

fn build_revoke_fanout_payload(
    revoke_event_id: &str,
    capability_grant_id: &str,
    realm_id: &str,
    revoked_at: DateTime<Utc>,
    service_did: &str,
    cokret_config: &CokretConfig,
) -> Value {
    json!({
        "kind": "ck.coauth.collaboration_capability.fanout.v1",
        "operation": "revoke",
        "issuer_service_did": service_did,
        "event_kind": "ck.capability.revoke",
        "event_id": revoke_event_id,
        "capability_grant_id": capability_grant_id,
        "payload": {
            "grant_id": capability_grant_id,
            "realm_id": realm_id,
            "revoked_at": revoked_at,
        },
        "principal_servers": principal_servers(cokret_config),
    })
}

fn principal_servers(cokret_config: &CokretConfig) -> Vec<Value> {
    cokret_config
        .principal_servers
        .iter()
        .map(|server| {
            json!({
                "name": server.name.as_str(),
                "audience": server.audience.as_str(),
                "endpoint": server.endpoint.as_str(),
                "did": server.did.as_deref(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use coauth_admin_types::collaboration_capability_admin::CollaborationCapabilityAction;
    use coauth_config::{CokretConfig, PrincipalServerConfig};

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

    fn config() -> CokretConfig {
        CokretConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-dev".to_owned(),
                audience: "http://soland.test".to_owned(),
                endpoint: "http://soland.test".parse().unwrap(),
                did: Some("did:web:soland.test".to_owned()),
                oauth_introspection_bearer: None,
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }],
            ..CokretConfig::default()
        }
    }

    #[test]
    fn grant_fanout_payload_uses_standard_capability_event_shape() {
        let issued_at = Utc.with_ymd_and_hms(2026, 6, 1, 1, 2, 3).unwrap();
        let payload = build_grant_fanout_payload(
            "ck:event:01904100-0000-7000-8000-000000000011",
            "ck:grant:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck:realm:01904100-0000-7000-8000-000000000001",
            CollaborationCapabilityAction::PinAdd,
            None,
            None,
            issued_at,
            "did:web:coauth.example",
            &config(),
        );

        assert_eq!(payload["event_kind"], "ck.capability.grant");
        assert_eq!(
            payload["payload"]["grant_id"],
            "ck:grant:01904100-0000-7000-8000-000000000010"
        );
        assert_eq!(
            payload["payload"]["grant"]["issuer"],
            "did:web:coauth.example"
        );
        assert_eq!(
            payload["payload"]["grant"]["actions"],
            json!(["ck.pin.add"])
        );
        assert_eq!(
            payload["principal_servers"][0]["did"],
            "did:web:soland.test"
        );
    }

    #[test]
    fn revoke_fanout_payload_uses_standard_revoke_event_shape() {
        let revoked_at = Utc.with_ymd_and_hms(2026, 6, 1, 1, 2, 3).unwrap();
        let payload = build_revoke_fanout_payload(
            "ck:event:01904100-0000-7000-8000-000000000012",
            "ck:grant:01904100-0000-7000-8000-000000000010",
            "ck:realm:01904100-0000-7000-8000-000000000001",
            revoked_at,
            "did:web:coauth.example",
            &config(),
        );

        assert_eq!(payload["event_kind"], "ck.capability.revoke");
        assert_eq!(
            payload["payload"]["grant_id"],
            "ck:grant:01904100-0000-7000-8000-000000000010"
        );
        assert_eq!(
            payload["payload"]["realm_id"],
            "ck:realm:01904100-0000-7000-8000-000000000001"
        );
    }
}
