//! Admin endpoints for managing collaboration capability grants.
//!
//! Surfaces four routes consumed by sodmin and other admin clients:
//!
//! - `GET    /_coauth/admin/collaboration/capabilities/templates`
//! - `GET    /_coauth/admin/collaboration/capabilities`
//! - `POST   /_coauth/admin/collaboration/capabilities`
//! - `DELETE /_coauth/admin/collaboration/capabilities/{id}`

use arkret_core::canonical::{canonical_json_bytes, canonical_sha256};
use arkret_core::identifiers::{EventId, GrantId, new_prefixed_uuid7};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_admin_types::collaboration_capability_admin::{
    CollaborationCapabilityGrant, CreateCollaborationCapabilityGrant,
    ListCollaborationCapabilityGrantsOutcome, ListCollaborationCapabilityTemplatesOutcome,
    RiskTier, collaboration_capability_templates,
};
use coauth_config::ArkretConfig;
use coauth_data::queue::{CollaborationCapabilityFanoutJob, QueueJobRepositoryExt as _};
use coauth_data::{
    CollaborationCapabilityAction, CollaborationCapabilityRevokeFanout,
    NewCollaborationCapabilityGrant, RepositoryAccess,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::constraints::Constrainable as _;
use coauth_jose::jwt::JsonWebSignatureHeader;
use coauth_keystore::Keystore;
use rand_core::SeedableRng as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::{Value, json};
use signature::RandomizedSigner as _;
use soland_core::capability_fanout::CapabilityFanoutBody;
use ulid::Ulid;

use crate::JsonResult;
use crate::error::AppError;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::arkret::service_id_for;
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

    let arkret_config = depot.arkret_config()?;
    let service_id = service_id_for(&arkret_config);
    let key_store = depot.key_store()?;
    let capability_grant_id = GrantId::new(new_prefixed_uuid7("ak:grant:"))
        .map_err(|err| AppError::internal_box(Box::new(err)))?
        .into_string();
    let grant_event_id = EventId::new(new_prefixed_uuid7("ak:event:"))
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
        service_id.as_str(),
        &arkret_config,
        &key_store,
    );
    let grant_fanout_payload = grant_fanout_payload?;
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

    // REL-03: consume the approved proposal *before* persisting the grant
    // and scheduling its fan-out. `mark_executed` claims execution rights
    // (`approved -> executed`); a concurrent request racing on the same
    // proposal sees `AlreadyExecuted` and is rejected, so a single approval
    // cannot mint two grants.
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
    let revoke_event_id = EventId::new(new_prefixed_uuid7("ak:event:"))
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
            let arkret_config = depot.arkret_config()?;
            let service_id = service_id_for(&arkret_config);
            let key_store = depot.key_store()?;
            let revoke_fanout_payload = build_revoke_fanout_payload(
                &revoke_event_id,
                &revoked.capability_grant_id,
                &revoked.realm_id,
                revoked.revoked_at.unwrap_or_else(|| clock.now()),
                service_id.as_str(),
                &arkret_config,
                &key_store,
            )?;
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

/// Fanout envelope kind expected by soland's
/// `/_soland/root/authz/capability-fanout` handler (shared contract in
/// `soland_core::capability_fanout`).
const CAPABILITY_FANOUT_KIND: &str = "ak.coauth.collaboration_capability.fanout.v1";

fn build_grant_fanout_payload(
    grant_event_id: &str,
    capability_grant_id: &str,
    subject: &str,
    realm_id: &str,
    action: CollaborationCapabilityAction,
    expires_at: Option<DateTime<Utc>>,
    approval_evidence_ref: Option<&str>,
    issued_at: DateTime<Utc>,
    service_id: &str,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
) -> Result<CapabilityFanoutBody, AppError> {
    let mut grant = json!({
        "id": capability_grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": service_id,
        "subject": subject,
        "actions": [action.as_action_str()],
        "resources": [{ "kind": "realm", "realm_id": realm_id }],
        "issued_at": issued_at,
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

    let unsigned_payload = json!({
        "grant_id": capability_grant_id,
        "grant": grant,
    });
    let proof = sign_fanout_proof(
        key_store,
        service_id,
        "ak.capability.grant",
        grant_event_id,
        capability_grant_id,
        &unsigned_payload,
        issued_at,
    )?;
    let mut signed_grant = unsigned_payload["grant"].clone();
    signed_grant["proofs"] = json!([proof]);

    Ok(CapabilityFanoutBody {
        kind: CAPABILITY_FANOUT_KIND.to_owned(),
        operation: "grant".to_owned(),
        issuer_service_id: service_id.to_owned(),
        event_kind: "ak.capability.grant".to_owned(),
        event_id: grant_event_id.to_owned(),
        capability_grant_id: capability_grant_id.to_owned(),
        payload: json!({
            "grant_id": capability_grant_id,
            "grant": signed_grant,
        }),
        principal_servers: principal_servers(arkret_config),
    })
}

fn build_revoke_fanout_payload(
    revoke_event_id: &str,
    capability_grant_id: &str,
    realm_id: &str,
    revoked_at: DateTime<Utc>,
    service_id: &str,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
) -> Result<CapabilityFanoutBody, AppError> {
    let mut revoke_payload = json!({
        "grant_id": capability_grant_id,
        "realm_id": realm_id,
        "revoked_at": revoked_at,
    });
    let proof = sign_fanout_proof(
        key_store,
        service_id,
        "ak.capability.revoke",
        revoke_event_id,
        capability_grant_id,
        &revoke_payload,
        revoked_at,
    )?;
    revoke_payload["proofs"] = json!([proof]);

    Ok(CapabilityFanoutBody {
        kind: CAPABILITY_FANOUT_KIND.to_owned(),
        operation: "revoke".to_owned(),
        issuer_service_id: service_id.to_owned(),
        event_kind: "ak.capability.revoke".to_owned(),
        event_id: revoke_event_id.to_owned(),
        capability_grant_id: capability_grant_id.to_owned(),
        payload: revoke_payload,
        principal_servers: principal_servers(arkret_config),
    })
}

fn sign_fanout_proof(
    key_store: &Keystore,
    service_id: &str,
    event_kind: &str,
    event_id: &str,
    capability_grant_id: &str,
    payload: &Value,
    created_at: DateTime<Utc>,
) -> Result<Value, AppError> {
    let transcript = json!({
        "kind": "org.arkret.coauth.collaboration_capability.proof.v1",
        "event_kind": event_kind,
        "event_id": event_id,
        "capability_grant_id": capability_grant_id,
        "payload": payload,
    });
    let transcript_bytes = canonical_json_bytes(&transcript).map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("capability fanout proof canonical transcript: {err}"),
        )
    })?;
    let event_digest = canonical_sha256(&transcript).map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("capability fanout proof digest: {err}"),
        )
    })?;
    let (verification_method, jws) = sign_detached_jws(key_store, service_id, &transcript_bytes)?;

    Ok(json!({
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": verification_method,
        "event_digest": event_digest,
        "created_at": created_at,
        "jws": jws,
    }))
}

fn sign_detached_jws(
    key_store: &Keystore,
    service_id: &str,
    payload_bytes: &[u8],
) -> Result<(String, String), AppError> {
    let alg = JsonWebSignatureAlg::EdDsa;
    let key = key_store.signing_key_for_algorithm(&alg).ok_or_else(|| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no EdDSA service signing key is configured for capability fanout",
        )
    })?;
    let key_id = key.kid().ok_or_else(|| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capability fanout signing key is missing kid",
        )
    })?;
    let verification_method = format!("{service_id}#{key_id}");
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(verification_method.clone());
    let protected =
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).map_err(|err| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("capability fanout JWS protected header: {err}"),
            )
        })?);
    let payload = Base64UrlUnpadded::encode_string(payload_bytes);
    let signing_input = format!("{protected}.{payload}");
    let signer = key_store.signer_for_algorithm(&alg).map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("capability fanout signer: {err}"),
        )
    })?;
    let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).map_err(|_| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capability fanout signer RNG failed",
        )
    })?;
    let raw = signer
        .try_sign_with_rng(&mut rng, signing_input.as_bytes())
        .map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "capability fanout detached JWS signing failed",
            )
        })?;
    let signature_bytes: Box<[u8]> = raw.into();
    let signature = Base64UrlUnpadded::encode_string(&signature_bytes);

    Ok((verification_method, format!("{protected}..{signature}")))
}

fn principal_servers(arkret_config: &ArkretConfig) -> Vec<Value> {
    arkret_config
        .principal_servers
        .iter()
        .map(|server| {
            let service_id =
                crate::services::resolved_principal_audiences::effective_audience_shared(server);
            json!({
                "name": server.name.as_str(),
                "audience": service_id.clone(),
                "endpoint": server.endpoint.as_str(),
                "did": service_id,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use coauth_admin_types::collaboration_capability_admin::CollaborationCapabilityAction;
    use coauth_config::{ArkretConfig, PrincipalServerConfig};
    use coauth_keystore::{JsonWebKeySet, Keystore, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use super::*;

    #[test]
    fn high_risk_request_validation_stays_in_body_shape() {
        let req = CreateCollaborationCapabilityGrant {
            subject: "did:web:alice.example".into(),
            realm_id: "ak:realm:demo".into(),
            action: CollaborationCapabilityAction::RealmSearchPolicy,
            expires_at: None,
            approval_evidence_ref: None,
        };
        assert!(req.validate().is_err());
    }

    fn config() -> ArkretConfig {
        ArkretConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-dev".to_owned(),
                endpoint: "http://soland.test".parse().unwrap(),
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }],
            ..ArkretConfig::default()
        }
    }

    fn key_store() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let eddsa = coauth_keystore::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("service-signing");
        Keystore::new(JsonWebKeySet::new(vec![eddsa]))
    }

    #[test]
    fn grant_fanout_payload_uses_standard_capability_event_shape() {
        let issued_at = Utc.with_ymd_and_hms(2026, 6, 1, 1, 2, 3).unwrap();
        let key_store = key_store();
        let payload = build_grant_fanout_payload(
            "ak:event:01904100-0000-7000-8000-000000000011",
            "ak:grant:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ak:realm:01904100-0000-7000-8000-000000000001",
            CollaborationCapabilityAction::PinAdd,
            None,
            None,
            issued_at,
            "did:web:coauth.example",
            &config(),
            &key_store,
        )
        .unwrap();

        assert_eq!(payload.event_kind, "ak.capability.grant");
        assert_eq!(
            payload.payload["grant_id"],
            "ak:grant:01904100-0000-7000-8000-000000000010"
        );
        assert_eq!(payload.payload["grant"]["issuer"], "did:web:coauth.example");
        assert_eq!(payload.payload["grant"]["actions"], json!(["ak.pin.add"]));
        assert_eq!(payload.principal_servers[0]["did"], "did:web:soland.test");
        let proof = &payload.payload["grant"]["proofs"][0];
        assert_eq!(proof["alg"], "EdDSA");
        assert_eq!(
            proof["verification_method"],
            "did:web:coauth.example#service-signing"
        );
        assert_ne!(proof["jws"], "queued-for-service-signature");
        assert!(proof["jws"].as_str().unwrap().contains(".."));
        assert!(
            proof["event_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn revoke_fanout_payload_uses_standard_revoke_event_shape() {
        let revoked_at = Utc.with_ymd_and_hms(2026, 6, 1, 1, 2, 3).unwrap();
        let key_store = key_store();
        let payload = build_revoke_fanout_payload(
            "ak:event:01904100-0000-7000-8000-000000000012",
            "ak:grant:01904100-0000-7000-8000-000000000010",
            "ak:realm:01904100-0000-7000-8000-000000000001",
            revoked_at,
            "did:web:coauth.example",
            &config(),
            &key_store,
        )
        .unwrap();

        assert_eq!(payload.event_kind, "ak.capability.revoke");
        assert_eq!(
            payload.payload["grant_id"],
            "ak:grant:01904100-0000-7000-8000-000000000010"
        );
        assert_eq!(
            payload.payload["realm_id"],
            "ak:realm:01904100-0000-7000-8000-000000000001"
        );
        let proof = &payload.payload["proofs"][0];
        assert_eq!(proof["alg"], "EdDSA");
        assert_ne!(proof["jws"], "queued-for-service-signature");
        assert!(proof["jws"].as_str().unwrap().contains(".."));
    }
}
