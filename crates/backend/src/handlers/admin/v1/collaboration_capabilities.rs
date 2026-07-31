//! Admin endpoints for managing collaboration capability grants.
//!
//! Surfaces four routes consumed by sodmin and other admin clients:
//!
//! - `GET    /_coauth/admin/collaboration/capabilities/templates`
//! - `GET    /_coauth/admin/collaboration/capabilities`
//! - `POST   /_coauth/admin/collaboration/capabilities`
//! - `DELETE /_coauth/admin/collaboration/capabilities/{id}`

use arkret_canonical::{canonical_json_bytes, canonical_sha256, format_timestamp_canonical};
use arkret_identifiers::{EventId, GrantId, RealmId, new_prefixed_uuid7};
use arkret_models_collaboration::events_payloads::capability::CapabilityGrantPayload;
use arkret_models_collaboration::governance::grant_constraint::CapabilityGrant;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_admin_types::collaboration_capability_admin::{
    CapabilityRiskTier, CollaborationCapabilityGrant, CreateCollaborationCapabilityGrant,
    ListCollaborationCapabilityGrantsOutcome, ListCollaborationCapabilityTemplatesOutcome,
    collaboration_capability_templates,
};
use coauth_config::ArkretConfig;
use coauth_data::queue::{CollaborationCapabilityFanoutJob, QueueJobRepositoryExt as _};
use coauth_data::{
    CapabilityActionId, CollaborationCapabilityRevokeFanout, NewCollaborationCapabilityGrant,
    RepositoryAccess, capability_action_risk_tier,
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
use soland_contracts::integration::capability_fanout::{
    CapabilityFanoutBody, CapabilityFanoutProof, capability_fanout_proof_transcript,
};
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
    let data = repo
        .collaboration_capability_grant()
        .list_active()
        .await?
        .into_iter()
        .map(CollaborationCapabilityGrant::from)
        .collect();
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

    let tier = capability_action_risk_tier(body.action);
    let approved_proposal = if tier == CapabilityRiskTier::High {
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

    Ok(Json(grant.into()))
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

fn build_grant_fanout_payload(
    grant_event_id: &str,
    capability_grant_id: &str,
    subject: &str,
    realm_id: &str,
    action: CapabilityActionId,
    expires_at: Option<DateTime<Utc>>,
    approval_evidence_ref: Option<&str>,
    issued_at: DateTime<Utc>,
    service_id: &str,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
) -> Result<CapabilityFanoutBody, AppError> {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).map_err(|err| {
        AppError::new(StatusCode::BAD_REQUEST, format!("invalid realm_id: {err}"))
    })?;
    let typed_grant_id = GrantId::new(capability_grant_id.to_owned()).map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid generated capability_grant_id: {err}"),
        )
    })?;
    let mut grant_value = json!({
        "id": capability_grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": service_id,
        "subject": subject,
        "actions": [action.as_str()],
        "resources": [{ "kind": "realm", "realm_id": realm_id }],
        "issued_at": format_timestamp_canonical(issued_at),
        "proofs": [],
    });
    if let Some(expires_at) = expires_at {
        grant_value["expires_at"] = json!(format_timestamp_canonical(expires_at));
    }
    if let Some(approval_evidence_ref) = approval_evidence_ref {
        grant_value["constraints"] = json!([{
            "constraint_kind": "claim_based",
            "constraint_subkind": "approval",
            "effect": "allow",
            "approval_required": true,
            "x_approval_evidence_ref": approval_evidence_ref,
        }]);
    }

    let mut grant: CapabilityGrant = serde_json::from_value(grant_value).map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("generated capability grant is invalid: {err}"),
        )
    })?;
    let verification_method = signing_verification_method(key_store, service_id)?;
    let grant_payload_digest = grant.payload_digest().map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("capability grant payload digest: {err}"),
        )
    })?;
    let mut protocol_proof = arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        alg: "EdDSA".to_owned(),
        payload_digest: grant_payload_digest,
        created_at: issued_at,
        domain: None,
        audience: None,
        proof_purpose: Some(arkret_wire::PayloadProofPurpose::IssuerAttestation),
        jws: String::new(),
    };
    let proof_binding_bytes = grant
        .canonical_proof_binding_bytes(&protocol_proof)
        .map_err(|err| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("capability grant proof binding: {err}"),
            )
        })?;
    let (signed_verification_method, grant_proof_jws) =
        sign_detached_jws(key_store, service_id, &proof_binding_bytes)?;
    if signed_verification_method != verification_method {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capability grant signing key changed while building proof",
        ));
    }
    protocol_proof.jws = grant_proof_jws;
    grant.proofs.push(protocol_proof);
    let payload = serde_json::to_value(CapabilityGrantPayload {
        grant: Some(grant),
        grant_id: typed_grant_id,
        subject: None,
        actions: None,
        resources: None,
    })
    .map_err(|err| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("capability grant payload serialization failed: {err}"),
        )
    })?;
    let fanout_proof = sign_fanout_proof(
        key_store,
        service_id,
        "grant",
        "ak.capability.grant",
        grant_event_id,
        capability_grant_id,
        typed_realm_id.as_str(),
        &payload,
        issued_at,
    )?;

    Ok(CapabilityFanoutBody {
        kind: soland_contracts::integration::capability_fanout::CAPABILITY_FANOUT_KIND.to_owned(),
        operation: "grant".to_owned(),
        issuer_service_id: service_id.to_owned(),
        event_kind: "ak.capability.grant".to_owned(),
        event_id: grant_event_id.to_owned(),
        capability_grant_id: capability_grant_id.to_owned(),
        realm_id: typed_realm_id,
        payload,
        proofs: vec![fanout_proof],
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
    let typed_realm_id = RealmId::new(realm_id.to_owned()).map_err(|err| {
        AppError::new(StatusCode::BAD_REQUEST, format!("invalid realm_id: {err}"))
    })?;
    let revoke_payload = json!({
        "grant_id": capability_grant_id,
        "grant_ref": capability_grant_id,
        "reason": "administrative_revoke",
    });
    let proof = sign_fanout_proof(
        key_store,
        service_id,
        "revoke",
        "ak.capability.revoke",
        revoke_event_id,
        capability_grant_id,
        typed_realm_id.as_str(),
        &revoke_payload,
        revoked_at,
    )?;

    Ok(CapabilityFanoutBody {
        kind: soland_contracts::integration::capability_fanout::CAPABILITY_FANOUT_KIND.to_owned(),
        operation: "revoke".to_owned(),
        issuer_service_id: service_id.to_owned(),
        event_kind: "ak.capability.revoke".to_owned(),
        event_id: revoke_event_id.to_owned(),
        capability_grant_id: capability_grant_id.to_owned(),
        realm_id: typed_realm_id,
        payload: revoke_payload,
        proofs: vec![proof],
        principal_servers: principal_servers(arkret_config),
    })
}

fn sign_fanout_proof(
    key_store: &Keystore,
    service_id: &str,
    operation: &str,
    event_kind: &str,
    event_id: &str,
    capability_grant_id: &str,
    realm_id: &str,
    payload: &Value,
    created_at: DateTime<Utc>,
) -> Result<CapabilityFanoutProof, AppError> {
    let transcript = capability_fanout_proof_transcript(
        operation,
        service_id,
        event_kind,
        event_id,
        capability_grant_id,
        realm_id,
        payload,
    );
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

    Ok(CapabilityFanoutProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: arkret_identifiers::Hash::new(event_digest).map_err(|error| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("capability fanout proof digest invalid: {error}"),
            )
        })?,
        created_at,
        jws,
    })
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

fn signing_verification_method(
    key_store: &Keystore,
    service_id: &str,
) -> Result<arkret_wire::DidUrl, AppError> {
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
    arkret_wire::DidUrl::new(format!("{service_id}#{key_id}")).map_err(|error| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("capability fanout verification method is not a DID URL: {error}"),
        )
    })
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
    use coauth_admin_types::collaboration_capability_admin::CapabilityActionId;
    use coauth_config::{ArkretConfig, PrincipalServerConfig};
    use coauth_keystore::{JsonWebKeySet, Keystore, PrivateKey};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn high_risk_request_validation_stays_in_body_shape() {
        let req = CreateCollaborationCapabilityGrant {
            subject: "did:web:alice.example".into(),
            realm_id: "ak:realm:demo".into(),
            action: CapabilityActionId::RealmSearchPolicy,
            expires_at: None,
            approval_evidence_ref: None,
        };
        assert!(req.validate().is_err());
    }

    fn config() -> ArkretConfig {
        let config = ArkretConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-dev".to_owned(),
                endpoint: "http://soland.test".parse().unwrap(),
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }],
            ..ArkretConfig::default()
        };
        crate::services::resolved_principal_audiences::shared()
            .insert_for_test(&config.principal_servers[0].endpoint, "did:web:soland.test");
        config
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
            CapabilityActionId::PinAdd,
            None,
            Some("ak:event:01904100-0000-7000-8000-000000000099"),
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
        let typed_payload: CapabilityGrantPayload =
            serde_json::from_value(payload.payload.clone()).unwrap();
        let typed_grant = typed_payload.grant.as_ref().unwrap();
        let constraint = &typed_grant.constraints[0];
        assert_eq!(
            constraint.constraint_kind,
            arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::ClaimBased
        );
        assert_eq!(
            constraint.constraint_subkind,
            Some(
                arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::Approval
            )
        );
        assert_eq!(constraint.approval_required, Some(true));
        assert_eq!(
            constraint.extensions["x_approval_evidence_ref"],
            "ak:event:01904100-0000-7000-8000-000000000099"
        );
        let proof = &payload.payload["grant"]["proofs"][0];
        assert_eq!(proof["alg"], "EdDSA");
        assert_eq!(
            proof["verification_method"],
            "did:web:coauth.example#service-signing"
        );
        assert_ne!(proof["jws"], "queued-for-service-signature");
        assert!(proof["jws"].as_str().unwrap().contains(".."));
        assert!(
            proof["payload_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(payload.proofs.len(), 1);
        assert!(
            payload.proofs[0]
                .event_digest
                .as_str()
                .starts_with("sha256:")
        );
        let canonical = canonical_json_bytes(&payload).unwrap();
        let roundtrip: CapabilityFanoutBody = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(canonical_json_bytes(&roundtrip).unwrap(), canonical);
        let transcript = capability_fanout_proof_transcript(
            &roundtrip.operation,
            &roundtrip.issuer_service_id,
            &roundtrip.event_kind,
            &roundtrip.event_id,
            &roundtrip.capability_grant_id,
            roundtrip.realm_id.as_str(),
            &roundtrip.payload,
        );
        assert_eq!(
            roundtrip.proofs[0].event_digest.as_str(),
            canonical_sha256(&transcript).unwrap()
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
            payload.realm_id.as_str(),
            "ak:realm:01904100-0000-7000-8000-000000000001"
        );
        assert!(payload.payload.get("realm_id").is_none());
        assert!(payload.payload.get("proofs").is_none());
        assert_eq!(payload.proofs[0].alg, "EdDSA");
        assert_ne!(payload.proofs[0].jws, "queued-for-service-signature");
        assert!(payload.proofs[0].jws.contains(".."));
        let transcript = capability_fanout_proof_transcript(
            &payload.operation,
            &payload.issuer_service_id,
            &payload.event_kind,
            &payload.event_id,
            &payload.capability_grant_id,
            payload.realm_id.as_str(),
            &payload.payload,
        );
        assert_eq!(
            payload.proofs[0].event_digest.as_str(),
            canonical_sha256(&transcript).unwrap()
        );
        let other_realm_transcript = capability_fanout_proof_transcript(
            &payload.operation,
            &payload.issuer_service_id,
            &payload.event_kind,
            &payload.event_id,
            &payload.capability_grant_id,
            "ak:realm:01904100-0000-7000-8000-000000000002",
            &payload.payload,
        );
        assert_ne!(
            payload.proofs[0].event_digest.as_str(),
            canonical_sha256(&other_realm_transcript).unwrap()
        );
    }
}
