//! Transaction-bound B-model recovery device authorization.

use arkret_identifiers::{AuthorizationLeaseId, DeviceId, Did, Hash, ReceiptId};
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome;
use arkret_models_crypto::{RecoveryReceipt, RecoveryReceiptOutcome};
use arkret_models_identity::{
    SessionGrantCredentialClass, SessionGrantDeviceBinding, SignedSessionGrantClaims,
};
use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use arkret_signatures::{SignEventOptions, sign_event};
use arkret_wire::{
    AuthoritySetIssuerRole, AuthoritySetSourceKind, AuthorizationLease,
    AuthorizeRecoveryDeviceOutcome, AuthorizeRecoveryDeviceRequest, Event, EventKind, PayloadProof,
    PayloadSigner, PromoteRecoverySessionGrantOutcome, PromoteRecoverySessionGrantRequest,
    RECOVERY_ACCOUNT_AUTHORITY_SET_ID, RecoveryCompletionAttestation, ScopeRef,
    ServiceSignatureAlgorithm, proof_kind,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::{
    NewRecoveryDeviceAuthorization, NewRecoverySessionGrantPromotion, RepositoryAccess as _,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::device_enroll::{decode_device_public_key, truncate_to_seconds};
use super::session_grant::{
    mint_promoted_recovery_session_grant, persist_session_grant_with_browser_session_id,
};
use super::{ArkretRouteError, service_id_for};
use crate::handlers::common::DepotExt;
use crate::services::device_enrollment_authority::enrollment_authority;
use crate::services::did_resolver::{
    DidResolveError, verify_unpublished_webvh_candidate_from_history,
};
use crate::services::dpop::{DpopVerifier, dpop_htu, dpop_replay_record};
use crate::services::resolved_principal_audiences::{effective_audience, shared};

async fn configured_principal_server_document(
    depot: &Depot,
    server: &coauth_config::PrincipalServerConfig,
    expected_did: &str,
) -> Result<super::DidDocument, ArkretRouteError> {
    let mut url = server
        .endpoint
        .join("/_arkret/root/identity/document")
        .map_err(|error| {
            ArkretRouteError::Internal(
                anyhow::anyhow!(
                    "configured Principal Server identity endpoint is invalid: {error}"
                )
                .into(),
            )
        })?;
    url.query_pairs_mut().append_pair("did", expected_did);
    let response = depot
        .http_client()?
        .get(url.clone())
        .send()
        .await
        .map_err(|error| {
            ArkretRouteError::Internal(
                anyhow::anyhow!("configured Principal Server identity request failed: {error}")
                    .into(),
            )
        })?;
    let status = response.status();
    let body = response.bytes().await.map_err(|error| {
        ArkretRouteError::Internal(
            anyhow::anyhow!("configured Principal Server identity response failed: {error}").into(),
        )
    })?;
    if !status.is_success() {
        return Err(invalid_signature(format!(
            "configured Principal Server identity endpoint {url} returned {status}"
        )));
    }
    let view: arkret_models_identity::IdentityDocumentView = serde_json::from_slice(&body)
        .map_err(|error| {
            invalid_signature(format!(
                "configured Principal Server identity response is invalid: {error}"
            ))
        })?;
    let document: super::DidDocument = serde_json::from_value(serde_json::Value::Object(
        view.did_document.into_iter().collect(),
    ))
    .map_err(|error| {
        invalid_signature(format!(
            "configured Principal Server DID document is invalid: {error}"
        ))
    })?;
    if document.id != expected_did {
        return Err(invalid_signature(
            "configured Principal Server DID document changed service_id",
        ));
    }
    Ok(document)
}

async fn configured_principal_history(
    depot: &Depot,
    server: &coauth_config::PrincipalServerConfig,
    did: &arkret_identifiers::Did,
) -> Result<Vec<u8>, ArkretRouteError> {
    let mut builder = arkret_http_client::Client::builder(server.endpoint.clone())
        .http_client(depot.http_client()?);
    if server.endpoint.scheme() == "http" {
        builder = builder.allow_insecure_localhost();
    }
    let client = builder.build().map_err(|error| {
        ArkretRouteError::Internal(
            anyhow::anyhow!("configured Principal Server client is invalid: {error}").into(),
        )
    })?;
    let mut cursor = None;
    let mut history = Vec::new();
    loop {
        let page = client
            .identity_log(did.as_str(), cursor.as_deref(), Some(100))
            .await
            .map_err(|error| {
                failed_precondition(format!(
                    "configured Principal Server DID history is unavailable: {error}"
                ))
            })?;
        for entry in page.events {
            history.extend_from_slice(
                &serde_json::to_vec(&serde_json::Value::Object(entry.operation_body)).map_err(
                    |error| {
                        failed_precondition(format!(
                            "configured Principal Server DID history is invalid: {error}"
                        ))
                    },
                )?,
            );
            history.push(b'\n');
        }
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Err(failed_precondition(
                "configured Principal Server DID history pagination omitted next_cursor",
            ));
        }
    }
    Ok(history)
}

fn duplicate_conflict(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        message,
    )
}

fn invalid_signature(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::INVALID_SIGNATURE,
        message,
    )
}

fn failed_precondition(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::PRECONDITION_FAILED,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        message,
    )
}

fn exact_replay(
    record: coauth_data::RecoveryDeviceAuthorization,
    request: &AuthorizeRecoveryDeviceRequest,
    canonical_request: &[u8],
) -> Result<AuthorizeRecoveryDeviceOutcome, ArkretRouteError> {
    if record.ticket_id != request.ticket.ticket_id.as_str()
        || record.transaction_id != request.ticket.transaction_id.as_str()
        || record.transaction_request_digest != request.ticket.transaction_request_digest.as_str()
        || record.canonical_request != canonical_request
    {
        return Err(duplicate_conflict(
            "recovery authority identity was reused with different canonical request bytes",
        ));
    }
    serde_json::from_value(record.outcome).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "stored recovery authority outcome is invalid: {error}"
        )))
    })
}

fn verification_method_did(value: &str) -> &str {
    let without_fragment = value.split_once('#').map_or(value, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
}

fn did_version_id<'a>(
    principal_id: &arkret_identifiers::Did,
    reference: &'a str,
) -> Result<&'a str, ArkretRouteError> {
    reference
        .strip_prefix(principal_id.as_str())
        .and_then(|suffix| suffix.strip_prefix("?versionId="))
        .filter(|value| {
            !value.is_empty() && !value.bytes().any(|byte| matches!(byte, b'&' | b'#' | b'?'))
        })
        .ok_or_else(|| failed_precondition("recovery DID version reference is invalid"))
}

fn enrollment_delegation(
    state: serde_json::Value,
    principal_id: &arkret_identifiers::Did,
) -> Result<(String, String), ArkretRouteError> {
    let document: super::DidDocument = serde_json::from_value(state).map_err(|error| {
        failed_precondition(format!(
            "recovery DID entry state is not a valid DID document: {error}"
        ))
    })?;
    if document.id != principal_id.as_str() || !document.capability_delegation.is_empty() {
        return Err(failed_precondition(
            "recovery DID document is not the transaction principal's B-model document",
        ));
    }
    let mut delegations = document
        .service
        .iter()
        .filter(|service| service.kind == "ArkretDeviceEnrollmentAuthority");
    let delegation = delegations.next().ok_or_else(|| {
        failed_precondition(
            "recovery DID document omits ArkretDeviceEnrollmentAuthority delegation",
        )
    })?;
    if delegations.next().is_some()
        || !delegation
            .id
            .strip_prefix(principal_id.as_str())
            .is_some_and(|fragment| fragment.starts_with('#') && fragment.len() > 1)
    {
        return Err(failed_precondition(
            "recovery DID document enrollment delegation is ambiguous",
        ));
    }
    Ok((delegation.id.clone(), delegation.service_endpoint.clone()))
}

fn pre_fence_authorization_ref(
    previous_state: serde_json::Value,
    candidate_state: serde_json::Value,
    principal_id: &arkret_identifiers::Did,
    authority_did: &str,
) -> Result<String, ArkretRouteError> {
    let previous = enrollment_delegation(previous_state, principal_id)?;
    let candidate = enrollment_delegation(candidate_state, principal_id)?;
    if previous.1 != authority_did || candidate != previous {
        return Err(failed_precondition(
            "candidate DID document does not preserve the pre-fence Account Authority delegation",
        ));
    }
    Ok(previous.0)
}

fn validate_account_authority_policy(
    request: &AuthorizeRecoveryDeviceRequest,
    previous_state: &serde_json::Value,
    previous_version_id: &str,
    authority: &crate::services::device_enrollment_authority::EnrollmentAuthority,
) -> Result<(), ArkretRouteError> {
    let intent = &request
        .authorization_preimage
        .authorize_event_publication_intent;
    let policy = &intent.authority_set_policy;
    let source_digest = Hash::new(
        arkret_canonical::canonical_sha256(previous_state)
            .map_err(|error| failed_precondition(error.to_string()))?,
    )
    .map_err(|error| failed_precondition(error.to_string()))?;
    let rule = policy
        .validate_reference_and_action(
            &intent.authority_set_ref,
            &intent.scope_ref,
            &intent.authorization_rule_id,
            &intent.action,
        )
        .map_err(|error| failed_precondition(error.to_string()))?;
    if policy.authority_set_id != RECOVERY_ACCOUNT_AUTHORITY_SET_ID
        || policy.source.source_kind != AuthoritySetSourceKind::DidDocument
        || policy.source.source_ref != request.authorization_preimage.registry_previous_head
        || policy.source.source_digest != source_digest
        || policy.source.generation_ref != previous_version_id
        || rule.issuer_role != AuthoritySetIssuerRole::AccountEnrollmentAuthority
        || rule.threshold != 1
        || rule.issuers.len() != 1
        || rule.issuers[0].verification_method.as_str() != authority.verification_method()
    {
        return Err(failed_precondition(
            "recovery publication policy does not resolve from the pre-fence Account Authority delegation",
        ));
    }
    Ok(())
}

async fn verify_ticket_signature(
    req: &Request,
    depot: &Depot,
    _repo: &mut coauth_data::BoxRepository,
    request: &AuthorizeRecoveryDeviceRequest,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    let ticket = &request.ticket;
    ticket.validate_structural().map_err(|error| {
        invalid_signature(format!("invalid recovery authority ticket: {error}"))
    })?;
    if ticket.auth_data.alg != ServiceSignatureAlgorithm::EdDSA {
        return Err(invalid_signature(
            "this Account Authority only accepts EdDSA recovery authority tickets",
        ));
    }
    if ticket.expires_at <= now || ticket.issued_at > now + Duration::seconds(30) {
        return Err(failed_precondition(
            "recovery authority ticket is expired or not yet valid",
        ));
    }
    if verification_method_did(&ticket.auth_data.verification_method)
        != ticket.principal_server_id.as_str()
    {
        return Err(invalid_signature(
            "ticket verification method does not belong to principal_server_id",
        ));
    }

    let arkret_config = depot.arkret_config()?;
    let trusted_server = arkret_config
        .principal_servers
        .iter()
        .find(|server| {
            effective_audience(server, shared())
                .is_some_and(|service_id| service_id == ticket.principal_server_id)
        })
        .ok_or_else(|| {
            invalid_signature("ticket principal_server_id is not a configured Principal Server")
        })?;
    let document = configured_principal_server_document(
        depot,
        trusted_server,
        ticket.principal_server_id.as_str(),
    )
    .await?;
    let method = document
        .verification_method
        .iter()
        .find(|method| method.id == ticket.auth_data.verification_method)
        .ok_or_else(|| {
            invalid_signature("ticket verification method is absent from issuer DID document")
        })?;
    let material = method.public_key_material().map_err(invalid_signature)?;
    let signing_bytes = ticket
        .signing_bytes()
        .map_err(|error| invalid_signature(error.to_string()))?;
    if !verify_detached_ed25519_signature(&material, &signing_bytes, &ticket.auth_data.signature) {
        return Err(invalid_signature(
            "recovery authority ticket signature did not verify",
        ));
    }

    let _ = req;
    Ok(())
}

fn validate_fixed_event(
    request: &AuthorizeRecoveryDeviceRequest,
    authority: &crate::services::device_enrollment_authority::EnrollmentAuthority,
    authorization_ref: &str,
) -> Result<Event, ArkretRouteError> {
    let preimage = &request.authorization_preimage;
    let bytes = arkret_canonical::base64url::base64url_decode(
        &preimage.authorize_event_preimage.canonical_bytes_base64url,
    )
    .map_err(|error| failed_precondition(error.to_string()))?;
    let event: Event = serde_json::from_slice(&bytes).map_err(|error| {
        failed_precondition(format!("invalid authorize Event preimage: {error}"))
    })?;
    let payload = event
        .typed_payload::<DeviceAuthorizePayload>(EventKind::DEVICE_AUTHORIZE)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let expected_realm = arkret_models_identity::principal_control_realm_id(&preimage.principal_id);
    let expected_algorithms = preimage
        .algorithms
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let actual_algorithms = payload
        .algorithms
        .iter()
        .map(arkret_wire::NonEmptyString::as_str)
        .collect::<Vec<_>>();

    if event.event_id != preimage.authorize_event_id
        || event.actor_id != preimage.principal_id
        || event.actor_seq != preimage.actor_seq
        || event.realm_id.as_str() != expected_realm
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || event.created_at != preimage.not_before
        || event.hlc.is_none()
        || event.prev_refs.as_slice() != [preimage.reanchor_event_id.clone()]
        || !event.refs.is_empty()
        || !event.causal_refs.is_empty()
        || !event.preconditions.is_empty()
        || event.seal_ref.is_some()
        || event.auth_context.is_some()
        || event.seal_basis.is_some()
        || !event.unsigned.is_empty()
        || !event.proofs.is_empty()
        || event
            .executed_by
            .as_ref()
            .map(arkret_identifiers::Did::as_str)
            != Some(authority.did())
        || event.authorization_ref.as_deref() != Some(authorization_ref)
        || payload.principal_id != preimage.principal_id
        || payload.device_id != preimage.replacement_device_id
        || payload.device_public_key.as_str() != preimage.device_public_key
        || payload.hpke_key.as_str() != preimage.hpke_key
        || actual_algorithms != expected_algorithms
        || payload.not_before != preimage.not_before
        || payload.recovery_session_id.as_ref() != Some(&preimage.recovery_session_id)
        || payload.cross_signing_binding.is_some()
        || payload.proof.is_some()
        || !matches!(
            &payload.authorized_by,
            DeviceOrPrincipalRef::Did(did) if did.as_str() == authority.did()
        )
    {
        return Err(failed_precondition(
            "authorize Event preimage disagrees with the ticket-bound recovery plan",
        ));
    }
    payload
        .validate_service_attested_provenance(
            event.executed_by.as_ref(),
            event.authorization_ref.as_deref(),
            event.created_at,
        )
        .map_err(|error| failed_precondition(error.to_string()))?;
    let binding = payload
        .enrollment_authority_binding
        .as_ref()
        .ok_or_else(|| failed_precondition("enrollment authority binding is required"))?;
    if binding.authority_did.as_str() != authority.did()
        || binding.authorization_ref.as_str() != authorization_ref
    {
        return Err(failed_precondition(
            "authorize Event enrollment authority binding disagrees with durable delegation",
        ));
    }

    let device_signature = payload
        .device_signature
        .as_ref()
        .ok_or_else(|| failed_precondition("recovery authorize Event requires device_signature"))?;
    if serde_json::to_value(device_signature).ok()
        != serde_json::to_value(&preimage.possession_proof).ok()
    {
        return Err(failed_precondition(
            "replacement possession proof must equal authorize Event device_signature",
        ));
    }
    let possession_input = payload
        .device_possession_signature_input()
        .map_err(|error| failed_precondition(error.to_string()))?;
    let transcript_digest = Hash::new(arkret_canonical::sha256_digest(&possession_input))
        .map_err(|error| failed_precondition(error.to_string()))?;
    if transcript_digest != preimage.possession_proof.transcript_digest {
        return Err(invalid_signature(
            "replacement possession transcript digest mismatch",
        ));
    }
    let device_key = decode_device_public_key(&preimage.device_public_key)?;
    if !verify_detached_ed25519_signature(
        &PublicKeyMaterial::Ed25519Raw {
            bytes: device_key.to_vec(),
        },
        &possession_input,
        &preimage.possession_proof.signature,
    ) {
        return Err(invalid_signature(
            "replacement device possession signature did not verify",
        ));
    }

    Ok(event)
}

fn sign_authorization_lease(
    request: &AuthorizeRecoveryDeviceRequest,
    authority: &crate::services::device_enrollment_authority::EnrollmentAuthority,
    issued_at: DateTime<Utc>,
) -> Result<AuthorizationLease, ArkretRouteError> {
    let intent = &request
        .authorization_preimage
        .authorize_event_publication_intent;
    let mut lease = AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::from_uuid(uuid::Uuid::now_v7()),
        basis_ref: intent.basis_ref.clone(),
        actor_id: intent.actor_id.clone(),
        device_id: intent.device_id.clone(),
        scope_ref: intent.scope_ref.clone(),
        action: intent.action.clone(),
        authorization_rule_id: intent.authorization_rule_id.clone(),
        risk_tier: intent.risk_tier,
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        authority_set_ref: intent.authority_set_ref.clone(),
        authority_set_policy: intent.authority_set_policy.clone(),
        proofs: Vec::new(),
    };
    let payload_digest = lease
        .lease_digest()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: authority.verification_method().to_owned(),
        payload_digest,
        created_at: issued_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding_bytes = lease
        .proof_binding_bytes(&proof)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let signature = authority
        .signer()
        .sign_payload(&binding_bytes)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    proof.alg = signature.alg;
    proof.jws = signature.jws;
    lease.proofs.push(proof);
    lease
        .validate_structural()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    Ok(lease)
}

async fn replay_after_race(
    depot: &Depot,
    request: &AuthorizeRecoveryDeviceRequest,
    canonical_request: &[u8],
) -> Result<AuthorizeRecoveryDeviceOutcome, ArkretRouteError> {
    let mut repo = depot.repo().await?;
    let record = repo
        .recovery_authority()
        .lookup_authorization(request.ticket.ticket_id.as_str())
        .await?;
    let record = match record {
        Some(record) => Some(record),
        None => {
            repo.recovery_authority()
                .lookup_authorization_by_transaction(request.ticket.transaction_id.as_str())
                .await?
        }
    };
    repo.cancel().await?;
    match record {
        Some(record) => exact_replay(record, request, canonical_request),
        None => Err(invalid_signature(
            "holder proof JTI was already consumed without an accepted authorization",
        )),
    }
}

/// Consume a Principal-Server ticket and return one fixed authority-signed
/// `ak.device.authorize` Event.
#[handler]
pub async fn authorize_recovery_device_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<AuthorizeRecoveryDeviceOutcome>, ArkretRouteError> {
    let request: AuthorizeRecoveryDeviceRequest = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    request
        .validate_structural()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let canonical_request = arkret_canonical::canonical::canonical_json_bytes(&request)
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;

    let mut repo = depot.repo().await?;
    let existing_by_ticket = {
        let mut authorizations = repo.recovery_authority();
        authorizations
            .lookup_authorization(request.ticket.ticket_id.as_str())
            .await?
    };
    if let Some(record) = existing_by_ticket {
        repo.cancel().await?;
        return exact_replay(record, &request, &canonical_request).map(Json);
    }
    let existing_by_transaction = {
        let mut authorizations = repo.recovery_authority();
        authorizations
            .lookup_authorization_by_transaction(request.ticket.transaction_id.as_str())
            .await?
    };
    if let Some(record) = existing_by_transaction {
        repo.cancel().await?;
        return exact_replay(record, &request, &canonical_request).map(Json);
    }

    let now = truncate_to_seconds(crate::handlers::make_clock().now());
    verify_ticket_signature(req, depot, &mut repo, &request, now).await?;
    let config = depot.arkret_config()?;
    let service_id = service_id_for(&config);
    if request.ticket.account_authority_id != service_id
        || request.authorization_preimage.account_authority_id != service_id
    {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "recovery authority ticket targets another Account Authority",
        ));
    }
    if config.trust_domain.as_deref() != Some(request.ticket.trust_domain.as_str()) {
        return Err(failed_precondition(
            "recovery authority ticket trust domain mismatch",
        ));
    }

    repo.principal_did()
        .get_by_did(request.ticket.principal_id.as_str())
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "principal_unknown",
            )
        })?;
    let key_store = depot.key_store()?;
    let authority = enrollment_authority(&key_store)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let candidate_entry_bytes = arkret_canonical::base64url::base64url_decode(
        &request
            .authorization_preimage
            .did_entry_preimage
            .canonical_bytes_base64url,
    )
    .map_err(|error| failed_precondition(error.to_string()))?;
    let previous_version_id = did_version_id(
        &request.ticket.principal_id,
        &request.authorization_preimage.registry_previous_head,
    )?;
    let candidate_version_id = did_version_id(
        &request.ticket.principal_id,
        &request.authorization_preimage.did_entry_ref,
    )?;
    let principal_server = config
        .principal_servers
        .iter()
        .find(|server| {
            effective_audience(server, shared())
                .is_some_and(|service_id| service_id == request.ticket.principal_server_id)
        })
        .ok_or_else(|| {
            invalid_signature("ticket principal_server_id is not a configured Principal Server")
        })?;
    let current_history =
        configured_principal_history(depot, principal_server, &request.ticket.principal_id).await?;
    let verified_candidate = verify_unpublished_webvh_candidate_from_history(
        &request.ticket.principal_id,
        previous_version_id,
        &current_history,
        &candidate_entry_bytes,
        candidate_version_id,
    )
    .map_err(|error| match error {
        DidResolveError::BadResolverResponse(message) => failed_precondition(message),
        other => super::map_did_resolve_error(other),
    })?;
    validate_account_authority_policy(
        &request,
        &verified_candidate.previous_state,
        previous_version_id,
        &authority,
    )?;
    let authorization_ref = pre_fence_authorization_ref(
        verified_candidate.previous_state.clone(),
        verified_candidate.candidate_state,
        &request.ticket.principal_id,
        authority.did(),
    )?;

    let mut event = validate_fixed_event(&request, &authority, &authorization_ref)?;
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let dpop = DpopVerifier::verify_without_replay(
        &request.holder_proof.proof_jwt,
        "POST",
        &htu,
        now,
        None,
    )
    .map_err(|error| invalid_signature(error.to_string()))?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, &request.holder_proof.dpop_jkt)
        .map_err(|error| invalid_signature(error.to_string()))?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, &request.ticket.recovery_holder_jkt)
        .map_err(|error| invalid_signature(error.to_string()))?;
    if dpop.claims.nonce.as_deref() != Some(request.canonical_request_digest.as_str()) {
        return Err(invalid_signature(
            "holder proof nonce does not equal canonical_request_digest",
        ));
    }

    sign_event(
        &mut event,
        &authority.signer(),
        authority.verification_method(),
        SignEventOptions::new().with_created_at(now),
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let authorized_event_digest = Hash::new(
        event
            .event_digest()
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let authorization_lease = sign_authorization_lease(&request, &authority, now)?;
    let intent = &request
        .authorization_preimage
        .authorize_event_publication_intent;
    let outcome = AuthorizeRecoveryDeviceOutcome {
        ticket_id: request.ticket.ticket_id.clone(),
        transaction_id: request.ticket.transaction_id.clone(),
        authorize_event_id: request.ticket.authorize_event_id.clone(),
        authorized_event: serde_json::to_value(&event)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        authorized_event_digest,
        authorization_lease,
        cba_proof_bundles: intent.cba_proof_bundles.clone(),
        authority_receipt_id: ReceiptId::from_uuid(uuid::Uuid::now_v7()),
        accepted_at: now,
    };
    outcome
        .validate_against_request(&request)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let outcome_value = serde_json::to_value(&outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let jti_inserted = repo
        .dpop_replay()
        .consume_jti(dpop_replay_record(&dpop.claims.jti, now))
        .await?;
    if !jti_inserted {
        repo.cancel().await?;
        return replay_after_race(depot, &request, &canonical_request)
            .await
            .map(Json);
    }
    let inserted = repo
        .recovery_authority()
        .insert_authorization(NewRecoveryDeviceAuthorization {
            ticket_id: request.ticket.ticket_id.as_str().to_owned(),
            transaction_id: request.ticket.transaction_id.as_str().to_owned(),
            transaction_request_digest: request
                .ticket
                .transaction_request_digest
                .as_str()
                .to_owned(),
            did_entry_ref: request.ticket.did_entry_ref.as_str().to_owned(),
            did_entry_digest: request.ticket.did_entry_digest.as_str().to_owned(),
            authorization_ref,
            canonical_request: canonical_request.clone(),
            outcome: outcome_value,
            accepted_at: now,
        })
        .await?;
    if !inserted {
        repo.cancel().await?;
        return replay_after_race(depot, &request, &canonical_request)
            .await
            .map(Json);
    }
    repo.save().await?;
    Ok(Json(outcome))
}

fn exact_promotion_replay(
    record: coauth_data::RecoverySessionGrantPromotion,
    request: &PromoteRecoverySessionGrantRequest,
    canonical_request: &[u8],
) -> Result<PromoteRecoverySessionGrantOutcome, ArkretRouteError> {
    if record.transaction_id != request.transaction_id.as_str()
        || record.old_grant_id != request.old_grant_id
        || record.transaction_request_digest != request.transaction_request_digest.as_str()
        || record.canonical_request != canonical_request
    {
        return Err(duplicate_conflict(
            "recovery promotion identity was reused with different canonical request bytes",
        ));
    }
    serde_json::from_value(record.outcome).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "stored recovery promotion outcome is invalid: {error}"
        )))
    })
}

async fn verify_completion_attestation_signature(
    depot: &Depot,
    repo: &mut coauth_data::BoxRepository,
    attestation: &RecoveryCompletionAttestation,
    expected_coordinator: &str,
) -> Result<(), ArkretRouteError> {
    attestation
        .validate_structural()
        .map_err(|error| invalid_signature(error.to_string()))?;
    if attestation.coordinator_service_id.as_str() != expected_coordinator
        || verification_method_did(&attestation.auth_data.verification_method)
            != expected_coordinator
    {
        return Err(invalid_signature(
            "completion attestation signer does not equal the old grant audience",
        ));
    }
    let arkret_config = depot.arkret_config()?;
    let trusted_issuer = arkret_config
        .principal_servers
        .iter()
        .filter_map(|server| effective_audience(server, shared()))
        .any(|service_id| service_id.as_str() == expected_coordinator);
    if !trusted_issuer {
        return Err(invalid_signature(
            "completion attestation coordinator is not a configured Principal Server",
        ));
    }
    // §4 row 4 — recovery / continuity is an authority trigger and a
    // high-risk write, so the coordinator's key material must satisfy
    // `fresh_within(HIGH_RISK_MAX_AGE)` under the closed `Recovery` purpose.
    // Degraded / fallback / unproven-controller evidence maps to
    // `Stale` / `Quarantined` and fails closed inside `authority_document`,
    // replacing the previous `identity_fact_rejection` gate.
    let resolution = crate::services::did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &arkret_config,
        &depot.key_store()?,
        repo,
        depot.did_resolver_service()?.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        expected_coordinator,
        arkret_identity::DidBindingPurpose::Recovery,
        crate::services::did_binding::HIGH_RISK_MAX_AGE,
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|error| {
        invalid_signature(format!(
            "no fresh accepted recovery binding for the completion coordinator: {error}"
        ))
    })?;
    let method = resolution
        .document
        .verification_method
        .iter()
        .find(|method| method.id == attestation.auth_data.verification_method)
        .ok_or_else(|| {
            invalid_signature(
                "completion verification method is absent from coordinator DID document",
            )
        })?;
    let material = method.public_key_material().map_err(invalid_signature)?;
    let signing_bytes = attestation
        .signing_bytes()
        .map_err(|error| invalid_signature(error.to_string()))?;
    if !verify_detached_ed25519_signature(
        &material,
        &signing_bytes,
        &attestation.auth_data.signature,
    ) {
        return Err(invalid_signature(
            "recovery completion attestation signature did not verify",
        ));
    }
    Ok(())
}

fn validate_promotion_evidence(
    request: &PromoteRecoverySessionGrantRequest,
    prior_claims: &SignedSessionGrantClaims,
    old_grant: &coauth_data::SessionGrant,
) -> Result<RecoveryReceipt, ArkretRouteError> {
    let attestation = &request.completion_attestation;
    let recovery_binding = prior_claims.recovery_binding.as_ref().ok_or_else(|| {
        failed_precondition("old recovery grant is missing its typed recovery binding")
    })?;
    if prior_claims.grant_id != request.old_grant_id
        || prior_claims.credential_class != SessionGrantCredentialClass::RecoveryRestricted
        || prior_claims.device_binding.is_some()
        || prior_claims.subject != attestation.principal_id
        || prior_claims.audience != attestation.coordinator_service_id.as_str()
        || recovery_binding.recovery_session_id != attestation.recovery_session_id
        || old_grant.grant_id != request.old_grant_id
        || old_grant.subject != prior_claims.subject.as_str()
        || old_grant.audience != prior_claims.audience
        || old_grant.credential_class != "recovery_restricted"
        || old_grant.recovery_session_id.as_deref()
            != Some(recovery_binding.recovery_session_id.as_str())
        || old_grant.recovery_policy_id.as_deref() != Some(recovery_binding.policy_id.as_str())
        || old_grant.recovery_policy_version != Some(recovery_binding.policy_version as i64)
        || old_grant.device_authorization_event_id.is_some()
        || old_grant.model_generation_ref.is_some()
    {
        return Err(failed_precondition(
            "old grant, recovery binding and completion attestation disagree",
        ));
    }

    let receipt: RecoveryReceipt = serde_json::from_value(request.terminal_receipt.clone())
        .map_err(|error| failed_precondition(format!("terminal receipt is invalid: {error}")))?;
    receipt
        .validate()
        .map_err(|error| failed_precondition(error.to_string()))?;
    let receipt_bytes =
        arkret_canonical::canonical::canonical_json_bytes(&request.terminal_receipt)
            .map_err(|error| failed_precondition(error.to_string()))?;
    let receipt_digest = Hash::new(arkret_canonical::canonical::sha256_digest(&receipt_bytes))
        .map_err(|error| failed_precondition(error.to_string()))?;
    let receipt_generation = serde_json::to_value(&receipt.result_model_generation_ref)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let attested_generation = serde_json::to_value(&attestation.result_model_generation_ref)
        .map_err(|error| failed_precondition(error.to_string()))?;
    if receipt.outcome != RecoveryReceiptOutcome::Completed
        || receipt.receipt_id != attestation.terminal_receipt_id
        || receipt_digest != attestation.terminal_receipt_digest
        || receipt.transaction_id != attestation.transaction_id
        || receipt.transaction_request_digest != attestation.transaction_request_digest
        || receipt.prepared_plan_digest != attestation.prepared_plan_digest
        || receipt.principal_id != attestation.principal_id
        || receipt.recovery_session_id != attestation.recovery_session_id
        || receipt.policy_id != recovery_binding.policy_id
        || receipt.policy_version != recovery_binding.policy_version
        || receipt.new_device_id != attestation.replacement_device_id
        || receipt.authorization_event_id != attestation.device_authorization_event_id
        || receipt_generation != attested_generation
        || receipt.completed_at != attestation.completed_at
    {
        return Err(failed_precondition(
            "terminal receipt and coordinator completion attestation disagree",
        ));
    }
    Ok(receipt)
}

async fn replay_promotion_after_race(
    depot: &Depot,
    request: &PromoteRecoverySessionGrantRequest,
    canonical_request: &[u8],
) -> Result<PromoteRecoverySessionGrantOutcome, ArkretRouteError> {
    let mut repo = depot.repo().await?;
    let by_identity = {
        let mut promotions = repo.recovery_authority();
        promotions
            .lookup_promotion(request.transaction_id.as_str(), &request.old_grant_id)
            .await?
    };
    let record = match by_identity {
        Some(record) => Some(record),
        None => {
            let mut promotions = repo.recovery_authority();
            promotions
                .lookup_promotion_by_old_grant(&request.old_grant_id)
                .await?
        }
    };
    repo.cancel().await?;
    match record {
        Some(record) => exact_promotion_replay(record, request, canonical_request),
        None => Err(invalid_signature(
            "holder proof JTI or old grant was consumed without an accepted promotion",
        )),
    }
}

/// Consume one recovery-restricted grant and atomically persist its standard
/// device/current-generation-bound successor.
#[handler]
pub async fn promote_recovery_session_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PromoteRecoverySessionGrantOutcome>, ArkretRouteError> {
    let request: PromoteRecoverySessionGrantRequest = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    request
        .validate_structural()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let canonical_request = arkret_canonical::canonical::canonical_json_bytes(&request)
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;

    let mut repo = depot.repo().await?;
    let by_identity = {
        let mut promotions = repo.recovery_authority();
        promotions
            .lookup_promotion(request.transaction_id.as_str(), &request.old_grant_id)
            .await?
    };
    let existing = match by_identity {
        Some(record) => Some(record),
        None => {
            let mut promotions = repo.recovery_authority();
            promotions
                .lookup_promotion_by_old_grant(&request.old_grant_id)
                .await?
        }
    };
    if let Some(record) = existing {
        repo.cancel().await?;
        return exact_promotion_replay(record, &request, &canonical_request).map(Json);
    }

    let clock = crate::handlers::make_clock();
    let now = truncate_to_seconds(clock.now());
    let old_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_id(&request.old_grant_id)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
                "old recovery grant was not found",
            )
        })?;
    if !old_grant.is_active(&*clock) {
        return Err(failed_precondition(
            "old recovery grant is expired or already consumed",
        ));
    }
    let prior_jwt = Jwt::<SignedSessionGrantClaims>::try_from(old_grant.grant_jwt.as_str())
        .map_err(|error| failed_precondition(format!("stored old grant is invalid: {error}")))?;
    let prior_claims = prior_jwt.payload().clone();
    prior_claims
        .validate()
        .map_err(|error| failed_precondition(error.to_string()))?;
    let _receipt = validate_promotion_evidence(&request, &prior_claims, &old_grant)?;
    verify_completion_attestation_signature(
        depot,
        &mut repo,
        &request.completion_attestation,
        &old_grant.audience,
    )
    .await?;

    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let dpop = DpopVerifier::verify_without_replay(
        &request.holder_proof.proof_jwt,
        "POST",
        &htu,
        now,
        None,
    )
    .map_err(|error| invalid_signature(error.to_string()))?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, &request.holder_proof.dpop_jkt)
        .map_err(|error| invalid_signature(error.to_string()))?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, &prior_claims.cnf.jkt)
        .map_err(|error| invalid_signature(error.to_string()))?;
    if dpop.claims.nonce.as_deref() != Some(request.canonical_request_digest.as_str()) {
        return Err(invalid_signature(
            "holder proof nonce does not equal canonical_request_digest",
        ));
    }

    let jti_inserted = repo
        .dpop_replay()
        .consume_jti(dpop_replay_record(&dpop.claims.jti, now))
        .await?;
    if !jti_inserted {
        repo.cancel().await?;
        return replay_promotion_after_race(depot, &request, &canonical_request)
            .await
            .map(Json);
    }
    let consumed = repo
        .oauth_session_grant()
        .revoke_if_active(&*clock, old_grant.id)
        .await?;
    if !consumed {
        repo.cancel().await?;
        return replay_promotion_after_race(depot, &request, &canonical_request)
            .await
            .map(Json);
    }

    let device_binding = SessionGrantDeviceBinding {
        device_id: request.completion_attestation.replacement_device_id.clone(),
        authorization_event_id: request
            .completion_attestation
            .device_authorization_event_id
            .clone(),
        model_generation_ref: request
            .completion_attestation
            .result_model_generation_ref
            .clone(),
    };
    let material = mint_promoted_recovery_session_grant(
        &*clock,
        &depot.arkret_config()?,
        &depot.key_store()?,
        &prior_claims,
        old_grant.session_public_key.clone(),
        device_binding,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let mut rng = crate::handlers::make_rng();
    persist_session_grant_with_browser_session_id(
        &mut repo,
        &mut rng,
        &*clock,
        old_grant.browser_session_id,
        &material,
    )
    .await?;

    let new_grant = SessionGrantOutcome {
        principal_id: Did::new(material.subject.clone())
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        device_id: Some(
            DeviceId::new(material.device_id.clone().ok_or_else(|| {
                ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    "promoted grant omitted device id",
                ))
            })?)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        ),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        grant_id: Some(material.grant_id.clone()),
        session_public_key: Some(material.session_public_key.clone()),
        audience: Some(
            Did::new(material.audience.clone())
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        ),
        granted_scope: material.scopes.clone(),
        scope_details: None,
    };
    let outcome = PromoteRecoverySessionGrantOutcome {
        transaction_id: request.transaction_id.clone(),
        consumed_grant_id: request.old_grant_id.clone(),
        new_grant: serde_json::to_value(new_grant)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        consumed_at: now,
    };
    let outcome_value = serde_json::to_value(&outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let inserted = repo
        .recovery_authority()
        .insert_promotion(NewRecoverySessionGrantPromotion {
            transaction_id: request.transaction_id.as_str().to_owned(),
            old_grant_id: request.old_grant_id.clone(),
            transaction_request_digest: request.transaction_request_digest.as_str().to_owned(),
            recovery_session_id: request
                .completion_attestation
                .recovery_session_id
                .as_str()
                .to_owned(),
            replacement_device_id: request
                .completion_attestation
                .replacement_device_id
                .as_str()
                .to_owned(),
            device_authorization_event_id: request
                .completion_attestation
                .device_authorization_event_id
                .as_str()
                .to_owned(),
            model_generation_ref: serde_json::to_value(
                &request.completion_attestation.result_model_generation_ref,
            )
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            canonical_request: canonical_request.clone(),
            outcome: outcome_value,
            consumed_at: now,
        })
        .await?;
    if !inserted {
        repo.cancel().await?;
        return replay_promotion_after_race(depot, &request, &canonical_request)
            .await
            .map(Json);
    }
    repo.save().await?;
    Ok(Json(outcome))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn principal() -> arkret_identifiers::Did {
        arkret_identifiers::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap()
    }

    #[test]
    fn did_version_ref_is_exactly_bound_to_the_principal() {
        let principal = principal();
        assert_eq!(
            did_version_id(
                &principal,
                "did:webvh:z6mkfixture:alice.example?versionId=2-recovery"
            )
            .unwrap(),
            "2-recovery"
        );
        assert!(
            did_version_id(
                &principal,
                "did:webvh:z6mkfixture:alice.example?versionId=2-recovery&relativeRef=x"
            )
            .is_err()
        );
        assert!(
            did_version_id(
                &principal,
                "did:webvh:z6mkfixture:bob.example?versionId=2-recovery"
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_delegation_must_preserve_pre_fence_authority() {
        let principal = principal();
        let authority = "did:key:z6MkAuthority";
        let state = json!({
            "id": principal.as_str(),
            "service": [{
                "id": format!("{}#arkret-device-enrollment-authority", principal.as_str()),
                "type": "ArkretDeviceEnrollmentAuthority",
                "serviceEndpoint": authority
            }]
        });
        assert_eq!(
            pre_fence_authorization_ref(state.clone(), state, &principal, authority).unwrap(),
            format!("{}#arkret-device-enrollment-authority", principal.as_str())
        );
    }

    #[test]
    fn candidate_delegation_rejects_mixed_model_authority() {
        let principal = principal();
        let state = json!({
            "id": principal.as_str(),
            "capabilityDelegation": [
                format!("{}#self-enrollment", principal.as_str())
            ],
            "service": [{
                "id": format!("{}#arkret-device-enrollment-authority", principal.as_str()),
                "type": "ArkretDeviceEnrollmentAuthority",
                "serviceEndpoint": "did:key:z6MkOldAuthority"
            }]
        });
        assert!(enrollment_delegation(state, &principal).is_err());
    }

    #[test]
    fn candidate_only_delegation_cannot_create_pre_fence_authority() {
        let principal = principal();
        let previous = json!({"id": principal.as_str(), "service": []});
        let candidate = json!({
            "id": principal.as_str(),
            "service": [{
                "id": format!("{}#arkret-device-enrollment-authority", principal.as_str()),
                "type": "ArkretDeviceEnrollmentAuthority",
                "serviceEndpoint": "did:key:z6MkAuthority"
            }]
        });
        assert!(
            pre_fence_authorization_ref(previous, candidate, &principal, "did:key:z6MkAuthority")
                .is_err()
        );
    }
}
