//! Transaction-bound B-model recovery device authorization.

use arkret_identifiers::{Hash, ReceiptId};
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use arkret_signatures::{SignEventOptions, sign_event};
use arkret_wire::{
    AuthorizeRecoveryDeviceOutcome, AuthorizeRecoveryDeviceRequest, Event, EventKind, ScopeRef,
    ServiceSignatureAlgorithm,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::{NewRecoveryDeviceAuthorization, RepositoryAccess as _};
use salvo::prelude::*;

use super::device_enroll::{decode_device_public_key, truncate_to_seconds};
use super::{ArkretRouteError, service_id_for};
use crate::handlers::common::DepotExt;
use crate::services::device_enrollment_authority::enrollment_authority;
use crate::services::did_resolver::{DidResolveError, verify_unpublished_webvh_candidate};
use crate::services::dpop::{DpopVerifier, dpop_htu, dpop_replay_record};
use crate::services::resolved_principal_audiences::{effective_audience, shared};

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

fn candidate_authorization_ref(
    state: serde_json::Value,
    principal_id: &arkret_identifiers::Did,
    authority_did: &str,
) -> Result<String, ArkretRouteError> {
    let document: super::DidDocument = serde_json::from_value(state).map_err(|error| {
        failed_precondition(format!(
            "candidate DID entry state is not a valid DID document: {error}"
        ))
    })?;
    if document.id != principal_id.as_str() || !document.capability_delegation.is_empty() {
        return Err(failed_precondition(
            "candidate DID document is not the transaction principal's B-model document",
        ));
    }
    let mut delegations = document
        .service
        .iter()
        .filter(|service| service.kind == "ArkretDeviceEnrollmentAuthority");
    let delegation = delegations.next().ok_or_else(|| {
        failed_precondition(
            "candidate DID document omits ArkretDeviceEnrollmentAuthority delegation",
        )
    })?;
    if delegations.next().is_some()
        || delegation.service_endpoint != authority_did
        || !delegation
            .id
            .strip_prefix(principal_id.as_str())
            .is_some_and(|fragment| fragment.starts_with('#') && fragment.len() > 1)
    {
        return Err(failed_precondition(
            "candidate DID document enrollment delegation is ambiguous or targets another authority",
        ));
    }
    Ok(delegation.id.clone())
}

async fn verify_ticket_signature(
    req: &Request,
    depot: &Depot,
    repo: &mut coauth_data::BoxRepository,
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
    let trusted_issuer = arkret_config
        .principal_servers
        .iter()
        .filter_map(|server| effective_audience(server, shared()))
        .any(|service_id| service_id == ticket.principal_server_id);
    if !trusted_issuer {
        return Err(invalid_signature(
            "ticket principal_server_id is not a configured Principal Server",
        ));
    }

    let resolution = depot
        .did_resolver_service()?
        .resolve_did_document(
            &depot.http_client()?,
            &depot.url_builder()?,
            &arkret_config,
            &depot.key_store()?,
            repo,
            ticket.principal_server_id.as_str(),
        )
        .await
        .map_err(super::map_did_resolve_error)?;
    if let Some(rejection) = resolution.identity_fact_rejection() {
        return Err(invalid_signature(format!(
            "ticket issuer resolution is not a full identity fact: {}",
            rejection.as_str()
        )));
    }
    let method = resolution
        .document
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
        .map(|value| value.as_str())
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
    let candidate_state = verify_unpublished_webvh_candidate(
        &depot.http_client()?,
        &request.ticket.principal_id,
        previous_version_id,
        &candidate_entry_bytes,
        candidate_version_id,
    )
    .await
    .map_err(|error| match error {
        DidResolveError::BadResolverResponse(message) => failed_precondition(message),
        other => super::map_did_resolve_error(other),
    })?;
    let authorization_ref = candidate_authorization_ref(
        candidate_state,
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
    let outcome = AuthorizeRecoveryDeviceOutcome {
        ticket_id: request.ticket.ticket_id.clone(),
        transaction_id: request.ticket.transaction_id.clone(),
        authorize_event_id: request.ticket.authorize_event_id.clone(),
        authorized_event: serde_json::to_value(&event)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        authorized_event_digest,
        authority_receipt_id: ReceiptId::from_uuid(uuid::Uuid::now_v7()),
        accepted_at: now,
    };
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
    fn candidate_delegation_must_be_unique_and_target_this_authority() {
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
            candidate_authorization_ref(state, &principal, authority).unwrap(),
            format!("{}#arkret-device-enrollment-authority", principal.as_str())
        );
    }

    #[test]
    fn candidate_delegation_rejects_old_or_mixed_model_authority() {
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
        assert!(
            candidate_authorization_ref(state, &principal, "did:key:z6MkNewAuthority").is_err()
        );
    }
}
