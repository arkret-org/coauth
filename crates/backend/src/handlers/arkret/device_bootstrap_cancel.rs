//! Durable cancellation for a founding device-bootstrap transaction.

use arkret_models_collaboration::contact_operations::{
    BootstrapMode, BootstrapRetryableError, CancelDeviceBootstrapOutcome,
    CancelDeviceBootstrapRequestBody, DeviceBootstrapDecision,
    DeviceBootstrapDecisionRequestPreimage, RequestedDeviceBootstrapDecision,
};
use arkret_models_identity::{
    SessionGrantBootstrapBinding, SessionGrantCredentialClass, SignedSessionGrantClaims,
};
use coauth_data::RepositoryAccess as _;
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::device_enroll::bearer_token_from_request;
use super::{ArkretRouteError, service_id_for, trust_domain_for};
use crate::handlers::common::DepotExt;
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu, dpop_replay_record};
use crate::services::peer_protocol_client::{PeerProtocolClient, PeerProtocolClientError};

pub struct DeviceBootstrapCancelCanonicalJson {
    bytes: Vec<u8>,
    status: StatusCode,
}

impl DeviceBootstrapCancelCanonicalJson {
    fn success(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            status: StatusCode::OK,
        }
    }

    fn accepted_conflict(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            status: StatusCode::CONFLICT,
        }
    }
}

impl Scribe for DeviceBootstrapCancelCanonicalJson {
    fn render(self, response: &mut Response) {
        response.status_code(self.status);
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.bytes)
            .expect("canonical JSON response body is writable");
    }
}

fn pending_cancel_response(
    body: &CancelDeviceBootstrapRequestBody,
    retryable_error: BootstrapRetryableError,
) -> Result<DeviceBootstrapCancelCanonicalJson, ArkretRouteError> {
    let placeholder = arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let mut outcome = CancelDeviceBootstrapOutcome::Pending {
        transaction_id: body.transaction_id.clone(),
        retryable_error,
        retry_after_ms: Some(1000),
        outcome_digest: placeholder,
    };
    let digest = outcome
        .recompute_outcome_digest()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let CancelDeviceBootstrapOutcome::Pending { outcome_digest, .. } = &mut outcome else {
        unreachable!("constructed pending cancel outcome")
    };
    *outcome_digest = digest;
    outcome
        .validate_against(body)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    arkret_canonical::canonical_json_bytes(&outcome)
        .map(DeviceBootstrapCancelCanonicalJson::success)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

pub(crate) async fn verify_device_bootstrap_decision_evidence(
    depot: &Depot,
    request: arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
    outcome: arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionOutcome,
    expected_principal_server_id: &arkret_identifiers::Did,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<coauth_data::DeviceBootstrapDecisionEvidence, ArkretRouteError> {
    if outcome.receipt.principal_server_id != *expected_principal_server_id
        || outcome.receipt.decided_at > now + chrono::Duration::seconds(30)
    {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
            "Principal Server decision receipt identity or timestamp is invalid",
        ));
    }
    outcome.validate_against(&request).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
            error.to_string(),
        )
    })?;

    let http_client = depot.http_client()?;
    let authority_document = if expected_principal_server_id
        .as_str()
        .starts_with("did:webvh:")
    {
        crate::services::did_resolver::resolve_verified_webvh_document_at(
            &http_client,
            expected_principal_server_id,
            outcome.receipt.decided_at,
        )
        .await
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                error.to_string(),
            )
        })?
    } else {
        let mut repo = depot.repo().await?;
        let did_resolver = depot.did_resolver_service()?;
        let binding_store = depot.verified_did_binding_store()?;
        let authority = crate::services::did_binding::authority_document(
            &http_client,
            &depot.url_builder()?,
            &depot.arkret_config()?,
            &depot.key_store()?,
            &mut repo,
            did_resolver.as_ref(),
            binding_store.as_ref(),
            expected_principal_server_id.as_str(),
            arkret_identity::DidBindingPurpose::Issuer,
            crate::services::did_binding::high_risk_freshness(),
            now,
        )
        .await
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                error.to_string(),
            )
        })?;
        let document = authority.document;
        repo.save().await?;
        document
    };
    outcome
        .receipt
        .validate_proof_with(|verification_method, binding, detached_jws| {
            if !assertion_method_authorizes(&authority_document, verification_method.as_str()) {
                return Err(arkret_wire::WireError::Protocol(
                    "decision receipt key is not authorized for assertionMethod".to_owned(),
                ));
            }
            let verified = verify_detached_jws_with_sdk(
                detached_jws,
                binding,
                &authority_document.verification_method,
            )
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
            if verified != verification_method.as_str() {
                return Err(arkret_wire::WireError::Protocol(
                    "decision receipt verification method mismatch".to_owned(),
                ));
            }
            Ok(())
        })
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                error.to_string(),
            )
        })?;
    let canonical_receipt = arkret_canonical::canonical_json_bytes(&outcome.receipt)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    Ok(coauth_data::DeviceBootstrapDecisionEvidence {
        request,
        outcome,
        canonical_receipt,
    })
}

fn assertion_method_authorizes(document: &super::DidDocument, verification_method: &str) -> bool {
    document
        .assertion_method
        .iter()
        .any(|method| method == verification_method)
}

#[handler]
pub async fn cancel_device_bootstrap_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<DeviceBootstrapCancelCanonicalJson, ArkretRouteError> {
    let body: CancelDeviceBootstrapRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let cancel_request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let canonical_request = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let grant_jwt = bearer_token_from_request(req)?;
    let claims = Jwt::<SignedSessionGrantClaims>::try_from(grant_jwt.as_str())
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?
        .payload()
        .clone();
    claims
        .validate()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let (
        transaction_id,
        principal_id,
        device_id,
        device_key_digest,
        holder_jkt,
        bootstrap_request_digest,
        founding_event_ids,
        founding_batch_digest,
        bootstrap_transaction_expires_at,
    ) = match claims.bootstrap_binding.as_ref() {
        Some(SessionGrantBootstrapBinding::Founding {
            transaction_id,
            principal_id,
            device_id,
            device_key_digest,
            holder_jkt,
            canonical_request_digest,
            founding_event_ids,
            founding_batch_digest,
            bootstrap_transaction_expires_at,
            ..
        }) if founding_event_ids.len() == 2 => (
            transaction_id,
            principal_id,
            device_id,
            device_key_digest,
            holder_jkt,
            canonical_request_digest,
            founding_event_ids,
            founding_batch_digest,
            *bootstrap_transaction_expires_at,
        ),
        _ => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "cancel requires a founding device_bootstrap credential",
            ));
        }
    };
    if claims.credential_class != SessionGrantCredentialClass::DeviceBootstrap
        || body.mode != BootstrapMode::Founding
        || body.transaction_id.as_str() != transaction_id
        || body.canonical_request_digest != *bootstrap_request_digest
        || claims.cnf.jkt != *holder_jkt
    {
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
            "cancel request does not match the founding bootstrap credential",
        ));
    }

    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
            "device bootstrap cancel requires holder DPoP",
        )
    })?;
    let clock = crate::handlers::make_clock();
    let now = clock.now();
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let dpop = DpopVerifier::verify_without_replay(
        &dpop_header,
        req.method().as_str(),
        &htu,
        now,
        Some(&grant_jwt),
    )
    .map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, holder_jkt).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;

    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&grant_jwt)
        .await?
        .filter(|grant| grant.grant_id == claims.grant_id)
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
                "bootstrap grant is absent from the issuer ledger",
            )
        })?;
    if grant.subject != principal_id.as_str()
        || grant.device_id.as_deref() != Some(device_id.as_str())
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "bootstrap grant ledger binding mismatch",
        ));
    }
    let prior_cancel = {
        let mut handoff = repo.account_handoff();
        handoff
            .get_device_bootstrap_cancel_operation(&body.transaction_id, &body.idempotency_key)
            .await?
    };
    if let Some(operation) = prior_cancel.as_ref() {
        let exact_request = operation.canonical_request_digest == cancel_request_digest
            && operation.canonical_request == canonical_request;
        if !exact_request {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
                "cancel idempotency key was used with different request bytes",
            ));
        }
    }
    let transaction = {
        let mut handoff = repo.account_handoff();
        handoff
            .get_device_bootstrap_transaction(&body.transaction_id)
            .await?
    }
    .ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
            "device bootstrap transaction not found",
        )
    })?;
    let arkret_config = depot.arkret_config()?;
    let current_service_id = service_id_for(&arkret_config);
    let grant_audience_id = claims.audience.clone();
    if transaction.mode != body.mode
        || transaction.canonical_request_digest != body.canonical_request_digest
        || transaction.bootstrap_grant_id != grant.grant_id
        || transaction.founding_event_ids.as_slice() != founding_event_ids.as_slice()
        || transaction.founding_batch_digest != *founding_batch_digest
        || transaction.expires_at != bootstrap_transaction_expires_at
        || transaction.account_authority_id != current_service_id
        || transaction.principal_server_id != grant_audience_id
        || transaction.principal_id != *principal_id
        || transaction.device_id != *device_id
        || transaction.device_key_digest != *device_key_digest
        || transaction.holder_jkt != *holder_jkt
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
            "cancel request conflicts with the durable bootstrap transaction",
        ));
    }
    // Cancellation and expiry race with founding-batch acceptance in another
    // service. Only the Principal Server's durable decision fence can make
    // that race linearizable; a projection read is never negative evidence.
    let target = arkret_config
        .principal_servers
        .iter()
        .find_map(|server| {
            crate::services::resolved_principal_audiences::effective_audience_shared(server)
                .filter(|audience| audience.as_str() == claims.audience.as_str())
                .map(|audience| (server, audience))
        })
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
                "bootstrap grant audience is not a configured Principal Server",
            )
        })?;
    if target.1 != transaction.principal_server_id {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
            "configured Principal Server identity drifted from the durable bootstrap transaction",
        ));
    }
    if let Some(canonical_outcome) = prior_cancel
        .as_ref()
        .and_then(|operation| operation.canonical_outcome.clone())
    {
        repo.cancel().await.ok();
        let response =
            if transaction.state == coauth_data::DeviceBootstrapTransactionState::Accepted {
                DeviceBootstrapCancelCanonicalJson::accepted_conflict(canonical_outcome)
            } else {
                DeviceBootstrapCancelCanonicalJson::success(canonical_outcome)
            };
        return Ok(response);
    }

    let decision_request = if let Some(operation) = prior_cancel.as_ref() {
        operation.authority_request.clone()
    } else {
        let requested_decision = if transaction.expires_at <= now {
            RequestedDeviceBootstrapDecision::Expired
        } else {
            RequestedDeviceBootstrapDecision::Cancelled
        };
        DeviceBootstrapDecisionRequestPreimage {
            account_authority_id: transaction.account_authority_id.clone(),
            transaction_id: body.transaction_id.clone(),
            idempotency_key: body.idempotency_key.clone(),
            requested_decision,
            principal_id: transaction.principal_id.clone(),
            device_id: transaction.device_id.clone(),
            grant_id: transaction.bootstrap_grant_id.clone(),
            canonical_request_digest: transaction.canonical_request_digest.clone(),
            founding_event_ids: [
                transaction.founding_event_ids[0].clone(),
                transaction.founding_event_ids[1].clone(),
            ],
            founding_batch_digest: transaction.founding_batch_digest.clone(),
            bootstrap_transaction_expires_at: transaction.expires_at,
        }
        .finalize()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    };
    let canonical_authority_request = arkret_canonical::canonical_json_bytes(&decision_request)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let prepared = repo
        .account_handoff()
        .reserve_device_bootstrap_cancel(coauth_data::DeviceBootstrapCancelReserveInput {
            request: body.clone(),
            canonical_request_digest: cancel_request_digest.clone(),
            canonical_request: canonical_request.clone(),
            authority_request: decision_request,
            canonical_authority_request,
            now,
        })
        .await?;
    let operation = match prepared {
        coauth_data::DeviceBootstrapCancelReserve::Reserved(operation)
        | coauth_data::DeviceBootstrapCancelReserve::Replay(operation) => operation,
        coauth_data::DeviceBootstrapCancelReserve::Conflict => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
                "cancel idempotency key conflicts with a durable prepared request",
            ));
        }
        coauth_data::DeviceBootstrapCancelReserve::Terminal(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "device bootstrap transaction is already terminal",
            ));
        }
        coauth_data::DeviceBootstrapCancelReserve::NotFound => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                "device bootstrap transaction disappeared before cancel was prepared",
            ));
        }
    };
    if let Some(canonical_outcome) = operation.canonical_outcome {
        repo.cancel().await.ok();
        let response =
            if transaction.state == coauth_data::DeviceBootstrapTransactionState::Accepted {
                DeviceBootstrapCancelCanonicalJson::accepted_conflict(canonical_outcome)
            } else {
                DeviceBootstrapCancelCanonicalJson::success(canonical_outcome)
            };
        return Ok(response);
    }
    let decision_request = operation.authority_request;
    // The prepared Principal request is durable before crossing the service
    // boundary. Every retry reuses these exact canonical bytes and digest,
    // even when the local clock crosses the bootstrap deadline.
    repo.save().await?;
    let trust_domain = arkret_identifiers::TypedTrustDomainId::new(trust_domain_for(
        &depot.url_builder()?,
        &arkret_config,
    ))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let destination_service_id = target.1;
    let identity = arkret_models_crypto::http_bodies::PeerKeyPackagesClaimTransportBinding {
        source_service_id: decision_request.account_authority_id.clone(),
        destination_service_id: destination_service_id.clone(),
        source_trust_domain: trust_domain.clone(),
        destination_trust_domain: trust_domain,
    };
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let peer =
        PeerProtocolClient::new(Some(&target.0.endpoint), &http_client, &key_store, identity)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let authority_outcome = match peer.post_device_bootstrap_decision(&decision_request).await {
        Ok(outcome) => outcome,
        Err(PeerProtocolClientError::Status(409)) => {
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
                "Principal Server rejected a conflicting bootstrap decision intent",
            ));
        }
        Err(PeerProtocolClientError::Status(503)) => {
            return pending_cancel_response(&body, BootstrapRetryableError::DependencyPending);
        }
        Err(_) => {
            return pending_cancel_response(&body, BootstrapRetryableError::TemporarilyUnavailable);
        }
    };
    let authority_evidence = match verify_device_bootstrap_decision_evidence(
        depot,
        decision_request,
        authority_outcome,
        &destination_service_id,
        now,
    )
    .await
    {
        Ok(evidence) => evidence,
        Err(_) => {
            return pending_cancel_response(&body, BootstrapRetryableError::TemporarilyUnavailable);
        }
    };
    let authority_decision = authority_evidence.outcome.decision;
    let mut repo = depot.repo().await?;

    if !repo
        .dpop_replay()
        .consume_jti(dpop_replay_record(&dpop.claims.jti, now))
        .await?
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "DPoP JTI was already consumed",
        ));
    }
    let decision = match authority_decision {
        DeviceBootstrapDecision::Accepted => coauth_data::DeviceBootstrapCancelDecision::Accept,
        DeviceBootstrapDecision::Cancelled => coauth_data::DeviceBootstrapCancelDecision::Cancel,
        DeviceBootstrapDecision::Expired => coauth_data::DeviceBootstrapCancelDecision::Expire,
    };
    let committed = repo
        .account_handoff()
        .commit_device_bootstrap_cancel(coauth_data::DeviceBootstrapCancelInput {
            request: body,
            canonical_request_digest: cancel_request_digest,
            canonical_request,
            decision,
            authority: authority_evidence,
            now,
        })
        .await?;
    match committed {
        coauth_data::DeviceBootstrapCancelCommit::Committed { operation, .. }
        | coauth_data::DeviceBootstrapCancelCommit::Replay(operation) => {
            repo.save().await?;
            let canonical_outcome = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                    "durable cancel operation has no terminal outcome",
                )
            })?;
            Ok(if authority_decision == DeviceBootstrapDecision::Accepted {
                DeviceBootstrapCancelCanonicalJson::accepted_conflict(canonical_outcome)
            } else {
                DeviceBootstrapCancelCanonicalJson::success(canonical_outcome)
            })
        }
        _ => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
                "Principal and Account Authority bootstrap decisions conflict",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_dependency_response_is_closed_and_digest_bound() {
        let request = CancelDeviceBootstrapRequestBody {
            transaction_id: arkret_wire::ProtocolOpaqueId::new("bootstrap-test".to_owned())
                .unwrap(),
            mode: BootstrapMode::Founding,
            canonical_request_digest: arkret_identifiers::Hash::new(format!(
                "sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            idempotency_key: arkret_wire::IdempotencyKey::new("cancel-test".to_owned()).unwrap(),
        };
        let response =
            pending_cancel_response(&request, BootstrapRetryableError::DependencyPending).unwrap();
        let outcome: CancelDeviceBootstrapOutcome =
            serde_json::from_slice(&response.bytes).unwrap();
        outcome.validate_against(&request).unwrap();
        assert!(matches!(
            outcome,
            CancelDeviceBootstrapOutcome::Pending {
                retryable_error: BootstrapRetryableError::DependencyPending,
                retry_after_ms: Some(1000),
                ..
            }
        ));
    }

    #[test]
    fn decision_receipt_key_must_be_an_assertion_method() {
        let document: crate::handlers::arkret::DidDocument =
            serde_json::from_value(serde_json::json!({
            "id": "did:web:principal.example",
            "verificationMethod": [{
                "id": "did:web:principal.example#auth-only",
                "type": "JsonWebKey2020",
                "controller": "did:web:principal.example",
                "publicKeyJwk": {"kty":"OKP","crv":"Ed25519","x":"11qYAYdk9JtJ7w"}
            }],
            "authentication": ["did:web:principal.example#auth-only"],
            "assertionMethod": []
            }))
            .unwrap();
        assert!(!assertion_method_authorizes(
            &document,
            "did:web:principal.example#auth-only"
        ));
    }
}
