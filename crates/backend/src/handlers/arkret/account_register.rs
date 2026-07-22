//! Canonical account-first identity creation and binding.
use arkret_core::{
    AccountBindingReceipt, AccountBindingState, AccountHandoffAllowedOperation,
    AccountRegisterOutcome, AccountRegisterRequestBody, AccountStatus, DidOperationSubmitOutcome,
    IdentityCreationOperationStatus,
};
use coauth_data::RepositoryAccess as _;
use coauth_data::account_handoff::{
    IdentityCreationRegistrationContext, IdentityCreationSagaState,
};
use coauth_data::user::{
    PrincipalDidRepository as _, UserRepository as _, VerifiedPrincipalDidBindingInput,
};
use salvo::prelude::*;
use serde_json::Value;

use super::account_handoff::{authenticate_account_handoff, enforce_handoff_operation};
use super::{ArkretRouteError, DepotExt};
use crate::handlers::{make_clock, make_rng};
use crate::services::soland_webvh;

/// `POST /_arkret/gate/account/register` identity-creation branch.
#[handler]
pub async fn account_register_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AccountRegisterOutcome>, ArkretRouteError> {
    let (grant, _dpop) =
        authenticate_account_handoff(req, depot, AccountHandoffAllowedOperation::Register).await?;
    enforce_handoff_operation(&grant, AccountHandoffAllowedOperation::Register)?;

    let body: AccountRegisterRequestBody = req
        .parse_json()
        .await
        .map_err(|_| schema_violation("invalid account register body"))?;
    let identity_creation = body
        .identity_creation
        .as_ref()
        .ok_or_else(|| schema_violation("account handoff register requires identity_creation"))?;
    if body.proof.is_some() {
        return Err(schema_violation(
            "identity_creation and ordinary account lifecycle proof are mutually exclusive",
        ));
    }
    if body.device_id.is_some() {
        return Err(failed_precondition(
            "the founding device must be enrolled after the verified identity binding",
        ));
    }
    if identity_creation.did_operation.did != body.principal_id
        || identity_creation.control_proof.principal_id != body.principal_id
    {
        return Err(failed_precondition(
            "principal_id does not match the identity-creation operation and control proof",
        ));
    }

    let clock = make_clock();
    let now = clock.now();
    let mut repo = depot.repo().await?;
    let context = repo
        .account_handoff()
        .registration_context(
            &grant,
            &identity_creation.lease_id,
            identity_creation.lease_fence,
            &identity_creation.control_proof.challenge_id,
            now,
        )
        .await?
        .ok_or_else(|| {
            failed_precondition(
                "reason_code=challenge_expired; lease, fence, reservation, or challenge is stale",
            )
        })?;
    repo.cancel().await.ok();

    validate_registration_transcript(&context, identity_creation)?;
    let validated = arkret_signatures::webvh::verify_identity_creation_control_proof(
        &identity_creation.did_operation,
        &identity_creation.control_proof,
    )
    .map_err(|error| proof_invalid(error.to_string()))?;
    if validated.principal_id != body.principal_id {
        return Err(proof_invalid(
            "validated inception principal does not match the registration principal",
        ));
    }

    let registry_outcome = match context.lease.state {
        IdentityCreationSagaState::Reserved => {
            let target = principal_server_target(depot, &grant.audience)?;
            let outcome = soland_webvh::submit_did_operation(
                &depot.http_client()?,
                &target.endpoint,
                target.bearer.as_deref(),
                &identity_creation.did_operation,
            )
            .await
            .map_err(|error| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_core::error::ErrorCode::SERVICE_UNAVAILABLE,
                    format!("principal registry rejected identity creation: {error}"),
                )
            })?;
            validate_registry_outcome(&outcome, &body.principal_id)?;
            let head = outcome.head_event_digest.as_ref().expect("validated head");
            let receipt = serde_json::to_value(&outcome)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            let mut repo = depot.repo().await?;
            if !repo
                .account_handoff()
                .mark_published(&context, &receipt, head, now)
                .await?
            {
                repo.cancel().await.ok();
                return Err(failed_precondition(
                    "identity creation lost its lease or reservation fence",
                ));
            }
            repo.save().await?;
            outcome
        }
        IdentityCreationSagaState::Published => {
            let outcome: DidOperationSubmitOutcome =
                serde_json::from_value(context.lease.registry_receipt.clone().ok_or_else(
                    || failed_precondition("published identity has no registry receipt"),
                )?)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            validate_registry_outcome(&outcome, &body.principal_id)?;
            let head = outcome.head_event_digest.as_ref().expect("validated head");
            let receipt = serde_json::to_value(&outcome)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            let mut repo = depot.repo().await?;
            if !repo
                .account_handoff()
                .mark_published(&context, &receipt, head, now)
                .await?
            {
                repo.cancel().await.ok();
                return Err(failed_precondition(
                    "published identity recovery lost its current fence",
                ));
            }
            repo.save().await?;
            outcome
        }
        IdentityCreationSagaState::Active => {
            return Err(failed_precondition(
                "identity creation operation has not been reserved",
            ));
        }
        IdentityCreationSagaState::Bound => {
            return Err(failed_precondition(
                "identity binding challenge was already consumed",
            ));
        }
    };

    let operation_status = match registry_outcome.status.as_str() {
        "accepted" => IdentityCreationOperationStatus::Accepted,
        "duplicate" => IdentityCreationOperationStatus::Duplicate,
        _ => unreachable!("registry outcome validated above"),
    };
    let head_event_digest = registry_outcome
        .head_event_digest
        .clone()
        .expect("registry outcome head validated above");
    let receipt = AccountBindingReceipt {
        binding_state: AccountBindingState::Bound,
        lease_id: identity_creation.lease_id.clone(),
        lease_fence: identity_creation.lease_fence,
        operation_status,
        operation_digest: validated.operation_digest,
        head_event_digest: head_event_digest.clone(),
    };

    let key_store = depot.key_store()?;
    let enrollment_authority =
        crate::services::device_enrollment_authority::enrollment_authority(&key_store)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let enrollment_authority_ref = inception_enrollment_authority_ref(
        body.principal_id.as_str(),
        &identity_creation.did_operation.operation,
        enrollment_authority.did(),
    )
    .ok_or_else(|| failed_precondition("invalid enrollment authority service reference"))?;
    let enrollment_authority_did = arkret_core::Did::new(enrollment_authority.did().to_owned())
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    let user = repo
        .user()
        .lookup(grant.service_account_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    let existing_binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, &grant.audience)
        .await?;
    match existing_binding {
        Some(existing)
            if existing.principal_id == body.principal_id.as_str()
                && existing.key_log_head == head_event_digest
                && existing.enrollment_authority_did == enrollment_authority_did
                && existing.enrollment_authority_ref == enrollment_authority_ref => {}
        Some(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_core::error::ErrorCode::DUPLICATE_CONFLICT,
                "service account already has a different verified principal binding",
            ));
        }
        None => {
            repo.principal_did()
                .add_verified(
                    &mut *rng,
                    &*clock,
                    &user,
                    VerifiedPrincipalDidBindingInput {
                        audience: grant.audience.clone(),
                        principal_id: body.principal_id.to_string(),
                        key_log_head: head_event_digest,
                        enrollment_authority_did,
                        enrollment_authority_ref,
                    },
                )
                .await?;
        }
    }
    if !repo
        .account_handoff()
        .mark_bound(&context, &receipt, now)
        .await?
    {
        repo.cancel().await.ok();
        return Err(failed_precondition(
            "published identity could not be atomically finalized as bound",
        ));
    }
    repo.save().await?;

    Ok(Json(AccountRegisterOutcome {
        principal_id: body.principal_id,
        state: AccountStatus::Active,
        devices: Vec::new(),
        primary_handle_claim: None,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
        registration_audit: None,
        binding_receipt: Some(receipt),
    }))
}

fn validate_registration_transcript(
    context: &IdentityCreationRegistrationContext,
    registration: &arkret_core::IdentityCreationRegistration,
) -> Result<(), ArkretRouteError> {
    let reserved = context
        .lease
        .reserved_identity
        .as_ref()
        .ok_or_else(|| failed_precondition("identity creation operation is not reserved"))?;
    let proof = &registration.control_proof;
    let challenge = &context.challenge;
    if reserved.did_operation != registration.did_operation
        || reserved.principal_id != proof.principal_id
        || reserved.operation_digest != proof.operation_digest
        || challenge.challenge_id != proof.challenge_id
        || challenge.challenge != proof.challenge
        || challenge.purpose != proof.purpose
        || challenge.principal_id != proof.principal_id
        || challenge.operation_digest != proof.operation_digest
        || challenge.lease_id != proof.lease_id
        || challenge.lease_fence != proof.lease_fence
        || challenge.dpop_jkt != proof.dpop_jkt
        || challenge.audience != proof.audience
        || challenge.origin != proof.origin
        || challenge.trust_domain != proof.trust_domain
        || challenge.issued_at != proof.issued_at
        || challenge.expires_at != proof.expires_at
        || registration.lease_id != proof.lease_id
        || registration.lease_fence != proof.lease_fence
    {
        return Err(proof_invalid(
            "identity-creation control proof does not exactly replay the durable challenge transcript",
        ));
    }
    if proof.expires_at - proof.issued_at > chrono::Duration::minutes(5) {
        return Err(proof_invalid(
            "identity-creation challenge exceeds the 300 second freshness ceiling",
        ));
    }
    Ok(())
}

fn validate_registry_outcome(
    outcome: &DidOperationSubmitOutcome,
    principal_id: &arkret_core::Did,
) -> Result<(), ArkretRouteError> {
    if outcome.did != *principal_id
        || !matches!(outcome.status.as_str(), "accepted" | "duplicate")
        || outcome.seq != Some(1)
        || outcome.head_event_digest.is_none()
    {
        return Err(failed_precondition(
            "identity registry outcome does not verify the exact accepted inception",
        ));
    }
    Ok(())
}

struct PrincipalServerTarget {
    endpoint: url::Url,
    bearer: Option<String>,
}

fn principal_server_target(
    depot: &Depot,
    audience: &str,
) -> Result<PrincipalServerTarget, ArkretRouteError> {
    let config = depot.arkret_config()?;
    let server = config
        .principal_servers
        .iter()
        .find(|server| {
            crate::services::resolved_principal_audiences::effective_audience_shared(server)
                .as_ref()
                .is_some_and(|candidate| candidate.as_str() == audience)
        })
        .ok_or_else(|| {
            failed_precondition("handoff audience has no configured principal server")
        })?;
    Ok(PrincipalServerTarget {
        endpoint: server.endpoint.clone(),
        bearer: server
            .embedded_webvh_registration_bearer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    })
}

fn inception_enrollment_authority_ref(
    principal_id: &str,
    operation: &std::collections::BTreeMap<String, Value>,
    authority_did: &str,
) -> Option<String> {
    let document = operation.get("state")?;
    if document.get("capabilityDelegation").is_some() {
        return None;
    }
    let mut designated = document
        .get("service")?
        .as_array()?
        .iter()
        .filter(|service| {
            service.get("type").and_then(Value::as_str)
                == Some(arkret_models_discovery::service_requirements::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
        });
    let service = designated.next()?;
    if designated.next().is_some()
        || service.get("serviceEndpoint").and_then(Value::as_str) != Some(authority_did)
    {
        return None;
    }
    let reference = service.get("id").and_then(Value::as_str)?;
    let reference = if reference.starts_with('#') {
        format!("{principal_id}{reference}")
    } else {
        reference.to_owned()
    };
    arkret_core::DidUrl::new(reference.clone()).ok()?;
    reference
        .strip_prefix(principal_id)
        .is_some_and(|fragment| fragment.starts_with('#') && fragment.len() > 1)
        .then_some(reference)
}

fn schema_violation(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_core::error::ErrorCode::SCHEMA_VIOLATION,
        message,
    )
}

fn proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_core::error::ErrorCode::INVALID_SIGNATURE,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn failed_precondition(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_core::error::ErrorCode::FAILED_PRECONDITION,
        message,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, TimeZone as _, Utc};
    use coauth_data::account_handoff::{
        AccountHandoffGrant, IdentityBindingChallengeRecord, IdentityCreationLeaseRecord,
    };
    use coauth_data::{IdentityCreationSagaState, new_id};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    fn transcript_fixture() -> (
        IdentityCreationRegistrationContext,
        arkret_core::IdentityCreationRegistration,
    ) {
        let now = Utc.with_ymd_and_hms(2026, 7, 19, 0, 0, 0).unwrap();
        let mut rng = ChaChaRng::seed_from_u64(0x7a11_5c21);
        let service_account_id = new_id(now, &mut rng);
        let did = arkret_core::Did::new("did:webvh:zfixture:principal.example").unwrap();
        let operation = arkret_core::DidOperationSubmitRequestBody {
            did: did.clone(),
            did_method: "webvh".to_owned(),
            seq: Some(0),
            prev_event_digest: None,
            operation: BTreeMap::from([(
                "state".to_owned(),
                serde_json::json!({ "id": did.as_str() }),
            )]),
        };
        let reserved =
            arkret_core::ReservedIdentityCreation::from_operation(operation.clone()).unwrap();
        let request_id =
            arkret_core::RequestId::new("ak:request:019b0000-0000-7000-8000-000000000071").unwrap();
        let request_digest = arkret_core::Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap();
        let audience = arkret_core::Did::new("did:web:principal.example").unwrap();
        let trust_domain =
            arkret_core::TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap();
        let lease_id = "D".repeat(32);
        let holder_jkt = "A".repeat(43);
        let challenge_id = "E".repeat(32);
        let challenge_value = "F".repeat(43);
        let expires_at = now + Duration::minutes(5);
        let challenge = IdentityBindingChallengeRecord {
            request_id: request_id.clone(),
            request_digest: request_digest.clone(),
            service_account_id,
            challenge_id: challenge_id.clone(),
            challenge: challenge_value.clone(),
            purpose: arkret_core::IdentityBindingPurpose::AccountBinding,
            principal_id: did.clone(),
            operation_digest: reserved.operation_digest.clone(),
            lease_id: lease_id.clone(),
            lease_fence: 4,
            dpop_jkt: holder_jkt.clone(),
            audience: audience.clone(),
            origin: "https://account.example".to_owned(),
            trust_domain: trust_domain.clone(),
            issued_at: now,
            expires_at,
            consumed_at: None,
            replaced_at: None,
        };
        let grant = AccountHandoffGrant {
            id: new_id(now, &mut rng),
            request_id,
            request_digest,
            service_account_id,
            browser_session_id: None,
            audience: audience.to_string(),
            cnf_jkt: holder_jkt.clone(),
            allowed_operations: arkret_core::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            account_handoff_grant: "G".repeat(43),
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            revoked_at: None,
            consumed_at: None,
        };
        let lease = IdentityCreationLeaseRecord {
            service_account_id,
            audience: audience.to_string(),
            lease_id: lease_id.clone(),
            holder_jkt,
            fence: 4,
            expires_at: now + Duration::minutes(15),
            reserved_identity: Some(reserved.clone()),
            state: IdentityCreationSagaState::Reserved,
            registry_receipt: None,
            head_event_digest: None,
            binding_receipt: None,
            created_at: now,
            updated_at: now,
        };
        let registration = arkret_core::IdentityCreationRegistration {
            lease_id,
            lease_fence: 4,
            did_operation: operation,
            control_proof: arkret_core::IdentityCreationControlProof {
                proof_kind:
                    arkret_core::IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
                challenge_id,
                challenge: challenge_value,
                purpose: arkret_core::IdentityBindingPurpose::AccountBinding,
                principal_id: did,
                operation_digest: reserved.operation_digest,
                lease_id: challenge.lease_id.clone(),
                lease_fence: challenge.lease_fence,
                dpop_jkt: challenge.dpop_jkt.clone(),
                audience,
                origin: challenge.origin.clone(),
                trust_domain,
                issued_at: now,
                expires_at,
                verification_key_multibase: "z6Mkfixture".to_owned(),
                signature: "fixture-signature".to_owned(),
            },
        };
        (
            IdentityCreationRegistrationContext {
                grant,
                lease,
                challenge,
            },
            registration,
        )
    }

    #[test]
    fn registration_transcript_rejects_cross_boundary_replay_fields() {
        let (context, registration) = transcript_fixture();
        validate_registration_transcript(&context, &registration).unwrap();

        let mut cross_audience = registration.clone();
        cross_audience.control_proof.audience =
            arkret_core::Did::new("did:web:other.example").unwrap();
        assert!(validate_registration_transcript(&context, &cross_audience).is_err());

        let mut cross_origin = registration.clone();
        cross_origin.control_proof.origin = "https://other.example".to_owned();
        assert!(validate_registration_transcript(&context, &cross_origin).is_err());

        let mut cross_trust_domain = registration.clone();
        cross_trust_domain.control_proof.trust_domain =
            arkret_core::TypedTrustDomainId::new("ak:trust_domain:other.example").unwrap();
        assert!(validate_registration_transcript(&context, &cross_trust_domain).is_err());

        let mut stale_fence = registration.clone();
        stale_fence.control_proof.lease_fence += 1;
        assert!(validate_registration_transcript(&context, &stale_fence).is_err());
    }

    #[test]
    fn registration_transcript_rejects_freshness_windows_over_300_seconds() {
        let (mut context, mut registration) = transcript_fixture();
        let oversized_expiry = context.challenge.issued_at + Duration::seconds(301);
        context.challenge.expires_at = oversized_expiry;
        registration.control_proof.expires_at = oversized_expiry;

        assert!(validate_registration_transcript(&context, &registration).is_err());
    }
}
