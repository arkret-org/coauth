//! Canonical account-first identity creation and binding.
use arkret_models_collaboration::account_lifecycle::{
    AccountRegisterOutcome, AccountRegisterRequestBody,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody;
use arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome;
use arkret_models_identity::{
    AccountBindingKind, AccountBindingReceipt, AccountBindingState, AccountHandoffAllowedOperation,
    DidOperationSubmitOutcome, DidOperationSubmitStatus, IdentityCreationOperationStatus,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_data::RepositoryAccess as _;
use coauth_data::account_handoff::{
    IdentityCreationBindingCommit, IdentityCreationRegisterReplay,
    IdentityCreationRegistrationContext, IdentityCreationSagaState,
};
use coauth_data::storage::user::BrowserSessionRepository as _;
use coauth_data::user::{
    PrincipalDidRepository as _, UserRepository as _, VerifiedPrincipalDidBindingInput,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::constraints::Constrainable as _;
use salvo::prelude::*;
use signature::RandomizedSigner as _;

use super::account_handoff::{
    authenticate_account_handoff, enforce_handoff_operation,
    verify_account_handoff_holder_without_lookup,
};
use super::session_grant::{
    SessionGrantIssuanceSeed, acquire_human_device_binding, issue_session_grant_for_audience,
    persist_session_grant,
};
use super::{
    ArkretRouteError, DepotExt, SessionGrantError, issuer_did_for, preferred_signing_key,
    service_id_for, trust_domain_for,
};
use crate::handlers::{make_clock, make_rng};
use crate::services::peer_protocol_client::{PeerProtocolClient, PeerProtocolClientError};
use crate::services::soland_webvh;

/// `POST /_arkret/gate/account/register` identity-creation branch.
#[handler]
pub async fn account_register_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AccountRegisterOutcome>, ArkretRouteError> {
    let (handoff_token, replay_dpop) = verify_account_handoff_holder_without_lookup(req, depot)?;
    let mut replay_repo = depot.repo().await?;
    let mut grant = replay_repo
        .account_handoff()
        .get_by_token(&handoff_token, chrono::Utc::now())
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::UNAUTHENTICATED,
                "account handoff is expired, revoked, or unknown",
            )
        })?;
    replay_repo.cancel().await.ok();
    if replay_dpop.jkt != grant.cnf_jkt {
        return Err(proof_invalid(
            "account handoff DPoP key does not match the credential cnf.jkt",
        ));
    }
    enforce_handoff_operation(&grant, AccountHandoffAllowedOperation::Register)?;

    let body: AccountRegisterRequestBody = req
        .parse_json()
        .await
        .map_err(|_| schema_violation("invalid account register body"))?;
    body.validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    if body.proof.is_some() {
        return Err(failed_precondition(
            "published-DID registration cannot establish a pair-bound local PCR lineage",
        ));
    }
    let identity_creation = body
        .identity_creation
        .as_ref()
        .ok_or_else(|| schema_violation("account handoff register requires identity_creation"))?;
    let request_digest = canonical_register_request_digest(&body)?;

    let mut repo = depot.repo().await?;
    let replay = repo
        .account_handoff()
        .registration_replay(
            &grant,
            &identity_creation.identity_creation_lease_id,
            identity_creation.lease_fence,
            &identity_creation.control_proof.challenge_id,
            &request_digest,
        )
        .await?;
    match replay {
        IdentityCreationRegisterReplay::Pending => {
            repo.cancel().await.ok();
            let (active_grant, _dpop) =
                authenticate_account_handoff(req, depot, AccountHandoffAllowedOperation::Register)
                    .await?;
            if active_grant.id != grant.id {
                return Err(proof_invalid(
                    "account handoff identity changed during replay check",
                ));
            }
            grant = active_grant;
        }
        IdentityCreationRegisterReplay::Replay(outcome) => {
            repo.cancel().await.ok();
            return Ok(Json(*outcome));
        }
        IdentityCreationRegisterReplay::DuplicateConflict => {
            repo.cancel().await.ok();
            return Err(duplicate_conflict(
                "identity-creation register request differs from the completed request",
            ));
        }
    }
    if body.device_id.is_some() {
        return Err(failed_precondition(
            "top-level device_id is not used by the atomic identity-creation flow",
        ));
    }
    if identity_creation.did_operation.did != body.full_id
        || identity_creation.control_proof.principal_id != body.principal_id
        || identity_creation.control_proof.full_id != body.full_id
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
            &identity_creation.identity_creation_lease_id,
            identity_creation.lease_fence,
            &identity_creation.control_proof.challenge_id,
            now,
        )
        .await?
        .ok_or_else(|| {
            failed_precondition(
                "reason_code=identity_creation_challenge_expired; lease, fence, reservation, or challenge is stale",
            )
        })?;
    repo.cancel().await.ok();

    identity_creation
        .validate()
        .map_err(|error| proof_invalid(error.to_string()))?;
    validate_registration_transcript(&context, identity_creation)?;
    let create_event = identity_creation.pcr_genesis_unit.create();
    if arkret_identifiers::RealmId::from_event_id(&create_event.event_id)
        != identity_creation.control_proof.pcr_realm_id
        || create_event.realm_id != identity_creation.control_proof.pcr_realm_id
    {
        return Err(proof_invalid(
            "PCR realm_id is not the root-signed create event_id retyped as a realm",
        ));
    }
    validate_initial_session_request(identity_creation, &grant)?;
    // Resolve the exact Principal Server once for the whole registration
    // transaction. The same service identity is the handoff/session audience,
    // the PCR submission target, and the server pinned by the resulting
    // PrincipalAuthorityKey.
    let principal_server = principal_server_target(depot, &grant.audience)?;
    let browser_session_id = grant.browser_session_id.ok_or_else(|| {
        failed_precondition("identity creation requires its originating browser session")
    })?;
    let mut prerequisite_repo = depot.repo().await?;
    let browser_session = prerequisite_repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or_else(|| failed_precondition("originating browser session no longer exists"))?;
    prerequisite_repo.cancel().await.ok();
    let key_store = depot.key_store()?;
    let (_, session_signing_key) = preferred_signing_key(&key_store)
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?;
    let session_signing_key_id = session_signing_key
        .kid()
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?
        .to_owned();
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
    arkret_signatures::webvh::verify_registration_did_evidence_draft(
        &identity_creation.did_operation,
        &identity_creation.registration_did_evidence_draft,
    )
    .map_err(|error| proof_invalid(error.to_string()))?;

    let (registry_outcome, registration_did_evidence) = match context.lease.state {
        IdentityCreationSagaState::Reserved => {
            let outcome = soland_webvh::submit_did_operation(
                &depot.http_client()?,
                &principal_server.endpoint,
                principal_server.bearer.as_deref(),
                &identity_creation.did_operation,
            )
            .await
            .map_err(|error| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
                    format!("principal registry rejected identity creation: {error}"),
                )
            })?;
            validate_registry_outcome(&outcome, &body.full_id)?;
            let registration_did_evidence = identity_creation
                .registration_did_evidence_draft
                .clone()
                .accept(outcome.accepted_at)
                .map_err(|error| proof_invalid(error.to_string()))?;
            let head = outcome.head_event_digest.as_ref().expect("validated head");
            let mut repo = depot.repo().await?;
            if !repo
                .account_handoff()
                .mark_did_published(&context, &outcome, head, &registration_did_evidence, now)
                .await?
            {
                repo.cancel().await.ok();
                return Err(failed_precondition(
                    "identity creation lost its lease or reservation fence",
                ));
            }
            repo.save().await?;
            (outcome, registration_did_evidence)
        }
        IdentityCreationSagaState::DidPublished
        | IdentityCreationSagaState::PcrAccepted
        | IdentityCreationSagaState::AccountBound => {
            let outcome: DidOperationSubmitOutcome =
                context.lease.registry_receipt.clone().ok_or_else(|| {
                    failed_precondition("published identity has no registry receipt")
                })?;
            validate_registry_outcome(&outcome, &body.full_id)?;
            let registration_did_evidence = context
                .lease
                .registration_did_evidence
                .clone()
                .ok_or_else(|| {
                    failed_precondition(
                        "published identity has no frozen registration DID evidence",
                    )
                })?;
            if registration_did_evidence.accepted_at != outcome.accepted_at {
                return Err(failed_precondition(
                    "frozen registration DID evidence does not carry the registry acceptance time",
                ));
            }
            let head = outcome.head_event_digest.as_ref().expect("validated head");
            if context.lease.state == IdentityCreationSagaState::DidPublished {
                let mut repo = depot.repo().await?;
                if !repo
                    .account_handoff()
                    .mark_did_published(&context, &outcome, head, &registration_did_evidence, now)
                    .await?
                {
                    repo.cancel().await.ok();
                    return Err(failed_precondition(
                        "published identity recovery lost its current fence",
                    ));
                }
                repo.save().await?;
            }
            (outcome, registration_did_evidence)
        }
        IdentityCreationSagaState::Active => {
            return Err(failed_precondition(
                "identity creation operation has not been reserved",
            ));
        }
        IdentityCreationSagaState::Completed => {
            return Err(failed_precondition(
                "reason_code=identity_creation_challenge_already_consumed; identity binding challenge was already consumed",
            ));
        }
    };

    let pcr_request = PcrGenesisSubmitRequestBody {
        account_authority_id: service_id_for(&depot.arkret_config()?),
        principal_id: body.principal_id.clone(),
        full_id: body.full_id.clone(),
        pcr_realm_id: identity_creation.control_proof.pcr_realm_id.clone(),
        idempotency_key: arkret_wire::IdempotencyKey::new(format!(
            "pcr-genesis:{}",
            request_digest.as_str()
        ))
        .map_err(schema_violation)?,
        registration_request_digest: request_digest.clone(),
        did_version_id: identity_creation.control_proof.did_version_id.clone(),
        log_head_digest: identity_creation.control_proof.log_head_digest.clone(),
        control_key_digest: identity_creation.control_proof.control_key_digest.clone(),
        registration_did_operation: identity_creation.did_operation.clone(),
        registration_did_evidence,
        identity_creation_control_proof: identity_creation.control_proof.clone(),
        genesis_unit: identity_creation.pcr_genesis_unit.clone(),
    };
    pcr_request
        .validate()
        .map_err(|error| proof_invalid(error.to_string()))?;
    let pcr_request_digest = pcr_request
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let pcr_outcome = if matches!(
        context.lease.state,
        IdentityCreationSagaState::Reserved | IdentityCreationSagaState::DidPublished
    ) {
        let config = depot.arkret_config()?;
        let trust_domain = arkret_identifiers::TypedTrustDomainId::new(trust_domain_for(
            &depot.url_builder()?,
            &config,
        ))
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        let http_client = depot.http_client()?;
        let key_store = depot.key_store()?;
        let peer = PeerProtocolClient::new(
            Some(&principal_server.endpoint),
            &http_client,
            &key_store,
            issuer_did_for(&config),
            arkret_models_crypto::http_bodies::PeerKeyPackagesClaimTransportBinding {
                source_service_id: service_id_for(&config).into(),
                destination_service_id: principal_server.service_id.clone().into(),
                source_trust_domain: trust_domain.clone(),
                destination_trust_domain: trust_domain,
            },
        )
        .map_err(map_peer_error)?;
        let outcome = peer
            .post_principal_genesis(&pcr_request)
            .await
            .map_err(map_peer_error)?;
        let mut repo = depot.repo().await?;
        if !repo
            .account_handoff()
            .mark_pcr_accepted(&context, &pcr_request_digest, &outcome, now)
            .await?
        {
            repo.cancel().await.ok();
            return Err(failed_precondition(
                "PCR genesis receipt could not be durably attached to this registration",
            ));
        }
        repo.save().await?;
        outcome
    } else {
        let outcome = context
            .lease
            .pcr_genesis_receipt
            .clone()
            .ok_or_else(|| failed_precondition("PCR-accepted saga has no durable receipt"))?;
        if context.lease.pcr_genesis_request_digest.as_ref() != Some(&pcr_request_digest) {
            return Err(duplicate_conflict(
                "PCR genesis request differs from the durable accepted request",
            ));
        }
        outcome
            .validate_against(&pcr_request)
            .map_err(|error| failed_precondition(error.to_string()))?;
        outcome
    };
    if pcr_outcome.receipt.issuer != principal_server.service_id {
        return Err(failed_precondition(
            "PCR genesis receipt issuer does not match the selected Principal Server",
        ));
    }
    let principal_authority = arkret_wire::PrincipalAuthorityKey::new(
        body.principal_id.clone(),
        principal_server.service_id.clone(),
    );

    let operation_status = match registry_outcome.status {
        DidOperationSubmitStatus::Accepted => IdentityCreationOperationStatus::Accepted,
        DidOperationSubmitStatus::Duplicate => IdentityCreationOperationStatus::Duplicate,
        _ => unreachable!("registry outcome validated above"),
    };
    let head_event_digest = registry_outcome
        .head_event_digest
        .clone()
        .expect("registry outcome head validated above");
    let mut receipt = AccountBindingReceipt {
        binding_state: AccountBindingState::Bound,
        binding_kind: AccountBindingKind::IdentityCreation,
        account_authority_id: service_id_for(&depot.arkret_config()?),
        account_subject: context.challenge.account_subject.clone(),
        principal_id: body.principal_id.clone(),
        full_id: body.full_id.clone(),
        did_version_id: identity_creation.control_proof.did_version_id.clone(),
        control_key_digest: identity_creation.control_proof.control_key_digest.clone(),
        identity_creation_lease_id: Some(identity_creation.identity_creation_lease_id.clone()),
        lease_fence: Some(identity_creation.lease_fence),
        operation_status,
        operation_digest: validated.operation_digest,
        head_event_digest: head_event_digest.clone(),
        issued_at: now,
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#{}",
                issuer_did_for(&depot.arkret_config()?),
                crate::services::service_identity::SERVICE_IDENTITY_VERIFICATION_METHOD_FRAGMENT
            ))
            .map_err(|error| {
                ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    error.to_owned(),
                ))
            })?,
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        },
    };
    sign_account_binding_receipt(&mut receipt, &key_store)?;
    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    if context.lease.state != IdentityCreationSagaState::AccountBound {
        if !repo
            .account_handoff()
            .mark_account_bound(&context, &receipt, now)
            .await?
        {
            repo.cancel().await.ok();
            return Err(failed_precondition(
                "PCR-accepted identity could not be atomically bound to the account",
            ));
        }
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
                if existing.principal_id == body.principal_id
                    && existing.key_log_head == head_event_digest => {}
            Some(_) => {
                repo.cancel().await.ok();
                return Err(duplicate_conflict(
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
                            audience: principal_server.service_id.clone(),
                            principal_id: body.principal_id.clone(),
                            key_log_head: head_event_digest,
                            verified_full_id: body.full_id.clone(),
                            verified_version_id: identity_creation
                                .control_proof
                                .did_version_id
                                .clone(),
                            binding_receipt: receipt.clone(),
                            accepted_service_id: principal_server.service_id.clone(),
                            binding_version: 1,
                            binding_frontier_digest: arkret_identifiers::Hash::new(
                                arkret_canonical::canonical_sha256(&receipt)
                                    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
                            )
                            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
                            principal_authority: principal_authority.clone(),
                        },
                    )
                    .await?;
            }
        }
        repo.save().await?;
        repo = depot.repo().await?;
    }

    let mut nonce = [0_u8; 32];
    rand_core::RngCore::fill_bytes(&mut *rng, &mut nonce);
    let issuance_seed = SessionGrantIssuanceSeed::new(
        arkret_models_identity::SessionGrantIssuanceNonce::from_bytes(nonce).to_string(),
        coauth_data::new_id(now, &mut *rng).to_string(),
        now,
        now + depot.arkret_config()?.session_grant_ttl,
        session_signing_key_id,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let initial = &identity_creation.initial_session;
    let session_public_key: coauth_jose::jwk::PublicJsonWebKey =
        serde_json::from_str(initial.session_public_key.as_str())
            .map_err(|error| proof_invalid(error.to_string()))?;
    let device_binding = acquire_human_device_binding(
        depot,
        &principal_authority,
        initial.device_id.clone(),
        arkret_wire::DeviceRevocationGateActionClass::SessionGrantIssue,
        None,
        request_digest.clone(),
        now,
    )
    .await?;
    let material = issue_session_grant_for_audience(
        &issuance_seed,
        &*clock,
        &depot.arkret_config()?,
        &key_store,
        &browser_session,
        session_public_key,
        initial.audience.to_string(),
        initial.device_id.clone(),
        initial.requested_scope_strings(),
        Some(body.principal_id.as_str()),
        &principal_authority,
        grant.cnf_jkt.clone(),
        device_binding,
        arkret_models_identity::SessionGrantProofKind::DidBoundSignature,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    persist_session_grant(&mut repo, &mut *rng, &*clock, &browser_session, &material).await?;
    let session_grant_outcome = SessionGrantOutcome {
        principal_id: body.principal_id.clone(),
        device_id: Some(initial.device_id.clone()),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        grant_id: material.grant_id.clone(),
        session_public_key: initial.session_public_key.clone(),
        audience: initial.audience.clone(),
        granted_scope: material.scopes.clone(),
        scope_details: None,
    };
    let outcome = AccountRegisterOutcome {
        principal_id: body.principal_id.clone(),
        state: AccountStatus::Active,
        devices: Vec::new(),
        primary_handle_claim: None,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
        registration_audit: None,
        binding_receipt: receipt,
        pcr_genesis_receipt: Some(pcr_outcome.receipt),
        session_grant_outcome: Some(session_grant_outcome),
    };
    outcome
        .validate_against_request(&body)
        .inspect_err(|error| {
            tracing::error!(%error, "identity-creation outcome validation failed");
        })
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let completion = repo
        .account_handoff()
        .mark_completed(&context, &request_digest, &outcome, now)
        .await?;
    let outcome = match completion {
        IdentityCreationBindingCommit::Committed => outcome,
        IdentityCreationBindingCommit::Replay(stored) => {
            repo.cancel().await.ok();
            return Ok(Json(*stored));
        }
        IdentityCreationBindingCommit::DuplicateConflict => {
            repo.cancel().await.ok();
            return Err(duplicate_conflict(
                "identity-creation register request lost a race to a different canonical request",
            ));
        }
        IdentityCreationBindingCommit::Stale => {
            repo.cancel().await.ok();
            return Err(failed_precondition(
                "account-bound identity could not commit its initial Standard grant",
            ));
        }
    };
    if !repo.account_handoff().consume_grant(&grant, now).await? {
        repo.cancel().await.ok();
        return Err(failed_precondition("account handoff was already consumed"));
    }
    repo.save().await?;
    Ok(Json(outcome))
}

fn validate_registration_transcript(
    context: &IdentityCreationRegistrationContext,
    registration: &arkret_models_identity::IdentityCreationRegistration,
) -> Result<(), ArkretRouteError> {
    let reserved = context
        .lease
        .reserved_identity
        .as_ref()
        .ok_or_else(|| failed_precondition("identity creation operation is not reserved"))?;
    let proof = &registration.control_proof;
    let challenge = &context.challenge;
    if challenge.account_subject != proof.account_subject {
        return Err(failed_precondition(
            "reason_code=account_binding_principal_mismatch; identity-creation proof changed the authenticated account subject",
        ));
    }
    if reserved.did_operation != registration.did_operation
        || arkret_identifiers::project_full_id_to_core_id(&registration.full_id)
            .map_err(|error| proof_invalid(error.to_string()))?
            != proof.principal_id
        || registration.full_id != proof.full_id
        || reserved.operation_digest != proof.operation_digest
        || challenge.challenge_id != proof.challenge_id
        || challenge.challenge != proof.challenge
        || challenge.purpose != proof.purpose
        || challenge.principal_id != proof.principal_id
        || challenge.full_id != proof.full_id
        || challenge.operation_digest != proof.operation_digest
        || challenge.did_version_id != proof.did_version_id
        || challenge.log_head_digest != proof.log_head_digest
        || challenge.control_key_digest != proof.control_key_digest
        || challenge.pcr_realm_id != proof.pcr_realm_id
        || challenge.realm_create_payload_digest != proof.realm_create_payload_digest
        || challenge.founding_authorize_payload_digest != proof.founding_authorize_payload_digest
        || challenge.initial_session_request_digest != proof.initial_session_request_digest
        || challenge.lease_id != proof.identity_creation_lease_id
        || challenge.lease_fence != proof.lease_fence
        || challenge.dpop_jkt != proof.dpop_jkt
        || challenge.audience != proof.audience
        || challenge.origin != proof.origin
        || challenge.trust_domain != proof.trust_domain
        || challenge.issued_at != proof.issued_at
        || challenge.expires_at != proof.expires_at
        || registration.identity_creation_lease_id != proof.identity_creation_lease_id
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

fn sign_account_binding_receipt(
    receipt: &mut AccountBindingReceipt,
    key_store: &coauth_keystore::Keystore,
) -> Result<(), ArkretRouteError> {
    let payload_digest = receipt
        .canonical_payload_digest()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    receipt.proof.payload_digest = payload_digest.clone();
    let payload = receipt
        .canonical_proof_binding_bytes()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let algorithm = JsonWebSignatureAlg::Ed25519;
    let header = coauth_jose::jwt::JsonWebSignatureHeader::new(algorithm)
        .with_kid(receipt.proof.verification_method.to_string());
    let protected =
        serde_json::to_vec(&header).map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let protected = Base64UrlUnpadded::encode_string(&protected);
    let payload = Base64UrlUnpadded::encode_string(&payload);
    let signing_input = format!("{protected}.{payload}");
    let signer = key_store
        .service_identity_signer()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let mut entropy = make_rng();
    let mut rng = crate::handlers::make_rng_from(&mut *entropy);
    let signature = signer
        .try_sign_with_rng(&mut rng, signing_input.as_bytes())
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let signature: Box<[u8]> = signature.into();
    receipt.proof.jws = format!(
        "{protected}..{}",
        Base64UrlUnpadded::encode_string(&signature)
    );
    receipt
        .validate_shape()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

fn canonical_register_request_digest(
    body: &AccountRegisterRequestBody,
) -> Result<arkret_identifiers::Hash, ArkretRouteError> {
    arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(body)
            .map_err(|_| schema_violation("account register body is not canonicalizable"))?,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

fn validate_registry_outcome(
    outcome: &DidOperationSubmitOutcome,
    full_id: &arkret_identifiers::DidFullId,
) -> Result<(), ArkretRouteError> {
    if outcome.did.as_str() != full_id.as_str()
        || !matches!(
            outcome.status,
            DidOperationSubmitStatus::Accepted | DidOperationSubmitStatus::Duplicate
        )
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
    service_id: arkret_identifiers::DidCoreId,
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
    let service_id =
        crate::services::resolved_principal_audiences::effective_audience_shared(server)
            .ok_or_else(|| {
                failed_precondition("principal server identity is unavailable or stale")
            })?;
    Ok(PrincipalServerTarget {
        endpoint: server.endpoint.clone(),
        service_id,
        bearer: server
            .embedded_webvh_registration_bearer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    })
}

fn validate_initial_session_request(
    registration: &arkret_models_identity::IdentityCreationRegistration,
    grant: &coauth_data::account_handoff::AccountHandoffGrant,
) -> Result<(), ArkretRouteError> {
    let initial = &registration.initial_session;
    if initial.audience.as_str() != grant.audience {
        return Err(failed_precondition(
            "initial SessionGrant audience does not match the account handoff audience",
        ));
    }
    initial
        .validate()
        .map_err(|error| failed_precondition(error.to_string()))?;
    let jkt = initial
        .session_public_key
        .thumbprint_sha256()
        .map_err(|error| proof_invalid(error.to_string()))?;
    if jkt != grant.cnf_jkt || jkt != registration.control_proof.dpop_jkt {
        return Err(proof_invalid(
            "initial SessionGrant key thumbprint does not match the authenticated holder",
        ));
    }
    Ok(())
}

fn map_peer_error(error: PeerProtocolClientError) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
        format!("principal server PCR genesis submission failed: {error}"),
    )
}

fn schema_violation(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        message,
    )
}

fn proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn failed_precondition(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        message,
    )
}

fn duplicate_conflict(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        message,
    )
}
