//! Standard SessionGrant issuance after trusted root-anchored recovery completion.

use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_collaboration::session_grants::SessionGrantOutcome;
use arkret_models_crypto::{RecoveryReceipt, RecoveryReceiptOutcome};
use arkret_models_identity::{
    AccountHandoffAllowedOperation, InitialSessionGrantIntent,
    STANDARD_INITIAL_SESSION_GRANT_OPERATIONS, SessionGrantProofKind,
};
use arkret_signatures::proof::verify_detached_ed25519_signature;
use arkret_wire::{IssueRecoveryCompletionGrantOutcome, IssueRecoveryCompletionGrantRequest};
use chrono::{Duration, Timelike as _, Utc};
use coauth_data::storage::user::BrowserSessionRepository as _;
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{
    NewRecoveryCompletionGrantIssuance, NewSessionGrantOperation, RepositoryAccess as _,
    SessionGrantCommitOutcome, SessionGrantExactOutcome, SessionGrantProofAuthorization,
    SessionGrantReserveOutcome, UserPatch,
};
use coauth_jose::constraints::Constrainable as _;
use salvo::prelude::*;
use sha2::Digest as _;

use super::ArkretRouteError;
use super::account_handoff::{
    authenticate_account_handoff, enforce_handoff_operation,
    verify_account_handoff_holder_without_lookup,
};
use super::canonical_response::ArkretCanonicalJson;
use super::session_grant::{
    SessionGrantIssuanceSeed, acquire_private_current_device_binding,
    issue_session_grant_for_audience, new_session_grant_record,
};
use crate::handlers::common::DepotExt;
use crate::services::account_status_publication::{
    author_and_enqueue_transition, validate_transition_plan,
};
use crate::services::station_trust::{effective_audience, shared};

/// `POST /_arkret/gate/account/recovery-session-grants/issue`.
///
/// A still-valid, Bound account handoff authenticates the account and the new
/// session key. The handoff audience Station proves that root
/// re-anchor and replacement-device authorization completed. Coauth then
/// issues a fresh Standard grant directly; there is no restricted predecessor
/// credential or cross-service recovery-coordinator authority.
#[handler]
pub async fn issue_recovery_completion_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let request: IssueRecoveryCompletionGrantRequest = req
        .parse_json()
        .await
        .map_err(|_| schema_violation("invalid recovery completion grant request"))?;
    request
        .validate_structural()
        .map_err(|error| schema_violation(error.to_string()))?;
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| schema_violation(error.to_string()))?;

    // Exact replay remains available after the successful call consumed the
    // handoff. Possession is re-proved with a fresh HTTP DPoP JTI before any
    // stored bytes are disclosed.
    let (handoff_token, replay_dpop) = verify_account_handoff_holder_without_lookup(req, depot)?;
    let now = truncate_to_seconds(crate::handlers::make_clock().now());
    let mut replay_repo = depot.repo().await?;
    let replay_grant = replay_repo
        .account_handoff()
        .get_by_token(&handoff_token, now)
        .await?
        .ok_or_else(unauthenticated_handoff)?;
    enforce_handoff_operation(
        &replay_grant,
        AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
    )?;
    if replay_dpop.jkt != replay_grant.cnf_jkt {
        replay_repo.cancel().await.ok();
        return Err(signature_invalid(
            "account handoff DPoP key does not match the credential cnf.jkt",
        ));
    }
    let prior = replay_repo
        .recovery_authority()
        .lookup_completion_issuance(request.transaction_id.as_str())
        .await?;
    replay_repo.cancel().await.ok();
    if let Some(prior) = prior {
        return exact_replay(
            prior,
            &request,
            &canonical_request,
            replay_grant.local_account_id,
        );
    }

    // A new issuance must use an active handoff; this call also consumes the
    // HTTP DPoP JTI. The handoff row itself is consumed in the final database
    // transaction together with the issuer ledger and replay record.
    let (handoff, dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
    )
    .await?;
    if handoff.id != replay_grant.id || dpop.jkt != handoff.cnf_jkt {
        return Err(signature_invalid(
            "account handoff identity changed during recovery completion issuance",
        ));
    }

    let initial: InitialSessionGrantIntent =
        serde_json::from_value(request.initial_session.clone())
            .map_err(|error| schema_violation(format!("initial_session is invalid: {error}")))?;
    initial
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    let receipt: RecoveryReceipt = serde_json::from_value(request.terminal_receipt.clone())
        .map_err(|error| failed_precondition(format!("terminal receipt is invalid: {error}")))?;
    receipt
        .validate()
        .map_err(|error| failed_precondition(error.to_string()))?;
    validate_completion_evidence(&request, &receipt, &initial, &handoff, &dpop.jkt)?;

    let mut prerequisite_repo = depot.repo().await?;
    let principal_binding = verify_account_principal_binding(
        &mut prerequisite_repo,
        handoff.local_account_id,
        &handoff.audience_id,
        receipt.account_id.principal_id.as_str(),
    )
    .await?;
    let account_id = principal_binding.account_id.clone();
    if receipt.account_id != account_id {
        prerequisite_repo.cancel().await.ok();
        return Err(signature_invalid(
            "terminal receipt account_id does not match the accepted AccountHandoff binding",
        ));
    }
    // The consecutive commit pair must sit in the Principal Control Realm this
    // exact account binding was installed under. A structurally valid pair from
    // any other Realm stream is a different authority and must not mint a
    // Standard grant for this account.
    if commit_pair_realm(&request.completion_attestation.reanchor_event_ref)
        != Some(&principal_binding.principal_control_realm_id)
    {
        prerequisite_repo.cancel().await.ok();
        return Err(failed_precondition(
            "recovery commits are not in this account's Principal Control Realm stream",
        ));
    }
    verify_station_completion_attestation(
        depot,
        &mut prerequisite_repo,
        &handoff.audience_id,
        &request,
    )
    .await?;
    let browser_session_id = handoff.browser_session_id.ok_or_else(|| {
        failed_precondition("recovery completion requires its authenticated browser session")
    })?;
    let browser_session = prerequisite_repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or_else(|| failed_precondition("authenticated browser session no longer exists"))?;
    // A deactivated account is not valid for ordinary use, but the dedicated
    // recovery-completion path may consume an unfinished browser session that
    // was established by the deployment's fresh account-auth recovery flow.
    // All other inactive states remain excluded.
    let recovery_session_eligible = browser_session.finished_at.is_none()
        && matches!(
            browser_session.user.status,
            AccountStatus::Active | AccountStatus::Deactivated
        );
    if !recovery_session_eligible || browser_session.user.id != handoff.local_account_id {
        prerequisite_repo.cancel().await.ok();
        return Err(failed_precondition(
            "account handoff browser session is no longer active for this account",
        ));
    }
    prerequisite_repo.cancel().await.ok();

    let clock = crate::handlers::make_clock();
    let now = truncate_to_seconds(clock.now());
    let config = depot.arkret_config()?;
    let expires_at = now + config.session_grant_ttl;
    let keyring = depot.keyring()?;
    let (_, signing_key) =
        crate::services::preferred_service_signing_key(&keyring).ok_or_else(|| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "no session-grant signing key is available",
            ))
        })?;
    let signing_key_id = signing_key
        .kid()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "preferred session-grant signing key has no kid",
            ))
        })?
        .to_owned();
    let issuer_id = super::owning_station_id_for(&config);
    let request_identity = format!("recovery-completion:{}", request.transaction_id);
    let intent_digest: [u8; 32] = sha2::Sha256::digest(&canonical_request).into();
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer_id,
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: Some(SessionGrantProofKind::AccountHandoff),
                request_identity: &request_identity,
                canonical_intent_digest: intent_digest,
                canonical_intent: &canonical_request,
                target_session_grant_id: None,
                issuance_nonce: None,
                session_id: None,
                grant_not_before: Some(now),
                grant_expires_at: Some(expires_at),
                signing_key_id: Some(&signing_key_id),
                retained_until: expires_at + Duration::days(7),
            },
        )
        .await?;
    let operation = match reserved {
        SessionGrantReserveOutcome::Reserved(operation) => operation,
        SessionGrantReserveOutcome::Pending(operation)
            if operation.state == coauth_data::SessionGrantOperationState::Reserved =>
        {
            operation
        }
        SessionGrantReserveOutcome::Replay(operation) => {
            let bytes = operation
                .canonical_outcome
                .ok_or_else(indeterminate_replay)?;
            repo.cancel().await.ok();
            return replay_record_after_ledger_race(
                depot,
                &request,
                &canonical_request,
                handoff.local_account_id,
                Some(bytes),
            )
            .await;
        }
        SessionGrantReserveOutcome::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(duplicate_conflict(
                "recovery transaction id was reused with a different canonical request",
            ));
        }
        SessionGrantReserveOutcome::Indeterminate(_) | SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            return Err(indeterminate_replay());
        }
    };

    let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)?;
    let session_public_key: coauth_jose::jwk::PublicJsonWebKey =
        serde_json::from_str(initial.session_public_key.as_str())
            .map_err(|error| signature_invalid(error.to_string()))?;
    let expected_device_binding = arkret_models_identity::SessionGrantDeviceBinding {
        device_id: initial.device_id.clone(),
        authorization_event_id: request
            .completion_attestation
            .device_authorization_event_ref
            .event_id
            .clone(),
        model_generation_ref: request.result_model_generation_ref,
    };
    let device_binding = acquire_private_current_device_binding(
        depot,
        &account_id,
        initial.device_id.clone(),
        arkret_wire::DeviceRevocationAdmissionAction::SessionGrantIssue,
        Some(&expected_device_binding),
        None,
        request.canonical_request_digest.clone(),
        clock.now(),
    )
    .await?;
    if device_binding != expected_device_binding {
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOKED,
            "recovery completion device binding is unavailable or generation-fenced",
        ));
    }
    let material = issue_session_grant_for_audience(
        &issuance_seed,
        &*clock,
        &config,
        &keyring,
        &browser_session,
        session_public_key,
        initial.audience_id.clone(),
        initial.device_id.clone(),
        STANDARD_INITIAL_SESSION_GRANT_OPERATIONS
            .iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
        Some(&receipt.account_id.principal_id),
        &account_id,
        handoff.cnf_jkt.clone(),
        device_binding,
        SessionGrantProofKind::AccountHandoff,
    )?;
    let wire_grant = SessionGrantOutcome {
        account_id: material.account_id.clone(),
        device_id: Some(initial.device_id.clone()),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        session_grant_id: material.grant_id.clone(),
        session_public_key: initial.session_public_key.clone(),
        audience_id: initial.audience_id.clone(),
        granted_scope: material.scopes.clone(),
        previous_session_grant_id: None,
    };
    let outcome = IssueRecoveryCompletionGrantOutcome {
        transaction_id: request.transaction_id.clone(),
        session_grant_outcome: serde_json::to_value(wire_grant)?,
        issued_at: issuance_seed.not_before,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;

    // The deployment permits reactivation, but only here: the terminal PCR
    // recovery evidence, replacement-device generation check, AccountStatus
    // successor, local account restoration and first new-generation grant
    // commit as one transaction. Exact replay then observes the same outcome.
    let current_user = repo
        .user()
        .lookup(handoff.local_account_id)
        .await?
        .ok_or_else(|| failed_precondition("recovery account no longer exists"))?;
    match current_user.status {
        AccountStatus::Active => {}
        AccountStatus::Deactivated => {
            let station = depot.station()?;
            let plan = author_and_enqueue_transition(
                &mut repo,
                &mut rng,
                &*clock,
                station.as_ref(),
                &keyring,
                super::owning_station_id_for(&config).as_str(),
                &current_user,
                &principal_binding,
                AccountStatus::Active,
                Some("pcr_recovery_completed".to_owned()),
                now,
            )
            .await
            .map_err(account_status_reactivation_failed)?;
            validate_transition_plan(
                &current_user,
                &principal_binding,
                AccountStatus::Active,
                &plan,
            )
            .map_err(account_status_reactivation_failed)?;
            repo.user()
                .patch(
                    &*clock,
                    current_user.clone(),
                    UserPatch {
                        status: Some(AccountStatus::Active),
                        ..UserPatch::default()
                    },
                )
                .await?;
        }
        AccountStatus::ErasurePending => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::ACCOUNT_ERASED,
                "hard-erasure lifecycle is terminal and cannot be reactivated",
            ));
        }
        status => {
            repo.cancel().await.ok();
            return Err(failed_precondition(format!(
                "account status {} is not eligible for recovery reactivation",
                status.as_str(),
            )));
        }
    }
    let checkpoint = serde_json::json!({
        "kind": "recovery_completion",
        "account_handoff_id": handoff.id.to_string(),
        "transaction_id": request.transaction_id.to_string(),
        "terminal_receipt_id": receipt.receipt_id.to_string(),
        "reanchor_ref": serde_json::to_value(&request.completion_attestation.reanchor_event_ref)?,
        "device_authorization_ref": serde_json::to_value(&request.completion_attestation.device_authorization_event_ref)?,
        "result_model_generation_ref": serde_json::to_value(request.result_model_generation_ref)?,
    });
    let authorization_ref = format!("account-handoff:{}", handoff.id);
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            &mut rng,
            &*clock,
            operation.id,
            SessionGrantProofAuthorization {
                authorization_ref: &authorization_ref,
                checkpoint: &checkpoint,
                proof_expires_at: handoff.expires_at,
            },
            SessionGrantExactOutcome {
                canonical_response: &canonical_outcome,
                response_digest: sha2::Sha256::digest(&canonical_outcome).into(),
            },
            new_session_grant_record(Some(browser_session_id), &material),
        )
        .await?;
    match committed {
        SessionGrantCommitOutcome::Committed(_) => {}
        SessionGrantCommitOutcome::Replay(operation) => {
            let bytes = operation
                .canonical_outcome
                .ok_or_else(indeterminate_replay)?;
            repo.cancel().await.ok();
            return replay_record_after_ledger_race(
                depot,
                &request,
                &canonical_request,
                handoff.local_account_id,
                Some(bytes),
            )
            .await;
        }
        SessionGrantCommitOutcome::Indeterminate(_) => {
            repo.cancel().await.ok();
            return Err(indeterminate_replay());
        }
    }

    let generation = serde_json::to_value(request.result_model_generation_ref)?;
    let inserted = repo
        .recovery_authority()
        .insert_completion_issuance(NewRecoveryCompletionGrantIssuance {
            transaction_id: request.transaction_id.to_string(),
            transaction_request_digest: request.transaction_request_digest.to_string(),
            local_account_id: handoff.local_account_id,
            principal_id: receipt.account_id.principal_id.clone(),
            device_id: initial.device_id.to_string(),
            reanchor_ref: serde_json::to_value(&request.completion_attestation.reanchor_event_ref)?,
            device_authorization_ref: serde_json::to_value(
                &request
                    .completion_attestation
                    .device_authorization_event_ref,
            )?,
            result_model_generation_ref: generation,
            canonical_request_digest: request.canonical_request_digest.to_string(),
            canonical_request: canonical_request.clone(),
            session_grant_operation_id: operation.id,
            canonical_outcome: canonical_outcome.clone(),
            issued_at: issuance_seed.not_before,
        })
        .await?;
    if !inserted {
        repo.cancel().await.ok();
        return replay_record_after_ledger_race(
            depot,
            &request,
            &canonical_request,
            handoff.local_account_id,
            None,
        )
        .await;
    }
    if !repo.account_handoff().consume_grant(&handoff, now).await? {
        repo.cancel().await.ok();
        return Err(failed_precondition(
            "account handoff was consumed before recovery completion committed",
        ));
    }
    repo.save().await?;
    Ok(ArkretCanonicalJson(canonical_outcome))
}

/// Cross-checks the two independent replacement-device / Station signatures
/// that together describe one atomic recovery commit.
///
/// The receipt and the completion attestation are signed by different keys over
/// overlapping members, so every shared member is compared here.
///
/// Recovery completion is accepted only when the re-anchor Event and the
/// replacement-device authorization Event are **two consecutive committed
/// positions of one PCR Realm stream**. The replacement device signs only the
/// two producer Event ids; the governing Station signs the two
/// `CommittedEventRef` quadruples. This boundary therefore joins the halves:
/// `receipt.reanchor_event_id` and `receipt.authorization_event_id` must be the
/// exact `event_id` members of `completion_attestation.reanchor_event_ref` and
/// `completion_attestation.device_authorization_event_ref`,
/// and the two refs must name the same Realm stream at strictly consecutive
/// positions. The client never signs, carries, or re-derives the `RealmCommit`
/// itself.
///
/// One `RealmCommit` carries exactly one `event_ref` at exactly one
/// `stream_position`, so the pair always names two distinct commits. Same-stream
/// adjacency, the Realm stream kind, and the distinctness of both `commit_id`
/// and `event_id` are all enforced by
/// `IssueRecoveryCompletionGrantRequest::validate_structural`, which delegates
/// to the SDK `validate_recovery_commit_pair`.
///
/// The coordinator is `account_id.station_id`; no separate coordinator member
/// exists on wire or in the signed projection.
fn validate_completion_evidence(
    request: &IssueRecoveryCompletionGrantRequest,
    receipt: &RecoveryReceipt,
    initial: &InitialSessionGrantIntent,
    handoff: &coauth_data::account_handoff::AccountHandoffGrant,
    dpop_jkt: &str,
) -> Result<(), ArkretRouteError> {
    let attestation = &request.completion_attestation;
    let receipt_bytes = arkret_canonical::canonical_json_bytes(&request.terminal_receipt)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let receipt_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&receipt_bytes))
            .map_err(|error| failed_precondition(error.to_string()))?;
    let receipt_generation = serde_json::to_value(receipt.result_model_generation_ref)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let request_generation = serde_json::to_value(request.result_model_generation_ref)
        .map_err(|error| failed_precondition(error.to_string()))?;
    if receipt.outcome != RecoveryReceiptOutcome::Completed
        || receipt.transaction_id != request.transaction_id
        || receipt.transaction_request_digest != request.transaction_request_digest
        || receipt.account_id != attestation.account_id
        || receipt.recovery_session_id != attestation.recovery_session_id
        || receipt.receipt_id != attestation.terminal_receipt_id
        || receipt_digest != attestation.terminal_receipt_digest
        || receipt.prepared_plan_digest != attestation.prepared_plan_digest
        || receipt.new_device_id != attestation.replacement_device_id
        || receipt.new_device_id != initial.device_id
        || receipt.reanchor_event_id != request.completion_attestation.reanchor_event_ref.event_id
        || receipt.authorization_event_id
            != request
                .completion_attestation
                .device_authorization_event_ref
                .event_id
        || receipt_generation != request_generation
        || receipt.completed_at > attestation.completed_at
        || attestation.account_id.station_id.as_str() != handoff.audience_id
    {
        return Err(failed_precondition(
            "recovery receipt, completion attestation, replacement device and current generation disagree",
        ));
    }
    if initial.audience_id.as_str() != handoff.audience_id {
        return Err(failed_precondition(
            "initial SessionGrant audience does not match the account handoff audience",
        ));
    }
    initial
        .validate()
        .map_err(|error| failed_precondition(error.to_string()))?;
    let session_jkt = initial
        .session_public_key
        .thumbprint_sha256()
        .map_err(|error| signature_invalid(error.to_string()))?;
    if session_jkt != handoff.cnf_jkt || session_jkt != dpop_jkt {
        return Err(signature_invalid(
            "initial session key thumbprint does not match the Bound handoff and HTTP DPoP key",
        ));
    }
    Ok(())
}

async fn verify_account_principal_binding(
    repo: &mut coauth_data::BoxRepository,
    account_id: coauth_data::Ulid,
    audience: &str,
    principal_id: &str,
) -> Result<coauth_data::PrincipalDidBinding, ArkretRouteError> {
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(principal_id, audience)
        .await?
        .ok_or_else(|| {
            failed_precondition("principal is not bound to an account at this audience")
        })?;
    if binding.user_id != account_id || binding.principal_id.as_str() != principal_id {
        return Err(failed_precondition(
            "recovered principal is bound to a different service account",
        ));
    }
    binding
        .account_id
        .validate()
        .map_err(|error| failed_precondition(error.to_string()))?;
    Ok(binding)
}

fn account_status_reactivation_failed(
    error: crate::services::account_status_publication::AccountStatusPublicationError,
) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::PRECONDITION_FAILED,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        error.to_string(),
    )
}

/// Verifies the Station signature over the fixed 14-member completion
/// projection.
///
/// The projection itself is owned by `arkret_wire` (`signing_bytes`), so this
/// boundary can never drift from the transcript the Station signed. The signer
/// must be the handoff audience, and `validate_completion_evidence` separately
/// requires `attestation.account_id.station_id` to equal that same audience, so
/// the coordinator is pinned to the account's own Station.
async fn verify_station_completion_attestation(
    depot: &Depot,
    repo: &mut coauth_data::BoxRepository,
    expected_station: &str,
    request: &IssueRecoveryCompletionGrantRequest,
) -> Result<(), ArkretRouteError> {
    let attestation = &request.completion_attestation;
    let signer_did = arkret_identifiers::Did::new(verification_method_did(
        attestation.auth_data.verification_method.as_str(),
    ))
    .map_err(|error| signature_invalid(error.to_string()))?;
    let signer_core = arkret_identifiers::project_did_to_core_id(&signer_did)
        .map_err(|error| signature_invalid(error.to_string()))?;
    if signer_core.as_str() != expected_station {
        return Err(signature_invalid(
            "recovery completion attestation must be signed by the handoff audience",
        ));
    }
    let config = depot.arkret_config()?;
    let trusted = config
        .stations
        .iter()
        .filter_map(|server| effective_audience(server, shared()))
        .any(|service_id| service_id.as_str() == expected_station);
    if !trusted {
        return Err(signature_invalid(
            "recovery completion signer is not the configured Station",
        ));
    }
    let resolution = crate::services::did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &config,
        &depot.keyring()?,
        repo,
        depot.did_resolver_service()?.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        signer_did.as_str(),
        arkret_identity::DidBindingPurpose::Recovery,
        crate::services::did_binding::high_risk_freshness(),
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|error| {
        signature_invalid(format!(
            "no fresh trusted recovery binding for the Station: {error}"
        ))
    })?;
    verify_with_document_method(
        &resolution.document,
        attestation.auth_data.verification_method.as_str(),
        &attestation
            .signing_bytes()
            .map_err(|error| signature_invalid(error.to_string()))?,
        &attestation.auth_data.signature,
        "completion attestation",
    )
}

fn verify_with_document_method(
    document: &super::DidDocument,
    verification_method: &str,
    signing_bytes: &[u8],
    signature: &str,
    label: &str,
) -> Result<(), ArkretRouteError> {
    let method = document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| signature_invalid(format!("{label} verification method is absent")))?;
    let material = method.public_key_material().map_err(signature_invalid)?;
    if !verify_detached_ed25519_signature(&material, signing_bytes, signature) {
        return Err(signature_invalid(format!(
            "{label} signature did not verify"
        )));
    }
    Ok(())
}

fn exact_replay(
    record: coauth_data::RecoveryCompletionGrantIssuance,
    request: &IssueRecoveryCompletionGrantRequest,
    canonical_request: &[u8],
    account_id: coauth_data::Ulid,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    if record.transaction_request_digest != request.transaction_request_digest.as_str()
        || record.canonical_request_digest != request.canonical_request_digest.as_str()
        || record.local_account_id != account_id
        || record.canonical_request != canonical_request
    {
        return Err(duplicate_conflict(
            "recovery transaction id was reused with different account or request bytes",
        ));
    }
    Ok(ArkretCanonicalJson(record.canonical_outcome))
}

async fn replay_record_after_ledger_race(
    depot: &Depot,
    request: &IssueRecoveryCompletionGrantRequest,
    canonical_request: &[u8],
    account_id: coauth_data::Ulid,
    ledger_outcome: Option<Vec<u8>>,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let mut repo = depot.repo().await?;
    let record = repo
        .recovery_authority()
        .lookup_completion_issuance(request.transaction_id.as_str())
        .await?;
    repo.cancel().await.ok();
    let outcome = exact_replay(
        record.ok_or_else(indeterminate_replay)?,
        request,
        canonical_request,
        account_id,
    )?;
    if ledger_outcome
        .as_ref()
        .is_some_and(|ledger| ledger != &outcome.0)
    {
        return Err(indeterminate_replay());
    }
    Ok(outcome)
}

/// Realm of a committed recovery Event, accepted only for a Realm stream.
///
/// Recovery re-anchor and replacement-device authorization belong to the
/// account's Principal Control Realm stream. A Circle or Sidecar stream ref is
/// a different visibility stream and is refused rather than projected onto its
/// parent Realm.
fn commit_pair_realm(
    committed: &arkret_wire::CommittedEventRef,
) -> Option<&arkret_identifiers::RealmId> {
    match &committed.stream_ref {
        arkret_wire::CommitStreamRef::Realm { realm_id } => Some(realm_id),
        arkret_wire::CommitStreamRef::Circle { .. }
        | arkret_wire::CommitStreamRef::Sidecar { .. } => None,
        _ => None,
    }
}

fn verification_method_did(value: &str) -> &str {
    value.split_once('#').map_or(value, |(did, _)| did)
}

fn truncate_to_seconds(value: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    value.with_nanosecond(0).unwrap_or(value)
}

fn unauthenticated_handoff() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::UNAUTHENTICATED,
        "account handoff is expired, revoked, or unknown",
    )
}

fn schema_violation(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        message,
    )
}

fn signature_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        message,
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

fn indeterminate_replay() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
        "recovery completion issuance is fenced without an exact replayable outcome",
    )
}
