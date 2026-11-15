//! Standard opaque issuance from one authenticated native Recovery completion.
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_crypto::{RecoveryTransactionCompletion, SecurityTransaction};
use arkret_models_identity::{
    AccountHandoffAllowedOperation, IssueRecoveryCompletionGrantResponseBody,
    RecoveryCompletionGrantRequestBody, STANDARD_INITIAL_SESSION_GRANT_OPERATIONS,
    SessionGrantProofKind, SessionGrantResponseBody,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{
    NewRecoveryCompletionGrantIssuance, NewSessionGrantOperation, RepositoryAccess as _,
    SessionGrantCommitOutcome, SessionGrantExactOutcome, SessionGrantProofAuthorization,
    SessionGrantReserveOutcome, UserPatch,
};
use salvo::prelude::*;

use super::ArkretRouteError;
use super::account_handoff::{
    authenticate_account_handoff, enforce_handoff_operation,
    verify_account_handoff_holder_without_lookup,
};
use super::canonical_response::ArkretCanonicalJson;
use super::session_grant::{
    acquire_current_replay_authority, acquire_private_current_device_admission,
    require_outer_dpop_fresh,
};
use crate::handlers::common::DepotExt;
use crate::services::account_status_publication::{
    author_and_enqueue_prepared_transition, validate_transition_plan,
};
use crate::services::session_grant::{
    HumanGrantIssuance, SessionGrantIssuanceSeed, issue_session_grant_for_audience,
    new_session_grant_record,
};
use crate::services::station_trust::owning_station_id_for;

#[handler]
pub async fn issue_recovery_completion_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let request: RecoveryCompletionGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|_| schema_violation("invalid typed recovery-completion request"))?;
    request
        .validate_structural()
        .map_err(|error| schema_violation(error.to_string()))?;
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)?;
    let config = depot.arkret_config()?;
    let issuer = owning_station_id_for(&config);
    let receipt = &request.terminal_receipt;
    if receipt.session_grant_ref.issuer_id != issuer {
        return Err(signature_invalid(
            "historical Recovery record belongs to another issuer",
        ));
    }
    let operation_identity = request.operation_identity(&issuer)?;
    let request_identity = arkret_canonical::sha256_digest(&operation_identity);
    let (handoff_token, replay_dpop) = verify_account_handoff_holder_without_lookup(req, depot)?;
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut repo = depot.repo().await?;
    let handoff = repo
        .account_handoff()
        .get_by_token(&handoff_token, now)
        .await?
        .ok_or_else(unauthenticated_handoff)?;
    enforce_handoff_operation(
        &handoff,
        AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
    )?;
    if replay_dpop.jkt != handoff.cnf_jkt
        || request.accepted_device_possession_proof.holder_jkt != handoff.cnf_jkt
        || handoff.audience_id != receipt.account_id.station_id.as_str()
    {
        return Err(signature_invalid(
            "fresh AccountHandoff, DPoP, new holder and full Account disagree",
        ));
    }
    let binding = verify_account_principal_binding(
        &mut repo,
        handoff.local_account_id,
        &handoff.audience_id,
        &receipt.account_id,
    )
    .await?;
    let browser_session_id = handoff.browser_session_id.ok_or_else(|| {
        failed_precondition("completion requires fresh account-authenticated browser context")
    })?;
    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or_else(|| failed_precondition("authenticated browser context is unavailable"))?;
    if browser_session.user.id != handoff.local_account_id
        || browser_session.finished_at.is_some()
        || !matches!(
            browser_session.user.status,
            AccountStatus::Active | AccountStatus::Deactivated
        )
    {
        return Err(failed_precondition(
            "current account lifecycle forbids recovery completion",
        ));
    }
    if browser_session.user.status == AccountStatus::Deactivated
        && !config.allow_recovery_reactivation
    {
        return Err(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED,
            "deployment policy denies recovery reactivation",
        ));
    }
    let inspection = inspect_completion_attempt(&mut repo, &request, &issuer, &*clock).await?;
    let inspected_at =
        fresh_completion_qualification_at_cut(&mut repo, &handoff, &replay_dpop, &*clock).await?;
    require_current_completion_issuer(depot, &issuer)?;
    let prior = match inspection {
        CompletionAttempt::Accepted(record) => Some(*record),
        CompletionAttempt::Unaccepted => None,
        CompletionAttempt::ExpiredUnaccepted => {
            if !repo
                .dpop_replay()
                .consume_jti(crate::services::dpop::dpop_replay_record(
                    &replay_dpop.claims.jti,
                    inspected_at,
                ))
                .await?
            {
                return Err(signature_invalid(
                    "completion expiry probe HTTP DPoP JTI was already consumed",
                ));
            }
            if let Err(error) =
                fresh_completion_qualification_at_cut(&mut repo, &handoff, &replay_dpop, &*clock)
                    .await
            {
                repo.cancel().await?;
                return Err(error);
            }
            repo.save().await?;
            return Err(expired_unaccepted_completion());
        }
    };
    repo.cancel().await?;
    if let Some(prior) = prior {
        return exact_replay(
            depot,
            prior,
            &request,
            &canonical_request,
            &handoff,
            &replay_dpop,
            Some(&replay_dpop.claims.jti),
            &*clock,
        )
        .await;
    }

    // First issuance alone admits the original business proof window and consumes the handoff.
    let (active_handoff, dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
    )
    .await?;
    if active_handoff.id != handoff.id || dpop.jkt != handoff.cnf_jkt {
        return Err(signature_invalid(
            "AccountHandoff changed during first issuance",
        ));
    }
    let completed = fetch_station_completion(depot, &request).await?;
    let completion = &completed.completion_attestation;
    request
        .validate_completion(completion)
        .map_err(|error| failed_precondition(error.to_string()))?;
    if completion.reanchor_event_ref.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: binding.principal_control_realm_id.clone(),
        })
    {
        return Err(failed_precondition(
            "completion belongs to another Principal Control Realm",
        ));
    }
    verify_station_completion(depot, &completed).await?;
    let payload = DeviceAuthorizePayload::try_from(&receipt.recovery_unit.events[1].event)
        .map_err(|error| signature_invalid(error.to_string()))?;
    let candidate_multibase = payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| signature_invalid("native replacement Event does not name a did:key"))?;
    let candidate_key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Multibase {
        value: candidate_multibase.to_owned(),
    };
    arkret_signatures::recovery::verify_recovery_receipt(
        receipt,
        &receipt.signature_proof.verification_method,
        &candidate_key,
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    arkret_signatures::recovery::verify_recovery_completion_holder(
        &request,
        &receipt.signature_proof.verification_method,
        &candidate_key,
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    let subject = super::account_handoff::account_subject(&issuer, handoff.local_account_id)?;
    let handoff_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(handoff_token.as_bytes()))?;
    let expected_device = arkret_models_identity::SessionGrantDeviceBinding {
        device_id: receipt.new_device_id.clone(),
        authorization_event_id: completion.device_authorization_event_ref.event_id.clone(),
        model_generation_ref: receipt.new_model_generation_ref,
    };
    let intent_digest = arkret_canonical::sha256_bytes(&canonical_request);
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;
    match inspect_completion_attempt(&mut repo, &request, &issuer, &*clock).await? {
        CompletionAttempt::Accepted(_) => {
            fresh_completion_qualification_at_cut(&mut repo, &handoff, &dpop, &*clock).await?;
            repo.cancel().await?;
            return replay_after_race(
                depot,
                &request,
                &canonical_request,
                &handoff,
                &dpop,
                &*clock,
            )
            .await;
        }
        CompletionAttempt::ExpiredUnaccepted => {
            fresh_completion_qualification_at_cut(&mut repo, &handoff, &dpop, &*clock).await?;
            repo.cancel().await?;
            return Err(expired_unaccepted_completion());
        }
        CompletionAttempt::Unaccepted => {}
    }
    let keyring = depot.keyring()?;
    // Authoring a successor may resolve the real AA issuer source. Prepare it
    // before any account head/user/binding lock; active completion needs none.
    let publication_source = if browser_session.user.status == AccountStatus::Deactivated {
        let context =
            crate::services::account_status_publication::AccountStatusIssuerContext::from_depot(
                depot,
            )?;
        let source = context
            .prepare(&mut repo, &keyring, &issuer, &binding, clock.now())
            .await
            .map_err(|error| failed_precondition(error))?;
        Some((context, source))
    } else {
        None
    };
    let qualified_at =
        fresh_completion_qualification_at_cut(&mut repo, &handoff, &dpop, &*clock).await?;
    if qualified_at >= request.accepted_device_possession_proof.expires_at {
        return reject_stale_first_attempt(
            depot,
            repo,
            &request,
            &canonical_request,
            &handoff,
            &dpop,
            &*clock,
        )
        .await;
    }
    // The business-key lock fences this one first acceptance. Read current
    // replacement eligibility after obtaining it, rather than letting an
    // admission captured before a lock wait survive a revoke/reanchor.
    let device_admission = acquire_private_current_device_admission(
        depot,
        &receipt.account_id,
        receipt.new_device_id.clone(),
        arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        Some(&expected_device),
        Some(arkret_wire::AcceptedDevicePossessionProof::Issue(
            request.accepted_device_possession_proof.clone(),
        )),
        request
            .accepted_device_possession_proof
            .session_intent_digest
            .clone(),
        clock.now(),
    )
    .await
    .map_err(recovery_completion_device_refusal)?;
    let device_deadline = device_admission.expires_at();
    let device_binding = device_admission.binding;
    if device_binding != expected_device {
        return Err(failed_precondition("replacement generation changed"));
    }
    // RPC and lock waits may outlive a once-fresh handoff. This time is also
    // the time used by the conditional handoff consumption at commit.
    let now = fresh_completion_qualification_at_cut(&mut repo, &handoff, &dpop, &*clock).await?;
    if now >= request.accepted_device_possession_proof.expires_at || now >= device_deadline {
        return reject_stale_first_attempt(
            depot,
            repo,
            &request,
            &canonical_request,
            &handoff,
            &dpop,
            &*clock,
        )
        .await;
    }
    let expires_at = now + config.session_grant_ttl;
    request
        .validate_first_issue(completion, &subject, &handoff_digest, &dpop.jkt, now)
        .map_err(|error| signature_invalid(error.to_string()))?;
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer_id: issuer.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: Some(SessionGrantProofKind::AccountHandoff),
                request_identity: &request_identity,
                canonical_intent_digest: intent_digest,
                canonical_intent: &canonical_request,
                target_session_grant_id: None,
                grant_not_before: Some(now),
                grant_expires_at: Some(expires_at),
                retained_until: expires_at + Duration::days(7),
            },
        )
        .await?;
    let operation = match reserved {
        SessionGrantReserveOutcome::Reserved(operation)
            if operation.state == coauth_data::SessionGrantOperationState::Reserved =>
        {
            operation
        }
        SessionGrantReserveOutcome::Replay(_) => {
            repo.cancel().await?;
            return replay_after_race(
                depot,
                &request,
                &canonical_request,
                &handoff,
                &dpop,
                &*clock,
            )
            .await;
        }
        SessionGrantReserveOutcome::Conflict(_) => {
            return Err(duplicate_conflict(
                "completion business key already has another complete request",
            ));
        }
        _ => return Err(indeterminate_replay()),
    };
    let seed = SessionGrantIssuanceSeed::from_operation(&operation)?;
    let public_key = serde_json::from_str(request.initial_session.session_public_key.as_str())
        .map_err(|error| signature_invalid(format!("invalid initial public key: {error}")))?;
    let material = issue_session_grant_for_audience(
        &seed,
        &config,
        HumanGrantIssuance {
            browser_session: &browser_session,
            session_public_key: public_key,
            audience_id: request.initial_session.audience_id.clone(),
            device_id: receipt.new_device_id.clone(),
            scopes: STANDARD_INITIAL_SESSION_GRANT_OPERATIONS
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
            subject_override: Some(&receipt.account_id.principal_id),
            account_id: &receipt.account_id,
            dpop_jkt: dpop.jkt.clone(),
            device_binding,
            proof_kind: SessionGrantProofKind::AccountHandoff,
        },
    )?;
    let issued_session = SessionGrantResponseBody {
        issuer_id: material.issuer_id.clone(),
        account_id: material.account_id.clone(),
        device_id: material.metadata.device_id.clone(),
        session_grant: material.session_grant.clone(),
        expires_at: material.expires_at_timestamp,
        session_grant_id: material.grant_id.clone(),
        session_public_key: material.metadata.session_public_key.clone(),
        audience_id: material.audience_id.clone(),
        granted_scope: material.scopes.clone(),
        previous_session_grant_id: None,
    };
    let outcome = IssueRecoveryCompletionGrantResponseBody {
        transaction_id: receipt.transaction_id.clone(),
        issued_session,
        issued_at: seed.not_before,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
    // Keep the existing account head -> user -> accepted-binding lock order.
    let head = repo
        .account_status_ledger()
        .current_for_gate(issuer.as_str(), &handoff.local_account_id.to_string())
        .await?;
    let current_user = repo
        .user()
        .lookup_for_gate(handoff.local_account_id)
        .await?
        .ok_or_else(|| failed_precondition("recovery account no longer exists"))?;
    let current_binding = repo
        .principal_did()
        .get_by_principal_id_and_audience_for_gate(
            receipt.account_id.principal_id.as_str(),
            receipt.account_id.station_id.as_str(),
        )
        .await?
        .ok_or_else(|| failed_precondition("accepted account binding no longer exists"))?;
    if head.as_ref().is_some_and(|head| {
        head.status != current_user.status
            || head.account_id != receipt.account_id
            || head.binding_version != binding.binding_version
    }) {
        return Err(failed_precondition(
            "local lifecycle and accepted issuer head disagree",
        ));
    }
    if current_binding != binding || current_user.id != binding.user_id {
        return Err(failed_precondition(
            "recovery account binding changed before issuer commit",
        ));
    }
    let now = fresh_completion_qualification_at_cut(&mut repo, &handoff, &dpop, &*clock).await?;
    if now >= request.accepted_device_possession_proof.expires_at || now >= device_deadline {
        return reject_stale_first_attempt(
            depot,
            repo,
            &request,
            &canonical_request,
            &handoff,
            &dpop,
            &*clock,
        )
        .await;
    }
    request
        .validate_first_issue(completion, &subject, &handoff_digest, &dpop.jkt, now)
        .map_err(|error| signature_invalid(error.to_string()))?;
    match current_user.status {
        AccountStatus::Active => {}
        AccountStatus::Deactivated => {
            if !depot.arkret_config()?.allow_recovery_reactivation {
                return Err(ArkretRouteError::coded(
                    StatusCode::FORBIDDEN,
                    arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED,
                    "deployment policy denies recovery reactivation",
                ));
            }
            let station = depot.station()?;
            let Some((context, source)) = publication_source.as_ref() else {
                repo.cancel().await?;
                return Err(ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
                    "account became deactivated during qualification; retry the identical completion request",
                ));
            };
            let plan = author_and_enqueue_prepared_transition(
                &mut repo,
                &mut rng,
                &*clock,
                station.as_ref(),
                &keyring,
                issuer.as_str(),
                &current_user,
                &binding,
                AccountStatus::Active,
                Some("pcr_recovery_completed".into()),
                now,
                context,
                source,
            )
            .await
            .map_err(account_status_reactivation_failed)?;
            validate_transition_plan(&current_user, &binding, AccountStatus::Active, &plan)
                .map_err(account_status_reactivation_failed)?;
            repo.user()
                .patch(
                    &*clock,
                    current_user,
                    UserPatch {
                        status: Some(AccountStatus::Active),
                        ..UserPatch::default()
                    },
                )
                .await?;
        }
        AccountStatus::ErasurePending => {
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::ACCOUNT_ERASED,
                "hard-erasure state cannot be reactivated",
            ));
        }
        _ => {
            return Err(failed_precondition(
                "current account state forbids recovery reactivation",
            ));
        }
    }
    let checkpoint = serde_json::json!({"kind":"recovery_completion", "account_handoff_id":handoff.id.to_string(),
        "terminal_receipt_digest":receipt.receipt_digest()?, "completion_attestation":completion,
        "accepted_device_possession_proof_digest":arkret_wire::AcceptedDevicePossessionProof::Issue(
            request.accepted_device_possession_proof.clone()).proof_digest()?});
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
                proof_expires_at: handoff
                    .expires_at
                    .min(request.accepted_device_possession_proof.expires_at)
                    .min(device_deadline),
            },
            SessionGrantExactOutcome {
                canonical_response: &canonical_outcome,
                response_digest: arkret_canonical::sha256_bytes(&canonical_outcome),
            },
            new_session_grant_record(Some(browser_session_id), &material),
        )
        .await?;
    match committed {
        SessionGrantCommitOutcome::Committed(_) => {}
        SessionGrantCommitOutcome::AuthorizationExpired(_) => {
            return reject_stale_first_attempt(
                depot,
                repo,
                &request,
                &canonical_request,
                &handoff,
                &dpop,
                &*clock,
            )
            .await;
        }
        SessionGrantCommitOutcome::Replay(_) => {
            repo.cancel().await?;
            return replay_after_race(
                depot,
                &request,
                &canonical_request,
                &handoff,
                &dpop,
                &*clock,
            )
            .await;
        }
        SessionGrantCommitOutcome::Indeterminate(_) => return Err(indeterminate_replay()),
    }
    let inserted = repo
        .recovery_authority()
        .insert_completion_issuance(NewRecoveryCompletionGrantIssuance {
            issuer_id: issuer,
            account_id: receipt.account_id.clone(),
            transaction_id: receipt.transaction_id.clone(),
            terminal_receipt_digest: receipt.receipt_digest()?,
            local_account_id: handoff.local_account_id,
            reanchor_ref: completion.reanchor_event_ref.clone(),
            device_authorization_ref: completion.device_authorization_event_ref.clone(),
            new_model_generation_ref: receipt.new_model_generation_ref,
            canonical_request_digest: request.canonical_request_digest.clone(),
            canonical_request: canonical_request.clone(),
            session_grant_operation_id: operation.id,
            canonical_outcome: canonical_outcome.clone(),
            issued_at: seed.not_before,
        })
        .await?;
    if !inserted {
        repo.cancel().await?;
        return replay_after_race(
            depot,
            &request,
            &canonical_request,
            &handoff,
            &dpop,
            &*clock,
        )
        .await;
    }
    if !repo.account_handoff().consume_grant(&handoff, now).await? {
        return Err(failed_precondition(
            "handoff was consumed before recovery completion committed",
        ));
    }
    let final_at =
        match fresh_completion_qualification_at_cut(&mut repo, &handoff, &dpop, &*clock).await {
            Ok(now) => now,
            Err(error) => {
                repo.cancel().await?;
                return Err(error);
            }
        };
    if final_at >= request.accepted_device_possession_proof.expires_at
        || final_at >= device_deadline
    {
        return reject_stale_first_attempt(
            depot,
            repo,
            &request,
            &canonical_request,
            &handoff,
            &dpop,
            &*clock,
        )
        .await;
    }
    require_current_completion_issuer(depot, &receipt.session_grant_ref.issuer_id)?;
    repo.save().await?;
    Ok(ArkretCanonicalJson(canonical_outcome))
}

/// Roll back every unpublished first-attempt effect before observing the
/// serialized business key again. Never renew a proof over an accepted or
/// unknown issuer outcome; an expired device observation alone retries exactly.
async fn reject_stale_first_attempt(
    depot: &Depot,
    repo: coauth_data::BoxRepository,
    request: &RecoveryCompletionGrantRequestBody,
    canonical_request: &[u8],
    handoff: &coauth_data::AccountHandoffGrant,
    dpop: &arkret_signatures::dpop::VerifiedDpopProof,
    clock: &dyn coauth_data::Clock,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    repo.cancel().await?;
    let issuer = owning_station_id_for(&depot.arkret_config()?);
    if issuer != request.terminal_receipt.session_grant_ref.issuer_id {
        return Err(signature_invalid(
            "completion issuer changed during the first attempt",
        ));
    }
    let mut repo = depot.repo().await?;
    let observed = inspect_completion_attempt(&mut repo, request, &issuer, clock).await?;
    let qualification =
        fresh_completion_qualification_at_cut(&mut repo, handoff, dpop, clock).await;
    repo.cancel().await?;
    qualification?;
    require_completion_outer_dpop_fresh(dpop, clock.now())?;
    match observed {
        CompletionAttempt::Accepted(record) => {
            exact_replay(
                depot,
                *record,
                request,
                canonical_request,
                handoff,
                dpop,
                None,
                clock,
            )
            .await
        }
        CompletionAttempt::ExpiredUnaccepted => Err(expired_unaccepted_completion()),
        CompletionAttempt::Unaccepted => Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "current-device observation expired before first acceptance; retry the identical completion request",
        )),
    }
}

async fn fetch_station_completion(
    depot: &Depot,
    request: &RecoveryCompletionGrantRequestBody,
) -> Result<RecoveryTransactionCompletion, ArkretRouteError> {
    let receipt = &request.terminal_receipt;
    let config = depot.arkret_config()?;
    let destination = config
        .stations
        .iter()
        .find(|server| {
            crate::services::station_trust::effective_audience_shared(server).as_ref()
                == Some(&receipt.account_id.station_id)
        })
        .ok_or_else(|| {
            failed_precondition(
                "the full Account origin Station has no configured registered channel",
            )
        })?;
    let http = depot.http_client()?;
    let channel = crate::services::peer_protocol_client::InternalAuthorityChannel::new(
        &destination.endpoint,
        &http,
        destination.internal_authority_shared_secret(),
        receipt.account_id.station_id.clone(),
    )
    .map_err(|error| {
        failed_precondition(format!(
            "registered completion channel unavailable: {error}"
        ))
    })?;
    let result = channel.get_recovery_completion(&receipt.transaction_id).await.map_err(|error| {
        if matches!(&error, crate::services::peer_protocol_client::PeerProtocolClientError::Status { status: 404, .. }) {
            return failed_precondition("original Station has no visible immutable completion at this authenticated read cut; preserve the frozen Recovery intent");
        }
        ArkretRouteError::coded(StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE, format!("original Station completion is unavailable: {error}"))
    })?;
    let SecurityTransaction::Recovery(completed) = result else {
        return Err(failed_precondition(
            "security transaction is not immutable completed Recovery",
        ));
    };
    completed
        .validate_structural()
        .map_err(|error| failed_precondition(error.to_string()))?;
    if &completed.account_id.station_id != channel.destination_service_id()
        || completed.account_id != receipt.account_id
        || completed.transaction_id != receipt.transaction_id
        || arkret_canonical::canonical_json_bytes(&completed.recovery_receipt)?
            != arkret_canonical::canonical_json_bytes(receipt)?
    {
        return Err(failed_precondition(
            "original Station returned another full signed Recovery",
        ));
    }
    Ok(completed)
}

async fn verify_station_completion(
    depot: &Depot,
    completed: &RecoveryTransactionCompletion,
) -> Result<(), ArkretRouteError> {
    let completion = &completed.completion_attestation;
    let method = &completion.signature_proof.verification_method;
    let signer = arkret_identifiers::Did::new(
        method
            .as_str()
            .split_once('#')
            .map_or(method.as_str(), |(did, _)| did),
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    if arkret_identifiers::project_did_to_core_id(&signer)
        .map_err(|error| signature_invalid(error.to_string()))?
        != completed.account_id.station_id
    {
        return Err(signature_invalid(
            "completion signer is not this full Account's original Station",
        ));
    }
    let http = depot.http_client()?;
    let config = depot.arkret_config()?;
    let resolver = depot.did_resolver_service()?;
    let document = if signer.method() == "webvh" {
        let historical = crate::services::did_resolver::resolve_verified_webvh_service_document_at(
            &http,
            resolver.resolver_egress_policy(),
            &signer,
            completion.completed_at,
        )
        .await
        .map_err(|error| {
            signature_invalid(format!("historical Station authority unavailable: {error}"))
        })?;
        crate::services::did_binding::to_shared_document(&historical)
            .map_err(|error| signature_invalid(error.to_string()))?
    } else {
        let mut repo = depot.read_repo().await?;
        let resolution = crate::services::did_binding::authority_document(
            &http,
            &depot.url_builder()?,
            &config,
            &depot.keyring()?,
            &mut repo,
            resolver.as_ref(),
            depot.verified_did_binding_store()?.as_ref(),
            signer.as_str(),
            arkret_identity::DidBindingPurpose::Service,
            crate::services::did_binding::high_risk_freshness(),
            crate::handlers::make_clock().now(),
        )
        .await
        .map_err(|error| signature_invalid(error.to_string()))?;
        repo.cancel().await?;
        resolution.accepted.document().clone()
    };
    arkret_identity::validate_verification_method_relationship(
        &document,
        method,
        &signer,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    let key =
        arkret_identity::resolve_verification_method_key_from_document(&document, method.as_str())
            .map_err(|error| signature_invalid(error.to_string()))?;
    arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
        &completion.signing_bytes()?,
        &completion.signature_proof.signature,
        &key.public_key,
    )
    .map_err(|error| signature_invalid(error.to_string()))
}

async fn verify_account_principal_binding(
    repo: &mut coauth_data::BoxRepository,
    local_id: coauth_data::Ulid,
    audience: &str,
    account: &arkret_wire::AccountId,
) -> Result<coauth_data::PrincipalDidBinding, ArkretRouteError> {
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(account.principal_id.as_str(), audience)
        .await?
        .filter(|binding| binding.user_id == local_id && binding.account_id == *account)
        .ok_or_else(|| {
            failed_precondition(
                "full recovered Account is not the current authenticated local binding",
            )
        })?;
    binding.account_id.validate()?;
    Ok(binding)
}

/// Re-read the actual handoff after waits; its original authentication does
/// not extend expiry. A consumed row may still authenticate an accepted exact
/// replay; first issuance separately consumes it conditionally in this transaction.
async fn fresh_completion_handoff_at_cut(
    repo: &mut coauth_data::BoxRepository,
    expected: &coauth_data::AccountHandoffGrant,
    clock: &dyn coauth_data::Clock,
) -> Result<DateTime<Utc>, ArkretRouteError> {
    let current = repo
        .account_handoff()
        .get_by_token(&expected.account_handoff_grant, clock.now())
        .await?
        .ok_or_else(unauthenticated_handoff)?;
    let browser_id = current
        .browser_session_id
        .ok_or_else(unauthenticated_handoff)?;
    let browser = repo
        .browser_session()
        .lookup(browser_id)
        .await?
        .ok_or_else(unauthenticated_handoff)?;
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    if current.id != expected.id
        || current.request_id != expected.request_id
        || current.request_digest != expected.request_digest
        || current.local_account_id != expected.local_account_id
        || current.browser_session_id != expected.browser_session_id
        || current.audience_id != expected.audience_id
        || current.cnf_jkt != expected.cnf_jkt
        || current.allowed_operations != expected.allowed_operations
        || current.issued_at != expected.issued_at
        || current.expires_at != expected.expires_at
        || current.issued_at > now
        || current.expires_at <= now
        || current.revoked_at.is_some()
        || browser.finished_at.is_some()
        || browser.user.id != current.local_account_id
        || !matches!(
            browser.user.status,
            AccountStatus::Active | AccountStatus::Deactivated
        )
    {
        return Err(unauthenticated_handoff());
    }
    enforce_handoff_operation(
        &current,
        AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
    )?;
    Ok(now)
}

/// Handoff re-reads may block. Keep the current HTTP proof's verified iat
/// deadline through that wait; this never re-admits the historical inner PoP.
async fn fresh_completion_qualification_at_cut(
    repo: &mut coauth_data::BoxRepository,
    handoff: &coauth_data::AccountHandoffGrant,
    dpop: &arkret_signatures::dpop::VerifiedDpopProof,
    clock: &dyn coauth_data::Clock,
) -> Result<DateTime<Utc>, ArkretRouteError> {
    let at = fresh_completion_handoff_at_cut(repo, handoff, clock).await?;
    require_completion_outer_dpop_fresh(dpop, clock.now())?;
    Ok(at)
}

fn require_completion_outer_dpop_fresh(
    dpop: &arkret_signatures::dpop::VerifiedDpopProof,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    let valid_through = crate::services::dpop::verified_proof_valid_through(dpop)
        .map_err(|error| signature_invalid(error.to_string()))?;
    require_outer_dpop_fresh(valid_through, now)
}

async fn exact_replay(
    depot: &Depot,
    record: coauth_data::RecoveryCompletionGrantIssuance,
    request: &RecoveryCompletionGrantRequestBody,
    canonical_request: &[u8],
    handoff: &coauth_data::AccountHandoffGrant,
    dpop: &arkret_signatures::dpop::VerifiedDpopProof,
    jti_to_consume: Option<&str>,
    clock: &dyn coauth_data::Clock,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let now = clock.now();
    require_completion_outer_dpop_fresh(dpop, now)?;
    let stored: RecoveryCompletionGrantRequestBody =
        serde_json::from_slice(&record.canonical_request)?;
    request
        .validate_exact_replay(&stored, &record.account_id, &dpop.jkt)
        .map_err(|error| duplicate_conflict(error.to_string()))?;
    if record.local_account_id != handoff.local_account_id
        || record.canonical_request != canonical_request
        || record.canonical_request_digest != request.canonical_request_digest
        || record.terminal_receipt_digest != request.terminal_receipt.receipt_digest()?
    {
        return Err(duplicate_conflict(
            "completion replay changed the original account or complete request",
        ));
    }
    let outcome: IssueRecoveryCompletionGrantResponseBody =
        serde_json::from_slice(&record.canonical_outcome)?;
    if outcome.transaction_id != record.transaction_id
        || outcome.issued_at != record.issued_at
        || outcome.issued_session.account_id != record.account_id
        || outcome.issued_session.issuer_id != record.issuer_id
        || arkret_canonical::canonical_json_bytes(&outcome)? != record.canonical_outcome
    {
        return Err(indeterminate_replay());
    }
    let mut repo = depot.repo().await?;
    let operation = repo
        .oauth_session_grant()
        .lock_operation(record.session_grant_operation_id)
        .await?;
    if operation.state != coauth_data::SessionGrantOperationState::Committed
        || operation.issuer_id != record.issuer_id
        || operation.result_grant_id.as_ref() != Some(&outcome.issued_session.session_grant_id)
        || operation.canonical_outcome.as_deref() != Some(record.canonical_outcome.as_slice())
        || operation.canonical_intent.as_deref() != Some(canonical_request)
    {
        return Err(indeterminate_replay());
    }
    let grant = repo
        .oauth_session_grant()
        .lookup_by_grant_id(&record.issuer_id, &outcome.issued_session.session_grant_id)
        .await?
        .ok_or_else(indeterminate_replay)?;
    if grant.session_grant != outcome.issued_session.session_grant
        || grant.issuance_operation_id != operation.id
    {
        return Err(indeterminate_replay());
    }
    if now >= grant.expires_at {
        return Err(ArkretRouteError::session_grant_replay_expired(
            grant.grant_id,
        ));
    }
    if let Some(state) = super::session_grant::replay_terminal_state(grant.lifecycle_state) {
        return Err(ArkretRouteError::session_grant_replay_terminal(
            grant.grant_id,
            state,
        ));
    }
    repo.cancel().await?;
    require_completion_outer_dpop_fresh(dpop, clock.now())?;
    let qualification_deadline = acquire_current_replay_authority(
        depot,
        &grant,
        &dpop.jkt,
        request.canonical_request_digest.clone(),
        now,
    )
    .await?;
    let mut repo = depot.repo().await?;
    lock_replay_issuer_qualification(&mut repo, &grant, &record).await?;
    let current_operation = repo
        .oauth_session_grant()
        .lock_operation(record.session_grant_operation_id)
        .await?;
    if current_operation != operation {
        return Err(indeterminate_replay());
    }
    let replay_at = fresh_completion_qualification_at_cut(&mut repo, handoff, dpop, clock).await?;
    validate_replay_deadline(replay_at, qualification_deadline, &grant)?;
    if let Some(jti) = jti_to_consume {
        if !repo
            .dpop_replay()
            .consume_jti(crate::services::dpop::dpop_replay_record(jti, replay_at))
            .await?
        {
            return Err(signature_invalid(
                "completion replay HTTP DPoP JTI was already consumed",
            ));
        }
    }
    let delivered_at =
        match fresh_completion_qualification_at_cut(&mut repo, handoff, dpop, clock).await {
            Ok(now) => now,
            Err(error) => {
                repo.cancel().await?;
                return Err(error);
            }
        };
    validate_replay_deadline(delivered_at, qualification_deadline, &grant)?;
    let current = repo
        .oauth_session_grant()
        .lookup_by_grant_id(&grant.issuer_id, &grant.grant_id)
        .await?
        .ok_or_else(indeterminate_replay)?;
    if let Some(state) = super::session_grant::replay_terminal_state(current.lifecycle_state) {
        return Err(ArkretRouteError::session_grant_replay_terminal(
            current.grant_id,
            state,
        ));
    }
    if current.session_grant != grant.session_grant || current.metadata != grant.metadata {
        return Err(indeterminate_replay());
    }
    if let Some(id) = current.browser_session_id {
        let browser = repo
            .browser_session()
            .lookup(id)
            .await?
            .ok_or_else(unauthenticated_handoff)?;
        if browser.finished_at.is_some() || browser.user.id != record.local_account_id {
            return Err(unauthenticated_handoff());
        }
    }
    let final_at =
        match fresh_completion_qualification_at_cut(&mut repo, handoff, dpop, clock).await {
            Ok(now) => now,
            Err(error) => {
                repo.cancel().await?;
                return Err(error);
            }
        };
    validate_replay_deadline(final_at, qualification_deadline, &grant)?;
    require_current_completion_issuer(depot, &record.issuer_id)?;
    repo.save().await?;
    Ok(ArkretCanonicalJson(record.canonical_outcome))
}

fn require_current_completion_issuer(
    depot: &Depot,
    expected: &arkret_identifiers::DidCoreId,
) -> Result<(), ArkretRouteError> {
    if owning_station_id_for(&depot.arkret_config()?) != *expected {
        return Err(signature_invalid(
            "completion issuer changed before outcome acceptance",
        ));
    }
    Ok(())
}

/// Current issuer lifecycle is read only after the remote qualification, in
/// the established head -> user -> accepted binding -> operation order.
async fn lock_replay_issuer_qualification(
    repo: &mut coauth_data::BoxRepository,
    grant: &coauth_data::SessionGrant,
    record: &coauth_data::RecoveryCompletionGrantIssuance,
) -> Result<(), ArkretRouteError> {
    let head = repo
        .account_status_ledger()
        .current_for_gate(
            record.issuer_id.as_str(),
            &record.local_account_id.to_string(),
        )
        .await?;
    let user = repo
        .user()
        .lookup_for_gate(record.local_account_id)
        .await?
        .ok_or_else(|| failed_precondition("replay account no longer exists"))?;
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience_for_gate(
            record.account_id.principal_id.as_str(),
            record.account_id.station_id.as_str(),
        )
        .await?
        .ok_or_else(|| failed_precondition("replay account binding no longer exists"))?;
    if user.status != AccountStatus::Active
        || binding.user_id != user.id
        || binding.account_id != record.account_id
        || grant.metadata.account_id != record.account_id
        || grant.local_account_id.as_str() != record.local_account_id.to_string()
        || record.reanchor_ref.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: binding.principal_control_realm_id.clone(),
            })
        || head.as_ref().is_some_and(|head| {
            head.status != user.status
                || head.account_id != binding.account_id
                || head.binding_version != binding.binding_version
        })
    {
        return Err(failed_precondition(
            "current replay issuer lifecycle or binding changed",
        ));
    }
    Ok(())
}

fn validate_replay_deadline(
    now: DateTime<Utc>,
    qualification_deadline: DateTime<Utc>,
    grant: &coauth_data::SessionGrant,
) -> Result<(), ArkretRouteError> {
    if now >= grant.expires_at {
        return Err(ArkretRouteError::session_grant_replay_expired(
            grant.grant_id.clone(),
        ));
    }
    if now >= qualification_deadline {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "current-device replay observation expired; retry the identical completion request",
        ));
    }
    Ok(())
}

async fn replay_after_race(
    depot: &Depot,
    request: &RecoveryCompletionGrantRequestBody,
    canonical_request: &[u8],
    handoff: &coauth_data::AccountHandoffGrant,
    dpop: &arkret_signatures::dpop::VerifiedDpopProof,
    clock: &dyn coauth_data::Clock,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let issuer = owning_station_id_for(&depot.arkret_config()?);
    let receipt = &request.terminal_receipt;
    let mut repo = depot.read_repo().await?;
    let record = repo
        .recovery_authority()
        .lookup_completion_issuance(&issuer, &receipt.account_id, &receipt.transaction_id)
        .await?
        .ok_or_else(indeterminate_replay)?;
    repo.cancel().await?;
    // First-admission authentication already consumed this JTI. The committed
    // racing outcome is still checked for all current qualifications below.
    exact_replay(
        depot,
        record,
        request,
        canonical_request,
        handoff,
        dpop,
        None,
        clock,
    )
    .await
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

/// The only source of a deterministic "renew PoP" decision. The lock remains
/// held by the caller through its first accept or negative decision transaction.
#[derive(Debug)]
enum CompletionAttempt {
    Accepted(Box<coauth_data::RecoveryCompletionGrantIssuance>),
    Unaccepted,
    ExpiredUnaccepted,
}

async fn inspect_completion_attempt(
    repo: &mut coauth_data::BoxRepository,
    request: &RecoveryCompletionGrantRequestBody,
    issuer: &arkret_identifiers::DidCoreId,
    clock: &dyn coauth_data::Clock,
) -> Result<CompletionAttempt, ArkretRouteError> {
    let receipt = &request.terminal_receipt;
    repo.recovery_authority()
        .lock_completion_business_key(issuer, &receipt.account_id, &receipt.transaction_id)
        .await?;
    if let Some(record) = repo
        .recovery_authority()
        .lookup_completion_issuance(issuer, &receipt.account_id, &receipt.transaction_id)
        .await?
    {
        return Ok(CompletionAttempt::Accepted(Box::new(record)));
    }
    // Read time after acquiring the lock. A candidate that was still doing
    // network qualification while an expiry probe won this lock cannot later
    // accept the expired body using its earlier captured time.
    if request.accepted_device_possession_proof.expires_at <= clock.now() {
        let request_identity = arkret_canonical::sha256_digest(request.operation_identity(issuer)?);
        if repo
            .oauth_session_grant()
            .lookup_operation_by_identity(
                issuer,
                coauth_data::SessionGrantOperationKind::Issue,
                Some(SessionGrantProofKind::AccountHandoff),
                &request_identity,
            )
            .await?
            .is_some()
        {
            return Err(indeterminate_replay());
        }
        return Ok(CompletionAttempt::ExpiredUnaccepted);
    }
    Ok(CompletionAttempt::Unaccepted)
}

fn expired_unaccepted_completion() -> ArkretRouteError {
    ArkretRouteError::CodedDetailed {
        status: StatusCode::UNAUTHORIZED,
        code: arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED,
        message: "no accepted completion exists at the serialized business key and the original PoP expired".into(),
        details: vec![("reason_code", serde_json::to_value(arkret_wire::ReasonCode::ProofInvalid)
            .expect("typed reason code serializes"))],
    }
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

// A verified completion attestation already proves this exact replacement was
// accepted. Losing its current binding is a fence of that known authorization,
// not the unknown-device case used by ordinary returning-device issuance.
fn recovery_completion_device_refusal(error: ArkretRouteError) -> ArkretRouteError {
    match error {
        ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::DEVICE_UNAUTHORIZED,
            ..
        } => ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_GENERATION_FENCED,
            "accepted recovery replacement is no longer current",
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_replacement_without_a_current_binding_is_generation_fenced() {
        let error = recovery_completion_device_refusal(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::DEVICE_UNAUTHORIZED,
            "no current binding",
        ));
        assert!(matches!(
            error,
            ArkretRouteError::Coded {
                status: StatusCode::CONFLICT,
                code: arkret_wire::ErrorCode::DEVICE_GENERATION_FENCED,
                ..
            }
        ));
    }

    #[test]
    fn unavailable_current_binding_does_not_become_a_device_refusal() {
        let error = recovery_completion_device_refusal(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "native gate unavailable",
        ));
        assert!(matches!(
            error,
            ArkretRouteError::Coded {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
    }
}

#[cfg(test)]
#[path = "recovery_authority/expiry_tests.rs"]
mod expiry_tests;
