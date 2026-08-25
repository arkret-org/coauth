use arkret_models_collaboration::session_grant_bodies::{
    AgentSessionGrantRequest, HumanSessionGrantRequest, RecoverySessionGrantRequest,
    SessionGrantOutcome, SessionGrantRequestBody,
};
use coauth_data::user::PrincipalDidRepository as _;
use coauth_data::{
    NewSessionGrantOperation, RepositoryAccess as _, SessionGrantCommitOutcome,
    SessionGrantOperation, SessionGrantReserveOutcome,
};
use salvo::prelude::*;
use sha2::Digest as _;

use super::*;
use crate::handlers::arkret::*;

pub struct CanonicalJsonResponse(Vec<u8>);

impl Scribe for CanonicalJsonResponse {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical JSON response body is writable");
    }
}

fn redact_session_grant_intent(
    body: &SessionGrantRequestBody,
) -> Result<serde_json::Value, ArkretRouteError> {
    let mut value =
        serde_json::to_value(body).map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let hash_value = |value: &serde_json::Value| -> Result<String, ArkretRouteError> {
        let bytes = arkret_canonical::canonical_json_bytes(value)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        Ok(format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(bytes))
        ))
    };
    if let Some(proof) = value
        .get_mut("proof")
        .and_then(serde_json::Value::as_object_mut)
    {
        for field in [
            "authorization_code",
            "code_verifier",
            "signature",
            "challenge",
            "state",
            "nonce",
        ] {
            if let Some(secret) = proof.get(field) {
                let digest = hash_value(secret)?;
                proof.insert(field.to_owned(), serde_json::Value::String(digest));
            }
        }
    }
    if let Some(binding) = value
        .get_mut("dpop_binding_proof")
        .and_then(serde_json::Value::as_object_mut)
        && let Some(proof_jwt) = binding.get("proof_jwt")
    {
        let digest = hash_value(proof_jwt)?;
        binding.insert("proof_jwt".to_owned(), serde_json::Value::String(digest));
    }
    if let Some(proof) = value
        .get_mut("accepted_device_possession_proof")
        .and_then(serde_json::Value::as_object_mut)
    {
        // Exact replay is identified by request_id and the signed stable
        // session_intent_digest. Re-signing the same intent must not create a
        // different issuer operation merely because its freshness window or
        // detached signature changed.
        for field in ["issued_at", "expires_at", "signature"] {
            proof.remove(field);
        }
    }
    Ok(value)
}

async fn reserve_issue_operation(
    depot: &Depot,
    body: &SessionGrantRequestBody,
    holder_jkt: &str,
    expires_at_cap: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Result<SessionGrantOperation, Vec<u8>>, ArkretRouteError> {
    let redacted_request = redact_session_grant_intent(body)?;
    let canonical_intent = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "request": redacted_request,
        "holder_jkt": holder_jkt,
    }))
    .map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            format!("session-grant request canonicalization failed: {error}"),
        )
    })?;
    let canonical_intent_digest: [u8; 32] = sha2::Sha256::digest(&canonical_intent).into();
    let (proof_kind, identity_material, ttl_cap) = match body {
        SessionGrantRequestBody::Human(request) => (
            arkret_models_identity::SessionGrantProofKind::AccountHandoff,
            serde_json::json!({
                "proof_kind": "account_handoff",
                "request_id": request.request_id,
            }),
            None,
        ),
        SessionGrantRequestBody::Recovery(request) => (
            arkret_models_identity::SessionGrantProofKind::AccountHandoff,
            serde_json::json!({
                "proof_kind": "account_handoff_recovery_session",
                "request_id": request.request_id,
            }),
            Some(chrono::Duration::minutes(15)),
        ),
        SessionGrantRequestBody::Agent(request) => (
            arkret_models_identity::SessionGrantProofKind::AgentKeyProof,
            serde_json::json!({
                "proof_kind": "agent_key_proof",
                "authorization_ref": request.agent_key_authorization_ref,
                "verification_method": request.proof.verification_method,
                "challenge": request.proof.challenge,
            }),
            Some(crate::handlers::account::agents::AGENT_SESSION_MAX_TTL),
        ),
    };
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity_material)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let request_identity = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(identity_bytes))
    );
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut grant_ttl = depot.arkret_config()?.session_grant_ttl;
    if let Some(ttl_cap) = ttl_cap {
        grant_ttl = grant_ttl.min(ttl_cap);
    }
    let grant_expires_at = expires_at_cap
        .map(|cap| (now + grant_ttl).min(cap))
        .unwrap_or(now + grant_ttl);
    if grant_expires_at <= now {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "account handoff expires before a recovery session grant can be issued",
        ));
    }
    let signing_key_store = depot.key_store()?;
    let (_, signing_key) = preferred_signing_key(&signing_key_store)
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?;
    let signing_key_id = signing_key
        .kid()
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?
        .to_owned();
    // Tombstones must outlive both the issued credential and ordinary delayed
    // retry horizons. A committed operation can still retain its canonical
    // outcome longer in storage policy; this is the minimum requested here.
    let retained_until = now + depot.arkret_config()?.session_grant_ttl + chrono::Duration::days(7);
    let issuer = service_id_for(&depot.arkret_config()?);
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer,
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: Some(proof_kind),
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_session_grant_id: None,
                issuance_nonce: None,
                session_id: None,
                grant_not_before: Some(now),
                grant_expires_at: Some(grant_expires_at),
                signing_key_id: Some(&signing_key_id),
                retained_until,
            },
        )
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    match reserved {
        SessionGrantReserveOutcome::Reserved(operation) => {
            // The reservation must be durable before any OIDC code, handoff or
            // agent proof can be consumed in a later transaction.
            repo.save().await?;
            Ok(Ok(operation))
        }
        SessionGrantReserveOutcome::Replay(operation) => {
            let grant_id = operation.result_grant_id.as_ref().ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "committed issue operation has no result grant identity",
                )
            })?;
            let grant = repo
                .oauth_session_grant()
                .lookup_by_grant_id(grant_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "committed issue operation result grant is no longer provable",
                    )
                })?;
            if grant.expires_at <= now {
                return Err(ArkretRouteError::session_grant_replay_expired(
                    grant.grant_id,
                ));
            }
            if grant.lifecycle_state != coauth_data::SessionGrantLifecycleState::Active {
                let state = match grant.lifecycle_state {
                    coauth_data::SessionGrantLifecycleState::Revoked => {
                        arkret_wire::SessionGrantReplayTerminalState::Revoked
                    }
                    coauth_data::SessionGrantLifecycleState::Superseded => {
                        arkret_wire::SessionGrantReplayTerminalState::Superseded
                    }
                    coauth_data::SessionGrantLifecycleState::Active => unreachable!(),
                };
                return Err(ArkretRouteError::session_grant_replay_terminal(
                    grant.grant_id,
                    state,
                ));
            }
            let outcome = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "committed session-grant operation has no retained canonical outcome",
                )
            })?;
            repo.cancel().await.ok();
            Ok(Err(outcome))
        }
        SessionGrantReserveOutcome::Pending(operation)
            if operation.state == coauth_data::SessionGrantOperationState::Reserved =>
        {
            repo.cancel().await.ok();
            Ok(Ok(operation))
        }
        SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "session-grant operation outcome is indeterminate; one-shot proof will not be consumed again",
            ))
        }
        SessionGrantReserveOutcome::Indeterminate(_) => {
            // The repository may have just evicted sensitive replay material
            // while retaining the request-identity tombstone. Commit that
            // transition before surfacing the fail-closed result.
            repo.save().await?;
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "session-grant operation replay material is unavailable",
            ))
        }
        SessionGrantReserveOutcome::Conflict(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "request identity was already used with a different canonical intent",
            ))
        }
    }
}

// ── Canonical Account Authority session-grant issuance ─────────────
//
// Human issuance consumes a Bound AccountHandoff plus an accepted-device PoP.
// Agent issuance is a separate scoped request variant. OIDC authorization
// codes are consumed only by AccountHandoff creation.

/// `POST /_arkret/gate/account/session-grants` — canonical session-grant
/// issuance. Returns the SDK `SessionGrantOutcome`.
#[handler]
pub async fn issue_session_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<CanonicalJsonResponse, ArkretRouteError> {
    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    require_principal_id(&raw_body)?;
    let body: SessionGrantRequestBody =
        serde_json::from_value(raw_body.clone()).map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                error.to_string(),
            )
        })?;
    body.validate().map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            error.to_string(),
        )
    })?;
    match body {
        SessionGrantRequestBody::Agent(agent) => {
            let dpop_binding = extract_kickoff_dpop(req, depot).await?;
            let binding =
                require_agent_key_proof_dpop_binding(dpop_binding, &agent.dpop_binding_proof)?;
            let request = SessionGrantRequestBody::Agent(agent.clone());
            let operation =
                match reserve_issue_operation(depot, &request, &binding.jkt, None).await? {
                    Ok(operation) => operation,
                    Err(outcome) => return Ok(CanonicalJsonResponse(outcome)),
                };
            issue_agent_key_proof_session_grant(req, depot, binding, &agent, operation).await
        }
        SessionGrantRequestBody::Human(human) => {
            let (handoff_token, dpop) =
                super::super::account_handoff::verify_account_handoff_holder_without_lookup(
                    req, depot,
                )?;
            validate_human_issue_proof_before_reservation(&human, &handoff_token, &dpop.jkt)?;
            let request = SessionGrantRequestBody::Human(human.clone());
            let operation = match reserve_issue_operation(depot, &request, &dpop.jkt, None).await? {
                Ok(operation) => operation,
                Err(outcome) => return Ok(CanonicalJsonResponse(outcome)),
            };
            issue_account_handoff_session_grant(depot, &human, handoff_token, dpop, operation).await
        }
        SessionGrantRequestBody::Recovery(recovery) => {
            let (handoff_token, dpop) =
                super::super::account_handoff::verify_account_handoff_holder_without_lookup(
                    req, depot,
                )?;
            let handoff_expires_at = validate_recovery_handoff_request_before_reservation(
                depot,
                &handoff_token,
                &dpop.jkt,
                &recovery,
            )
            .await?;
            let request = SessionGrantRequestBody::Recovery(recovery.clone());
            let operation =
                match reserve_issue_operation(depot, &request, &dpop.jkt, Some(handoff_expires_at))
                    .await?
                {
                    Ok(operation) => operation,
                    Err(outcome) => {
                        consume_recovery_dpop_jti(depot, &dpop).await?;
                        return Ok(CanonicalJsonResponse(outcome));
                    }
                };
            issue_recovery_session_grant(depot, &recovery, handoff_token, dpop, operation).await
        }
    }
}

async fn validate_recovery_handoff_request_before_reservation(
    depot: &Depot,
    handoff_token: &str,
    holder_jkt: &str,
    body: &RecoverySessionGrantRequest,
) -> Result<chrono::DateTime<chrono::Utc>, ArkretRouteError> {
    use coauth_data::storage::user::BrowserSessionRepository as _;
    use coauth_data::user::UserRepository as _;

    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut repo = depot.repo().await?;
    let handoff = repo
        .account_handoff()
        .get_active_by_token(handoff_token, now)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff is no longer active for recovery session issuance",
            )
        })?;
    super::super::account_handoff::enforce_handoff_operation(
        &handoff,
        arkret_models_identity::AccountHandoffAllowedOperation::IssueSessionGrant,
    )?;
    if handoff.cnf_jkt != holder_jkt || handoff.audience != body.audience.as_str() {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            "recovery request does not match the AccountHandoff holder or audience",
        ));
    }
    let user = repo
        .user()
        .lookup(handoff.service_account_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    repo.principal_did()
        .get_for_user_and_audience(&user, &handoff.audience)
        .await?
        .filter(|binding| binding.principal_id == body.principal_id)
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "recovery request principal is not bound to the authenticated account",
            )
        })?;
    let browser_session_id = handoff.browser_session_id.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "account handoff has no authenticated browser session",
        )
    })?;
    repo.browser_session()
        .lookup(browser_session_id)
        .await?
        .filter(|session| session.user.id == user.id && session.active())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff browser session is no longer active",
            )
        })?;
    let expires_at = handoff.expires_at;
    repo.cancel().await.ok();
    Ok(expires_at)
}

async fn consume_recovery_dpop_jti(
    depot: &Depot,
    dpop: &crate::services::dpop::DpopVerification,
) -> Result<(), ArkretRouteError> {
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut repo = depot.repo().await?;
    if !repo
        .dpop_replay()
        .consume_jti(crate::services::dpop::dpop_replay_record(
            &dpop.claims.jti,
            now,
        ))
        .await?
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            "reason_code=proof_invalid; handoff DPoP JTI was already consumed",
        ));
    }
    repo.save().await?;
    Ok(())
}

/// Exchange a server-authoritative Bound account handoff for a Standard
/// session on an already-authorized device.
///
/// OIDC is consumed when the handoff is created. This branch deliberately
/// does not perform another OIDC exchange: the handoff identifies the account,
/// its holder key signs this request, and the Principal Server independently
/// gates the requested durable device against revocation.
fn validate_human_issue_proof_before_reservation(
    body: &HumanSessionGrantRequest,
    handoff_token: &str,
    holder_jkt: &str,
) -> Result<(), ArkretRouteError> {
    let proof = &body.accepted_device_possession_proof;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    if proof.issued_at > now + chrono::Duration::minutes(5) || proof.expires_at <= now {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ReasonCode::PROOF_INVALID,
            "reason_code=proof_invalid; accepted-device issue proof is outside its validity window",
        ));
    }
    if proof.holder_jkt != holder_jkt {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ReasonCode::PROOF_INVALID,
            "reason_code=proof_invalid; accepted-device proof holder key does not match DPoP",
        ));
    }
    let handoff_digest = arkret_identifiers::Hash::new(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(handoff_token.as_bytes()))
    ))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if proof.account_handoff_grant_digest != handoff_digest {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ReasonCode::PROOF_INVALID,
            "reason_code=proof_invalid; accepted-device proof does not bind the presented AccountHandoff",
        ));
    }
    Ok(())
}

async fn issue_account_handoff_session_grant(
    depot: &Depot,
    body: &HumanSessionGrantRequest,
    handoff_token: String,
    dpop: crate::services::dpop::DpopVerification,
    operation: SessionGrantOperation,
) -> Result<CanonicalJsonResponse, ArkretRouteError> {
    use arkret_models_identity::{AccountHandoffAllowedOperation, SessionGrantProofKind};
    use coauth_data::storage::user::BrowserSessionRepository as _;
    use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};

    let proof_invalid = |message: &str| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            format!("reason_code=proof_invalid; {message}"),
        )
    };
    let proof = &body.accepted_device_possession_proof;
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let proof_expires_at = proof.expires_at;

    // Read and validate prerequisites, then release the transaction before the
    // cross-service device revocation check.
    let mut repo = depot.repo().await?;
    let handoff = repo
        .account_handoff()
        .get_active_by_token(&handoff_token, now)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff is no longer active for session issuance",
            )
        })?;
    super::super::account_handoff::enforce_handoff_operation(
        &handoff,
        AccountHandoffAllowedOperation::IssueSessionGrant,
    )?;
    if dpop.jkt != handoff.cnf_jkt || body.audience.as_str() != handoff.audience {
        repo.cancel().await.ok();
        return Err(proof_invalid(
            "AccountHandoff holder key or audience does not match",
        ));
    }
    let user = repo
        .user()
        .lookup(handoff.service_account_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    let expected_account_subject = super::super::account_handoff::account_subject(
        &service_id_for(&depot.arkret_config()?),
        user.id,
    )?;
    if proof.account_subject != expected_account_subject {
        repo.cancel().await.ok();
        return Err(proof_invalid(
            "accepted-device proof account subject does not match AccountHandoff",
        ));
    }
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, &handoff.audience)
        .await?
        .filter(|binding| binding.principal_id == body.principal_id)
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "principal binding is missing",
            )
        })?;
    let browser_session_id = handoff.browser_session_id.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "account handoff has no authenticated browser session",
        )
    })?;
    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .filter(|session| session.user.id == user.id && session.active())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff browser session is no longer active",
            )
        })?;
    let handoff_id = handoff.id;
    let handoff_service_account_id = handoff.service_account_id;
    let handoff_audience = handoff.audience.clone();
    let handoff_cnf_jkt = handoff.cnf_jkt.clone();
    let handoff_expires_at = handoff.expires_at;
    repo.cancel().await.ok();

    let device_id = body.device_id.clone();
    let device_binding = acquire_human_device_binding(
        depot,
        &binding.principal_authority,
        device_id.clone(),
        arkret_wire::DeviceRevocationGateActionClass::ReturningSessionGrantIssue,
        None,
        Some(arkret_wire::AcceptedDevicePossessionProof::Issue(
            proof.clone(),
        )),
        proof.session_intent_digest.clone(),
        now,
    )
    .await?;
    let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let granted_scope = arkret_models_identity::STANDARD_INITIAL_SESSION_GRANT_OPERATIONS
        .map(|operation| operation.as_str().to_owned())
        .to_vec();
    let material = issue_session_grant_for_audience(
        &issuance_seed,
        &*clock,
        &depot.arkret_config()?,
        &depot.key_store()?,
        &browser_session,
        dpop.jwk.clone(),
        handoff_audience.clone(),
        device_id.clone(),
        granted_scope,
        Some(binding.principal_id.as_str()),
        &binding.principal_authority,
        dpop.jkt.clone(),
        device_binding,
        SessionGrantProofKind::AccountHandoff,
    )
    .map_err(map_session_grant_material_error)?;
    let wire_outcome = SessionGrantOutcome {
        principal_id: binding.principal_id.clone(),
        device_id: Some(device_id),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        session_grant_id: material.grant_id.clone(),
        session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
            &material.session_public_key,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        audience: body.audience.clone(),
        granted_scope: material.scopes.clone(),
        scope_details: None,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&wire_outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    // Commit the issuer-ledger operation, handoff consumption and HTTP DPoP
    // JTI in one transaction so response loss can replay the exact canonical
    // outcome. Do not consume either one-time credential before the ledger
    // tells us this transaction owns the commit: a final-ledger race or an
    // indeterminate result must roll this transaction back intact.
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;
    let current_handoff = repo
        .account_handoff()
        .get_active_by_token(&handoff_token, now)
        .await?
        .filter(|current| {
            current.id == handoff_id
                && current.service_account_id == handoff_service_account_id
                && current.audience == handoff_audience
                && current.cnf_jkt == handoff_cnf_jkt
        })
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff changed or was consumed before session commit",
            )
        })?;
    let checkpoint = serde_json::json!({
        "kind": "account_handoff",
        "handoff_grant_id": handoff_id.to_string(),
        "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&dpop.claims.jti),
    });
    let committed = commit_session_grant_issuance(
        &mut repo,
        &mut rng,
        &*clock,
        operation.id,
        &format!("account-handoff:{handoff_id}"),
        &checkpoint,
        proof_expires_at.min(handoff_expires_at),
        &canonical_outcome,
        Some(browser_session_id),
        &material,
    )
    .await
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    match committed {
        SessionGrantCommitOutcome::Committed(_) => {
            if !repo
                .account_handoff()
                .consume_grant(&current_handoff, now)
                .await?
            {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::FAILED_PRECONDITION,
                    "account handoff was already consumed",
                ));
            }
            if !repo
                .dpop_replay()
                .consume_jti(crate::services::dpop::dpop_replay_record(
                    &dpop.claims.jti,
                    now,
                ))
                .await?
            {
                repo.cancel().await.ok();
                return Err(proof_invalid("handoff DPoP JTI was already consumed"));
            }
            repo.save().await?;
            Ok(CanonicalJsonResponse(canonical_outcome))
        }
        SessionGrantCommitOutcome::Replay(operation) => {
            repo.cancel().await.ok();
            operation
                .canonical_outcome
                .map(CanonicalJsonResponse)
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "replayed handoff issuance has no canonical outcome",
                    )
                })
        }
        SessionGrantCommitOutcome::Indeterminate(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "handoff session issuance outcome is indeterminate",
            ))
        }
    }
}

async fn issue_recovery_session_grant(
    depot: &Depot,
    body: &RecoverySessionGrantRequest,
    handoff_token: String,
    dpop: crate::services::dpop::DpopVerification,
    operation: SessionGrantOperation,
) -> Result<CanonicalJsonResponse, ArkretRouteError> {
    use coauth_data::storage::user::BrowserSessionRepository as _;
    use coauth_data::user::UserRepository as _;

    let proof_invalid = |message: &str| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            format!("reason_code=proof_invalid; {message}"),
        )
    };
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut repo = depot.repo().await?;
    let handoff = repo
        .account_handoff()
        .get_active_by_token(&handoff_token, now)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff is no longer active for recovery session issuance",
            )
        })?;
    super::super::account_handoff::enforce_handoff_operation(
        &handoff,
        arkret_models_identity::AccountHandoffAllowedOperation::IssueSessionGrant,
    )?;
    if dpop.jkt != handoff.cnf_jkt || body.audience.as_str() != handoff.audience {
        repo.cancel().await.ok();
        return Err(proof_invalid(
            "AccountHandoff holder key or audience does not match recovery request",
        ));
    }
    let user = repo
        .user()
        .lookup(handoff.service_account_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, &handoff.audience)
        .await?
        .filter(|binding| binding.principal_id == body.principal_id)
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "principal binding is missing",
            )
        })?;
    let browser_session_id = handoff.browser_session_id.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "account handoff has no authenticated browser session",
        )
    })?;
    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .filter(|session| session.user.id == user.id && session.active())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff browser session is no longer active",
            )
        })?;
    let handoff_id = handoff.id;
    let handoff_service_account_id = handoff.service_account_id;
    let handoff_audience = handoff.audience.clone();
    let handoff_cnf_jkt = handoff.cnf_jkt.clone();
    let handoff_expires_at = handoff.expires_at;
    repo.cancel().await.ok();

    let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if issuance_seed.expires_at > handoff_expires_at {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "recovery session grant would outlive its AccountHandoff",
        ));
    }
    let granted_scope = arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS
        .map(str::to_owned)
        .to_vec();
    let material = issue_recovery_session_grant_for_audience(
        &issuance_seed,
        &depot.arkret_config()?,
        &depot.key_store()?,
        dpop.jwk.clone(),
        handoff_audience.clone(),
        body.device_id.clone(),
        granted_scope,
        binding.principal_id.as_str(),
        &binding.principal_authority,
        dpop.jkt.clone(),
    )
    .map_err(map_session_grant_material_error)?;
    let wire_outcome = SessionGrantOutcome {
        principal_id: binding.principal_id,
        device_id: Some(body.device_id.clone()),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        session_grant_id: material.grant_id.clone(),
        session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
            &material.session_public_key,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        audience: body.audience.clone(),
        granted_scope: material.scopes.clone(),
        scope_details: None,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&wire_outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let mut rng = crate::handlers::make_rng();
    let commit_now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut repo = depot.repo().await?;
    let current_handoff = repo
        .account_handoff()
        .get_active_by_token(&handoff_token, commit_now)
        .await?
        .filter(|current| {
            current.id == handoff_id
                && current.service_account_id == handoff_service_account_id
                && current.audience == handoff_audience
                && current.cnf_jkt == handoff_cnf_jkt
        })
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account handoff changed or was consumed before recovery grant commit",
            )
        })?;
    let checkpoint = serde_json::json!({
        "kind": "account_handoff_recovery_session",
        "handoff_grant_id": current_handoff.id.to_string(),
        "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&dpop.claims.jti),
    });
    let committed = commit_session_grant_issuance(
        &mut repo,
        &mut rng,
        &*clock,
        operation.id,
        &format!("account-handoff-recovery:{handoff_id}"),
        &checkpoint,
        handoff_expires_at,
        &canonical_outcome,
        Some(browser_session.id),
        &material,
    )
    .await
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    match committed {
        SessionGrantCommitOutcome::Committed(_) => {
            if !repo
                .dpop_replay()
                .consume_jti(crate::services::dpop::dpop_replay_record(
                    &dpop.claims.jti,
                    commit_now,
                ))
                .await?
            {
                repo.cancel().await.ok();
                return Err(proof_invalid("handoff DPoP JTI was already consumed"));
            }
            repo.save().await?;
            Ok(CanonicalJsonResponse(canonical_outcome))
        }
        SessionGrantCommitOutcome::Replay(operation) => {
            let outcome = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "replayed recovery grant issuance has no canonical outcome",
                )
            })?;
            if !repo
                .dpop_replay()
                .consume_jti(crate::services::dpop::dpop_replay_record(
                    &dpop.claims.jti,
                    commit_now,
                ))
                .await?
            {
                repo.cancel().await.ok();
                return Err(proof_invalid("handoff DPoP JTI was already consumed"));
            }
            repo.save().await?;
            Ok(CanonicalJsonResponse(outcome))
        }
        SessionGrantCommitOutcome::Indeterminate(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "recovery grant issuance outcome is indeterminate",
            ))
        }
    }
}

async fn extract_kickoff_dpop(
    req: &Request,
    depot: &Depot,
) -> Result<Option<crate::handlers::account::auth::DpopSessionBinding>, ArkretRouteError> {
    let url_builder = depot.url_builder()?;
    crate::handlers::account::auth::extract_dpop_binding_for_kickoff_without_replay(
        req,
        depot,
        &url_builder,
    )
    .map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            format!("reason_code=proof_invalid; invalid grant-binding DPoP proof: {error}"),
        )
    })
}

fn require_agent_key_proof_dpop_binding(
    binding: Option<crate::handlers::account::auth::DpopSessionBinding>,
    body_binding: &arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof,
) -> Result<crate::handlers::account::auth::DpopSessionBinding, ArkretRouteError> {
    let binding = binding.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
            "agent_key_proof session grant requires a grant-binding DPoP proof",
        )
    })?;
    if body_binding.proof_jwt != binding.proof_jwt {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            "reason_code=proof_invalid; DPoP header does not match body dpop_binding_proof",
        ));
    }
    Ok(binding)
}

/// AKP-0008 §4.6 agent runtime authentication branch. Validates the
/// `agent_key_proof`, intersects scope, and mints a ≤ 15-minute device-bound
/// session grant. Returns the SDK `SessionGrantOutcome` with the
/// `scope_details` overlay. Human-approval and fail-closed rejections surface
/// as structured errors.
async fn issue_agent_key_proof_session_grant(
    _req: &mut Request,
    depot: &Depot,
    dpop_binding: crate::handlers::account::auth::DpopSessionBinding,
    body: &AgentSessionGrantRequest,
    operation: SessionGrantOperation,
) -> Result<CanonicalJsonResponse, ArkretRouteError> {
    use crate::handlers::account::agents::{
        AgentSessionProofError, enforce_authoritative_agent_lifecycle, validate_agent_session_proof,
    };

    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    let mut repo = depot.repo().await?;
    let agent_id = body.principal_id.as_str();
    let authoritative_agent =
        match enforce_authoritative_agent_lifecycle(&http_client, &arkret_config, agent_id).await {
            Ok(view) => view,
            Err(rejection) => {
                repo.cancel().await.ok();
                let message = match rejection.reason_code() {
                    Some(reason) => format!("reason_code={reason}; {}", rejection.code()),
                    None => rejection.code().to_owned(),
                };
                return Err(ArkretRouteError::coded(
                    rejection.http_status(),
                    rejection.code(),
                    message,
                ));
            }
        };
    let authorization = match validate_agent_session_proof(
        &mut repo,
        &mut rng,
        &*clock,
        &url_builder,
        &arkret_config,
        &authoritative_agent,
        body,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(AgentSessionProofError::Rejection(rejection)) => {
            repo.cancel().await.ok();
            let status = rejection.http_status();
            // Surface the machine-readable reason next to the registry code
            // (key-management §3.6.1: the runtime must be able to tell
            // `agent_key_authorization_expired` apart from `proof_invalid`).
            let message = match rejection.reason_code() {
                Some(reason) => format!("reason_code={reason}; {}", rejection.code()),
                None => rejection.code().to_owned(),
            };
            return Err(ArkretRouteError::coded(status, rejection.code(), message));
        }
        Err(AgentSessionProofError::HumanApprovalRequired(approval)) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::HumanApprovalRequired(approval));
        }
    };

    let audience = body.proof.audience.clone();

    // Controller lifecycle gate: a deactivated / suspended controller fails
    // closed (AKP-0008 §4.6). Resolve the controller's local user record when
    // the DID maps to a coauth-hosted account. Bind the lookup to an owned
    // value so the sub-repo borrow is released before `repo.cancel()`.
    let controller_binding = repo
        .principal_did()
        .get_by_did_and_audience(&authorization.controller_id, audience.as_str())
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let controller_blocked = if let Some(binding) = controller_binding {
        let user = repo
            .user()
            .lookup(binding.user_id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        user.is_some_and(|user| user.locked_at.is_some() || user.deactivated_at.is_some())
    } else {
        false
    };
    if controller_blocked {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "accountable controller is deactivated or suspended",
        ));
    }

    // The agent runtime authenticates with its own key, not a human browser
    // session, so there is no browser-session anchor to persist against. The
    // grant is a self-validating signed `ak.session.grant` JWT bound to the
    // runtime's DPoP key with the capped agent TTL; soland verifies the coauth
    // issuer signature and rechecks agent status inside the revocation
    // freshness window (AKP-0008 §4.11 natural-expiry path), bounded by the
    // ≤ 15-minute TTL.
    let now = clock.now();
    let expires_at = now + authorization.ttl;

    let session_public_key = serde_json::to_string(&dpop_binding.public_jwk).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(error))
    })?;
    let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let material = mint_agent_session_grant(
        &issuance_seed,
        &arkret_config,
        &key_store,
        &authorization.agent_id,
        &body.device_id,
        audience.to_string(),
        authorization.granted_scope.clone(),
        dpop_binding.jkt.clone(),
        session_public_key,
        authorization.scope_details.clone(),
        arkret_identifiers::EventId::new(body.agent_key_authorization_ref.clone())
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        body.proof.verification_method.clone(),
        now,
        expires_at,
    )
    .map_err(map_session_grant_material_error)?;

    let principal_id =
        arkret_identifiers::DidCoreId::new(authorization.agent_id.clone()).map_err(|e| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "agent principal is not a valid DID: {e}"
            )))
        })?;

    // grant_id / session_public_key / audience are SessionGrantOutcome
    // top-level fields (mirroring SessionGrantRefreshOutcome), NOT entries in
    // `scope_details`. The wire `scope_details` carries only the spec-typed
    // agent overlay (AKP-0008 §4.6); the JWT-internal scope details with the
    // canonical constraint projection are already baked into the minted grant
    // above.
    let grant_id = material.grant_id.clone();
    let wire_audience =
        arkret_identifiers::DidCoreId::new(material.audience.clone()).map_err(|e| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "issued agent grant carried a non-DID audience: {e}"
            )))
        })?;

    let wire_outcome = SessionGrantOutcome {
        principal_id,
        device_id: Some(body.device_id.clone()),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        session_grant_id: grant_id,
        session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
            &material.session_public_key,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        audience: wire_audience,
        granted_scope: material.scopes.clone(),
        scope_details: Some(authorization.wire_scope_details),
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&wire_outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let checkpoint = serde_json::json!({
        "kind": "agent_key_proof",
        "agent_key_authorization_ref": body.agent_key_authorization_ref,
        "verification_method": body.proof.verification_method,
        "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&dpop_binding.jti),
    });
    let authorization_ref = format!("agent:{}", body.agent_key_authorization_ref);
    let committed = commit_session_grant_issuance(
        &mut repo,
        &mut rng,
        &*clock,
        operation.id,
        &authorization_ref,
        &checkpoint,
        body.proof.expires_at,
        &canonical_outcome,
        None,
        &material,
    )
    .await
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    match committed {
        SessionGrantCommitOutcome::Committed(_) => {
            let inserted = repo
                .dpop_replay()
                .consume_jti(crate::services::dpop::dpop_replay_record(
                    &dpop_binding.jti,
                    clock.now(),
                ))
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            if !inserted {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::SIGNATURE_INVALID,
                    "reason_code=proof_invalid; agent DPoP JTI was already consumed",
                ));
            }
            repo.save()
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            super::super::test_chaos::maybe_delay_post_commit(
                "session_grant_issue_post_commit_pre_response",
                &operation.request_identity,
            )
            .await;
            Ok(CanonicalJsonResponse(canonical_outcome))
        }
        SessionGrantCommitOutcome::Replay(operation) => {
            repo.cancel().await.ok();
            let bytes = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "replayed agent operation has no canonical outcome",
                )
            })?;
            Ok(CanonicalJsonResponse(bytes))
        }
        SessionGrantCommitOutcome::Indeterminate(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "agent issuance outcome is indeterminate",
            ))
        }
    }
}

fn require_principal_id(raw_body: &serde_json::Value) -> Result<(), ArkretRouteError> {
    if raw_body
        .get("principal_id")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|principal_id| principal_id.trim().is_empty())
    {
        return Err(ArkretRouteError::coded(
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
            "principal_unknown",
        ));
    }
    Ok(())
}

fn map_session_grant_material_error(error: SessionGrantError) -> ArkretRouteError {
    match error {
        SessionGrantError::PrincipalUnknown => ArkretRouteError::coded(
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
            "principal_unknown",
        ),
        other => ArkretRouteError::Internal(Box::new(other)),
    }
}

pub(crate) fn map_oidc_exchange_error(
    error: crate::handlers::account::auth::oidc_bridge::OidcExchangeError,
) -> ArkretRouteError {
    if error.code == arkret_wire::ErrorCode::INTERNAL_ERROR {
        return ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
            error.message,
        ));
    }
    let (status, code) = match error.code {
        arkret_wire::ReasonCode::PROOF_INVALID
        | "invalid_authorization_code"
        | "invalid_client" => (
            StatusCode::UNAUTHORIZED,
            arkret_wire::ReasonCode::PROOF_INVALID,
        ),
        "invalid_audience" => (
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
        ),
        "invalid_request" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        ),
        "invalid_discovery_binding" => (
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
        ),
        "upstream_link_required" => (
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::CLAIM_REQUIRED,
        ),
        "principal_unknown" => (
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
        ),
        code @ (arkret_wire::ErrorCode::DEVICE_REVOCATION_PENDING
        | arkret_wire::ErrorCode::DEVICE_REVOKED) => (StatusCode::CONFLICT, code),
        // Account lifecycle statuses are context-dependent: the Spec registry
        // splits them per entry point, and issuance is the
        // `session_issuance_or_refresh` context. Read the split from the
        // generated table rather than restating it here.
        "account_locked" | "account_suspended" | "account_deactivated" | "account_erased" => {
            let code = arkret_wire::ErrorCode::from_wire(error.code)
                .expect("account lifecycle codes are registered");
            (
                super::account_lifecycle_status(
                    code,
                    arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh,
                ),
                code.as_str(),
            )
        }
        "account_unavailable" | "principal_account_registration_failed" => (
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
        ),
        "session_grant_denied" => (StatusCode::FORBIDDEN, arkret_wire::ErrorCode::POLICY_DENIED),
        _ => (
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        ),
    };
    let message = if error.code == code {
        error.message
    } else {
        format!("reason_code={}; {}", error.code, error.message)
    };
    ArkretRouteError::coded(status, code, message)
}

#[cfg(test)]
mod tests {
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::jwk::{JsonWebKeyPublicParameters, PublicJsonWebKey};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    use super::*;
    use crate::handlers::account::auth::DpopSessionBinding;
    use crate::handlers::account::auth::oidc_bridge::OidcExchangeError;

    fn test_dpop_binding(proof_jwt: &str) -> DpopSessionBinding {
        let signing = SigningKey::generate(&mut OsRng);
        let public_jwk =
            PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&signing.verifying_key()))
                .with_alg(JsonWebSignatureAlg::Ed25519);
        DpopSessionBinding {
            proof_jwt: proof_jwt.to_owned(),
            jti: "test-jti".to_owned(),
            jkt: "test-jkt".to_owned(),
            public_jwk,
        }
    }

    fn assert_coded(error: ArkretRouteError, expected_status: StatusCode, expected_code: &str) {
        match error {
            ArkretRouteError::Coded { status, code, .. } => {
                assert_eq!(status, expected_status);
                assert_eq!(code, expected_code);
            }
            other => panic!("expected coded error, got {other:?}"),
        }
    }

    fn unwrap_binding_error(
        result: Result<DpopSessionBinding, ArkretRouteError>,
    ) -> ArkretRouteError {
        match result {
            Ok(_) => panic!("expected DPoP binding rejection"),
            Err(error) => error,
        }
    }

    #[test]
    fn oidc_exchange_binding_errors_surface_as_proof_invalid() {
        let err = map_oidc_exchange_error(OidcExchangeError {
            code: "invalid_authorization_code",
            message: "authorization code was already exchanged".to_owned(),
        });

        match err {
            ArkretRouteError::Coded {
                status,
                code,
                message,
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(code, arkret_wire::ReasonCode::PROOF_INVALID);
                assert!(message.contains("reason_code=invalid_authorization_code"));
            }
            other => panic!("expected coded error, got {other:?}"),
        }
    }

    #[test]
    fn oidc_internal_errors_use_the_environment_aware_internal_renderer() {
        let error = map_oidc_exchange_error(OidcExchangeError {
            code: arkret_wire::ErrorCode::INTERNAL_ERROR,
            message: "upstream database detail".to_owned(),
        });

        match error {
            ArkretRouteError::Internal(source) => {
                assert_eq!(source.to_string(), "upstream database detail");
            }
            other => panic!("expected internal error, got {other:?}"),
        }
    }

    #[test]
    fn missing_principal_binding_is_exact_principal_unknown_not_found() {
        for error in [
            require_principal_id(&serde_json::json!({}))
                .expect_err("missing principal_id must fail"),
            map_session_grant_material_error(SessionGrantError::PrincipalUnknown),
            map_oidc_exchange_error(OidcExchangeError {
                code: "principal_unknown",
                message: "principal_unknown".to_owned(),
            }),
        ] {
            match error {
                ArkretRouteError::Coded {
                    status,
                    code,
                    message,
                } => {
                    assert_eq!(status, StatusCode::NOT_FOUND);
                    assert_eq!(code, arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN);
                    assert_eq!(message, "principal_unknown");
                }
                other => panic!("expected coded principal_unknown error, got {other:?}"),
            }
        }
    }

    #[test]
    fn issuance_lifecycle_errors_use_context_specific_statuses() {
        for (code, expected_status, expected_wire_code) in [
            (
                "account_locked",
                StatusCode::FORBIDDEN,
                arkret_wire::ErrorCode::ACCOUNT_LOCKED,
            ),
            (
                "account_suspended",
                StatusCode::FORBIDDEN,
                arkret_wire::ErrorCode::ACCOUNT_SUSPENDED,
            ),
            (
                "account_deactivated",
                StatusCode::FORBIDDEN,
                arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED,
            ),
            (
                "account_erased",
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::ACCOUNT_ERASED,
            ),
        ] {
            let error = map_oidc_exchange_error(OidcExchangeError {
                code,
                message: code.to_owned(),
            });
            assert_coded(error, expected_status, expected_wire_code);
        }
    }

    #[test]
    fn agent_key_proof_session_grant_requires_dpop_header_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            None,
            &arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof {
                proof_jwt: "proof.jwt".to_owned(),
            },
        ));

        assert_coded(
            err,
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
        );
    }

    #[test]
    fn agent_key_proof_session_grant_rejects_mismatched_body_dpop_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            Some(test_dpop_binding("header.proof.jwt")),
            &arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof {
                proof_jwt: "body.proof.jwt".to_owned(),
            },
        ));

        assert_coded(
            err,
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
        );
    }
}
