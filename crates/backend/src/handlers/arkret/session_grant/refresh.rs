use arkret_identifiers::DeviceId;
use arkret_models_collaboration::session_grant_bodies::session_grant_refresh_request_digest;
use arkret_models_collaboration::session_grants::{
    HumanSessionGrantRefreshRequest, SessionGrantOutcome, SessionGrantRefreshRequestBody,
};
use arkret_models_identity::{
    SessionGrantCredentialClass, SessionGrantHolderBinding, SessionGrantProofKind,
};
use chrono::{DateTime, Utc};
use coauth_data::{
    LocalAccountId, NewSessionGrantOperation, SessionGrantExactOutcome,
    SessionGrantProofAuthorization, SessionGrantRefreshCommit,
    SessionGrantRefreshOutcome as LedgerRefreshOutcome, SessionGrantReserveOutcome,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::*;
use crate::handlers::arkret::canonical_response::ArkretCanonicalJson;
use crate::handlers::arkret::*;

fn refresh_proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ReasonCode::PROOF_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn require_bound_device_id<'a>(
    presented_device_id: Option<&'a str>,
    persisted_device_id: Option<&'a str>,
) -> Result<&'a str, ArkretRouteError> {
    let presented = presented_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| refresh_proof_invalid("human refresh requires the presented device_id"))?;
    DeviceId::new(presented.to_owned()).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::PARAM_INVALID,
            format!("device_id is not a protocol device identifier: {error}"),
        )
    })?;

    let persisted = persisted_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            refresh_proof_invalid("session grant has no device_id binding for human refresh")
        })?;
    if presented != persisted {
        return Err(refresh_proof_invalid(
            "presented device_id does not match the persisted session grant binding",
        ));
    }

    Ok(persisted)
}

fn validate_human_refresh_before_reservation(
    body: &HumanSessionGrantRefreshRequest,
    prior_grant: &coauth_data::SessionGrant,
    prior_payload: &SignedSessionGrantClaims,
    holder_jkt: &str,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    let proof = &body.accepted_device_possession_proof;
    if proof.predecessor_session_grant_id != prior_grant.grant_id
        || proof.account_id != prior_payload.account_id
        || proof.device_id != body.device_id
        || proof.holder_jkt != holder_jkt
    {
        return Err(refresh_proof_invalid(
            "accepted-device refresh proof does not bind the predecessor, principal, device and holder key",
        ));
    }
    if proof.audience_id != prior_grant.audience_id {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "accepted-device refresh proof audience_id must match the session grant audience_id",
        ));
    }
    if proof.issued_at > now + chrono::Duration::seconds(30) || now >= proof.expires_at {
        return Err(refresh_proof_invalid(
            "accepted-device refresh proof is outside its validity window",
        ));
    }
    let audience_id = prior_grant.audience_id.clone();
    let expected_digest = session_grant_refresh_request_digest(
        &body.grant_jwt,
        &prior_grant.grant_id,
        &prior_payload.account_id.principal_id,
        &body.device_id,
        &audience_id,
        holder_jkt,
    )?;
    if proof.session_intent_digest != expected_digest {
        return Err(refresh_proof_invalid(
            "accepted-device refresh proof session intent digest mismatch",
        ));
    }
    Ok(())
}

// ── DPoP-bound session-grant refresh + debug seed ──────────────
//
// These two handlers were added in G3.C1 to complete the device-bound
// session-grant story: `refresh_session_grant` rotates an existing
// DPoP-bound grant onto a new access token (keeping `cnf.jkt` constant),
// and `debug_issue_dpop_grant` is the cotest harness seam that mints a
// fully signed grant without going through OIDC.

fn ensure_refreshable_credential_class(
    credential_class: SessionGrantCredentialClass,
) -> Result<(), ArkretRouteError> {
    if credential_class == SessionGrantCredentialClass::RecoverySession {
        Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "recovery_session grants are non-refreshable; recovery completion issues a distinct standard grant",
        ))
    } else {
        Ok(())
    }
}

/// `POST /_arkret/gate/account/session-grants/refresh` — exchange a near-expiry
/// DPoP-bound session grant for a fresh one. The caller MUST present:
///
/// * A `DPoP` header that proves possession of the same key the existing grant is bound to
///   (`cnf.jkt` on the old grant must match the new proof's `jkt`).
/// * A request body carrying the prior grant JWT, the bound `device_id`, and a fresh human-device
///   DID proof over the soft-logout restore transcript.
#[handler]
pub async fn refresh_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let keyring = depot.keyring()?;
    let http_client = depot.http_client()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. DPoP proof must be present — the refresh endpoint is the canonical proof-of-possession
    //    check.
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        // The grant-binding DPoP proof authorizes this operation; its absence is
        // an auth failure, not a malformed body.
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
            "session-grant grant-binding DPoP proof required",
        )
    })?;

    let body: SessionGrantRefreshRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    body.validate().map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            error.to_string(),
        )
    })?;
    let (grant_jwt, requested_audience, request_digest) = match &body {
        SessionGrantRefreshRequestBody::Human(request) => (
            request.grant_jwt.as_str(),
            request.audience_id.as_ref(),
            &request
                .accepted_device_possession_proof
                .session_intent_digest,
        ),
        SessionGrantRefreshRequestBody::Agent(request) => (
            request.grant_jwt.as_str(),
            request.audience_id.as_ref(),
            &request.agent_session_refresh_proof.request_canonical_digest,
        ),
    };
    let presented_grant =
        crate::services::dpop::dpop_authorization_token(req).ok_or_else(|| {
            ArkretRouteError::Unauthorized(
                "Authorization: DPoP <session_grant> is required".to_owned(),
            )
        })?;
    if presented_grant != grant_jwt {
        return Err(ArkretRouteError::Unauthorized(
            "DPoP authorization credential does not match grant_jwt".to_owned(),
        ));
    }

    // 2. Parse + load the existing grant. We never verify the JWT signature here — the persisted
    //    row IS the source of truth; the holder thumbprint is derived from the signed
    //    session_public_key carried by the claims.
    let jwt: Jwt<'_, SignedSessionGrantClaims> = Jwt::try_from(grant_jwt)
        .map_err(|_| ArkretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let prior_payload = jwt.payload().clone();
    prior_payload
        .validate()
        .map_err(|error| ArkretRouteError::BadRequest(format!("invalid grant_jwt: {error}")))?;
    ensure_refreshable_credential_class(prior_payload.credential_class)?;
    let expected_jkt = prior_payload
        .session_public_key
        .thumbprint_sha256()
        .map_err(|error| {
            ArkretRouteError::BadRequest(format!("invalid session_public_key: {error}"))
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(grant_jwt)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
                "no session grant matches the presented grant_jwt",
            )
        })?;

    // 3. Verify the DPoP proof against this exact endpoint, with the prior grant_jwt as the bound
    //    access token (so `ath` MUST match).
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base_url = url_builder.http_base();
    let htu = dpop_htu(&public_base_url, req);
    let verification =
        DpopVerifier::verify_without_replay(&dpop_header, &htm, &htu, now, Some(grant_jwt))
            .map_err(|error| {
                ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::SIGNATURE_INVALID,
                    error.to_string(),
                )
            })?;

    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            error.to_string(),
        )
    })?;

    match (&body, prior_payload.proof_kind) {
        (
            SessionGrantRefreshRequestBody::Human(request),
            Some(SessionGrantProofKind::AccountHandoff),
        ) => {
            validate_human_refresh_before_reservation(
                request,
                &prior_grant,
                &prior_payload,
                &verification.jkt,
                now,
            )?;
        }
        (SessionGrantRefreshRequestBody::Agent(_), Some(SessionGrantProofKind::AgentKeyProof)) => {}
        _ => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                "refresh request variant does not match predecessor credential class",
            ));
        }
    }

    // Reject request-shape mismatches before creating a durable reservation.
    // Predecessor lifecycle is intentionally checked after reservation because
    // an exact retry is allowed to replay the already-minted successor after
    // the predecessor has become superseded.
    if let Some(requested) = requested_audience
        && requested != &prior_grant.audience_id
    {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "session-grant rotation MUST NOT change the bound audience_id",
        ));
    }
    let device_id = match (&body, &prior_payload.holder_binding) {
        (
            SessionGrantRefreshRequestBody::Human(request),
            SessionGrantHolderBinding::HumanDevice { .. },
        ) => Some(require_bound_device_id(
            Some(request.device_id.as_str()),
            prior_grant.device_id.as_deref(),
        )?),
        (
            SessionGrantRefreshRequestBody::Agent(request),
            SessionGrantHolderBinding::AgentRuntime {
                agent_id,
                agent_key_authorization_ref,
                verification_method,
            },
        ) if prior_grant.device_id.is_none()
            && &request.principal_id == agent_id
            && &request.agent_key_authorization_ref == agent_key_authorization_ref
            && &request.agent_session_refresh_proof.verification_method == verification_method
            && prior_payload.account_id.principal_id == *agent_id =>
        {
            None
        }
        _ => {
            return Err(refresh_proof_invalid(
                "refresh holder does not match the predecessor grant",
            ));
        }
    };

    let request_identity = format!(
        "refresh:{}:{}",
        prior_grant.grant_id,
        request_digest.as_str()
    );
    let mut redacted = serde_json::to_value(&body)?;
    for proof_field in [
        "accepted_device_possession_proof",
        "agent_session_refresh_proof",
    ] {
        if let Some(proof) = redacted
            .get_mut(proof_field)
            .and_then(serde_json::Value::as_object_mut)
        {
            proof.remove("signature");
            proof.remove("issued_at");
            proof.remove("expires_at");
        }
    }
    let canonical_intent = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "request": redacted,
        "holder_jkt": verification.jkt,
    }))?;
    let canonical_intent_digest: [u8; 32] = arkret_canonical::sha256_bytes(&canonical_intent);
    let grant_not_before = arkret_canonical::normalize_timestamp_canonical(now);
    let ttl = if prior_payload.proof_kind == Some(SessionGrantProofKind::AgentKeyProof) {
        arkret_config
            .session_grant_ttl
            .min(crate::handlers::account::agents::AGENT_SESSION_MAX_TTL)
    } else {
        arkret_config.session_grant_ttl
    };
    let grant_expires_at = grant_not_before + ttl;
    let signing_key_id = super::super::preferred_signing_key_id(&keyring)?;
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer_id: prior_payload.issuer_id.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Refresh {
                    predecessor_grant_id: prior_grant.grant_id.clone(),
                },
                proof_kind: None,
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_session_grant_id: Some(&prior_grant.grant_id),
                issuance_nonce: None,
                session_id: Some(&prior_payload.session_id),
                grant_not_before: Some(grant_not_before),
                grant_expires_at: Some(grant_expires_at),
                signing_key_id: Some(&signing_key_id),
                retained_until: grant_expires_at + chrono::Duration::days(7),
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
            let result_grant_id = operation.result_grant_id.as_ref().ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "refresh replay has no durable successor",
                )
            })?;
            let successor = repo
                .oauth_session_grant()
                .lookup_by_grant_id(result_grant_id)
                .await?
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "refresh replay successor is unavailable",
                    )
                })?;
            if now >= successor.expires_at {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::session_grant_replay_expired(
                    successor.grant_id,
                ));
            }
            if successor.lifecycle_state != coauth_data::SessionGrantLifecycleState::Active {
                let state = super::replay_terminal_state(successor.lifecycle_state)
                    .expect("lifecycle state checked to be terminal above");
                repo.cancel().await.ok();
                return Err(ArkretRouteError::session_grant_replay_terminal(
                    successor.grant_id,
                    state,
                ));
            }
            let bytes = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "refresh replay has no canonical outcome",
                )
            })?;
            repo.cancel().await.ok();
            return Ok(ArkretCanonicalJson(bytes));
        }
        SessionGrantReserveOutcome::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "refresh request identity conflicts with a different canonical intent",
            ));
        }
        SessionGrantReserveOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "refresh replay material is unavailable",
            ));
        }
        SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "refresh authorization checkpoint is incomplete",
            ));
        }
    };

    if now >= prior_grant.expires_at {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::session_grant_replay_expired(
            prior_grant.grant_id,
        ));
    }
    if prior_grant.lifecycle_state != coauth_data::SessionGrantLifecycleState::Active {
        repo.cancel().await.ok();
        let state = super::replay_terminal_state(prior_grant.lifecycle_state)
            .expect("lifecycle state checked to be terminal above");
        return Err(ArkretRouteError::session_grant_replay_terminal(
            prior_grant.grant_id,
            state,
        ));
    }

    if prior_payload.proof_kind == Some(SessionGrantProofKind::AgentKeyProof) {
        use crate::handlers::account::agents::{
            AgentSessionProofError, enforce_authoritative_agent_lifecycle,
            validate_agent_session_refresh_proof,
        };

        let authoritative_agent = match enforce_authoritative_agent_lifecycle(
            &http_client,
            &arkret_config,
            &keyring,
            prior_payload.account_id.principal_id.as_str(),
        )
        .await
        {
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
        let agent_request = match &body {
            SessionGrantRefreshRequestBody::Agent(request) => request,
            SessionGrantRefreshRequestBody::Human(_) => {
                unreachable!("variant checked before reservation")
            }
        };
        let proof = &agent_request.agent_session_refresh_proof;
        let authorization = match validate_agent_session_refresh_proof(
            &mut repo,
            &mut rng,
            &*clock,
            &authoritative_agent,
            &prior_payload,
            &agent_request.grant_jwt,
            agent_request,
            proof,
        )
        .await
        {
            Ok(authorization) => authorization,
            Err(AgentSessionProofError::Rejection(rejection)) => {
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
            Err(AgentSessionProofError::HumanApprovalRequired(_)) => {
                repo.cancel().await.ok();
                return Err(refresh_proof_invalid(
                    "Agent session refresh cannot request expanded human-approved scope",
                ));
            }
        };

        let controller_binding = repo
            .principal_did()
            .get_by_principal_id_and_audience(
                authorization.accountable_principal_id.as_str(),
                prior_grant.audience_id.as_str(),
            )
            .await?
            .ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::FAILED_PRECONDITION,
                    "accountable controller has no local service account binding",
                )
            })?;
        let controller_user_id = controller_binding.user_id;
        let user = repo.user().lookup(controller_user_id).await?;
        let controller_blocked =
            user.is_none_or(|user| user.locked_at.is_some() || user.deactivated_at.is_some());
        if controller_blocked {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::FORBIDDEN,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "accountable controller is deactivated or suspended",
            ));
        }

        let scopes: Vec<String> = prior_grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect();
        let scope_details = prior_payload.scope_details.clone().ok_or_else(|| {
            refresh_proof_invalid("Agent session grant is missing its authorization scope binding")
        })?;
        let session_public_key = serde_json::to_string(&verification.public_jwk)?;
        let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)?;
        let new_material = mint_agent_session_grant(
            &issuance_seed,
            &arkret_config,
            &keyring,
            &prior_payload.account_id.principal_id,
            LocalAccountId::new(controller_user_id.to_string())?,
            prior_grant.audience_id.clone(),
            scopes,
            verification.jkt.clone(),
            session_public_key,
            scope_details,
            arkret_identifiers::EventId::new(authorization.authorized_event_id.clone())?,
            arkret_wire::DidUrl::new(authorization.verification_method.clone()).map_err(
                |error| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        error.to_owned(),
                    ))
                },
            )?,
            issuance_seed.not_before,
            issuance_seed.expires_at,
        )?;
        let audience_id = new_material.audience_id.clone();
        let outcome = SessionGrantOutcome {
            session_grant_id: new_material.grant_id.clone(),
            account_id: new_material.account_id.clone(),
            device_id: None,
            session_grant: new_material.grant_jwt.clone(),
            session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
                &new_material.session_public_key,
            )?,
            expires_at: new_material.expires_at_timestamp,
            audience_id,
            granted_scope: new_material.scopes.clone(),
            previous_session_grant_id: Some(prior_grant.grant_id.clone()),
        };
        let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
        let inserted = repo
            .dpop_replay()
            .consume_jti(crate::services::dpop::dpop_replay_record(
                &verification.claims.jti,
                now,
            ))
            .await?;
        if !inserted {
            repo.cancel().await.ok();
            return Err(refresh_proof_invalid(
                "refresh DPoP JTI was already consumed",
            ));
        }
        let proof_expires_at = proof.expires_at;
        let checkpoint = serde_json::json!({
            "kind": "agent_key_refresh",
            "agent_key_authorization_ref": authorization.authorized_event_id,
            "verification_method": authorization.verification_method,
            "request_canonical_digest": request_digest,
            "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&verification.claims.jti),
        });
        let authorization_ref = format!("agent-refresh:{}", authorization.authorized_event_id);
        let exact_outcome = SessionGrantExactOutcome {
            canonical_response: &canonical_outcome,
            response_digest: arkret_canonical::sha256_bytes(&canonical_outcome),
        };
        let committed = repo
            .oauth_session_grant()
            .commit_refresh(
                &mut rng,
                &*clock,
                SessionGrantRefreshCommit {
                    operation_id: operation.id,
                    authorization: SessionGrantProofAuthorization {
                        authorization_ref: &authorization_ref,
                        checkpoint: &checkpoint,
                        proof_expires_at,
                    },
                    outcome: exact_outcome,
                    predecessor_grant_id: &prior_grant.grant_id,
                    successor: new_session_grant_record(None, &new_material),
                },
            )
            .await?;
        repo.save().await?;
        if matches!(&committed, LedgerRefreshOutcome::Committed { .. }) {
            super::super::test_chaos::maybe_delay_post_commit(
                "session_grant_refresh_post_commit_pre_response",
                &request_identity,
            )
            .await;
        }
        return match committed {
            LedgerRefreshOutcome::Committed { .. } => Ok(ArkretCanonicalJson(canonical_outcome)),
            LedgerRefreshOutcome::Replay(operation) => operation
                .canonical_outcome
                .map(ArkretCanonicalJson)
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "agent refresh replay has no canonical outcome",
                    )
                }),
            LedgerRefreshOutcome::PredecessorTerminal(grant) => {
                let Some(state) = super::replay_terminal_state(grant.lifecycle_state) else {
                    return Err(ArkretRouteError::session_grant_replay_expired(
                        grant.grant_id,
                    ));
                };
                Err(ArkretRouteError::session_grant_replay_terminal(
                    grant.grant_id,
                    state,
                ))
            }
            LedgerRefreshOutcome::Indeterminate(_) => Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "agent refresh outcome is indeterminate",
            )),
        };
    }

    let device_id =
        device_id.ok_or_else(|| refresh_proof_invalid("human refresh has no device binding"))?;

    // 4. Resolve the underlying browser session so the new grant lives under the same
    //    authentication context.
    let browser_session_id = prior_grant.browser_session_id.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
            "session-grant refresh requires a browser-bound session grant",
        )
    })?;
    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "session grant references missing browser session",
            ))
        })?;

    // The browser session is the authentication context the grant chain hangs
    // off. Logout finishes it (sets `finished_at`) but does NOT eagerly revoke
    // outstanding grants — so without this check a logged-out device that still
    // holds the DPoP key could keep rotating its grant and stay signed in
    // forever, defeating logout. Refuse rotation once the session is finished:
    // re-authentication (a fresh browser session) is then required.
    if browser_session.finished_at.is_some() {
        repo.cancel().await?;
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SESSION_LOGGED_OUT,
            "underlying browser session is logged out; rotation chain cannot be resumed",
        ));
    }

    // Refresh is the `session_issuance_or_refresh` context, so the per-context
    // status split lives in the Spec registry, not here — this match only picks
    // which code the current account status maps to.
    let lifecycle_code = match browser_session.user.status {
        arkret_models_collaboration::objects::account_status::AccountStatus::Locked => {
            Some(arkret_wire::ErrorCode::AccountLocked)
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::Suspended => {
            Some(arkret_wire::ErrorCode::AccountSuspended)
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated => {
            Some(arkret_wire::ErrorCode::AccountDeactivated)
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending => {
            Some(arkret_wire::ErrorCode::AccountErased)
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::Active => None,
        arkret_models_collaboration::objects::account_status::AccountStatus::SoftLoggedOut => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::SESSION_LOGGED_OUT,
                "soft-logged-out account must re-authenticate through AccountHandoff issuance",
            ));
        }
    };
    if let Some(code) = lifecycle_code {
        repo.cancel().await?;
        return Err(ArkretRouteError::coded(
            super::account_lifecycle_status(
                code,
                arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh,
            ),
            code.as_str(),
            "account status forbids session-grant refresh",
        ));
    }

    // 5. Mint a new grant with the same subject_id + scope + audience_id. The
    // audience_id MUST NOT change across rotation: a client holding a grant for
    // one Station must not be able to rotate it into a grant for a
    // different audience_id (which it could then exchange there). Ignore any
    // client-supplied audience_id; reject an explicit mismatch defensively.
    let principal_binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(
            prior_grant.subject_id.as_str(),
            prior_grant.audience_id.as_str(),
        )
        .await?
        .ok_or_else(|| refresh_proof_invalid("session grant principal authority is unavailable"))?;
    principal_binding
        .account_id
        .validate()
        .map_err(|error| refresh_proof_invalid(error.to_string()))?;
    let human_request = match &body {
        SessionGrantRefreshRequestBody::Human(request) => request,
        SessionGrantRefreshRequestBody::Agent(_) => {
            unreachable!("variant checked before reservation")
        }
    };
    let proof = &human_request.accepted_device_possession_proof;

    // 6. Rebuild the successor solely from the durable reservation seed. The
    // signing window, nonce, chain id and signing key therefore remain byte
    // stable across a retry after an ambiguous transport failure.
    let audience_id = prior_grant.audience_id.clone();
    let scopes: Vec<String> = prior_grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)?;
    let proof_kind = prior_payload.proof_kind.ok_or_else(|| {
        refresh_proof_invalid("session-grant refresh predecessor is missing proof_kind")
    })?;
    let expected_device_binding = prior_payload.device_binding.as_ref().ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOKED,
            "human session-grant predecessor has no accepted-device binding",
        )
    })?;
    let device_binding = acquire_private_current_device_binding(
        depot,
        &principal_binding.account_id,
        arkret_identifiers::DeviceId::new(device_id.to_owned())?,
        arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        Some(expected_device_binding),
        Some(arkret_wire::AcceptedDevicePossessionProof::Refresh(
            proof.clone(),
        )),
        proof.session_intent_digest.clone(),
        now,
    )
    .await?;
    if &device_binding != expected_device_binding {
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOKED,
            "device authorization generation changed before refresh",
        ));
    }
    let device_id = arkret_identifiers::DeviceId::new(device_id.to_owned())?;
    let new_material = issue_session_grant_for_audience(
        &issuance_seed,
        &*clock,
        &arkret_config,
        &keyring,
        &browser_session,
        crate::services::dpop::session_public_jwk(&verification.public_jwk)?,
        audience_id,
        device_id.clone(),
        scopes,
        Some(&prior_grant.subject_id),
        &principal_binding.account_id,
        verification.jkt.clone(),
        device_binding,
        proof_kind,
    )?;

    let response_audience = new_material.audience_id.clone();

    let outcome = SessionGrantOutcome {
        session_grant_id: new_material.grant_id.clone(),
        account_id: new_material.account_id.clone(),
        device_id: Some(device_id),
        session_grant: new_material.grant_jwt.clone(),
        session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
            &new_material.session_public_key,
        )?,
        expires_at: new_material.expires_at_timestamp,
        audience_id: response_audience,
        granted_scope: new_material.scopes.clone(),
        previous_session_grant_id: Some(prior_grant.grant_id.clone()),
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
    let inserted = repo
        .dpop_replay()
        .consume_jti(crate::services::dpop::dpop_replay_record(
            &verification.claims.jti,
            now,
        ))
        .await?;
    if !inserted {
        repo.cancel().await.ok();
        return Err(refresh_proof_invalid(
            "refresh DPoP JTI was already consumed",
        ));
    }
    let proof_expires_at = proof.expires_at;
    let proof_digest =
        arkret_wire::AcceptedDevicePossessionProof::Refresh(proof.clone()).proof_digest()?;
    let authorization_ref = format!("device-refresh:{proof_digest}");
    let checkpoint = serde_json::json!({
        "kind": "human_device_refresh",
        "verification_method": proof.verification_method,
        "request_canonical_digest": request_digest,
        "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&verification.claims.jti),
    });
    let committed = repo
        .oauth_session_grant()
        .commit_refresh(
            &mut rng,
            &*clock,
            SessionGrantRefreshCommit {
                operation_id: operation.id,
                authorization: SessionGrantProofAuthorization {
                    authorization_ref: &authorization_ref,
                    checkpoint: &checkpoint,
                    proof_expires_at,
                },
                outcome: SessionGrantExactOutcome {
                    canonical_response: &canonical_outcome,
                    response_digest: arkret_canonical::sha256_bytes(&canonical_outcome),
                },
                predecessor_grant_id: &prior_grant.grant_id,
                successor: new_session_grant_record(Some(browser_session.id), &new_material),
            },
        )
        .await?;
    repo.save().await?;
    if matches!(&committed, LedgerRefreshOutcome::Committed { .. }) {
        super::super::test_chaos::maybe_delay_post_commit(
            "session_grant_refresh_post_commit_pre_response",
            &request_identity,
        )
        .await;
    }
    match committed {
        LedgerRefreshOutcome::Committed { .. } => Ok(ArkretCanonicalJson(canonical_outcome)),
        LedgerRefreshOutcome::Replay(operation) => operation
            .canonical_outcome
            .map(ArkretCanonicalJson)
            .ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "refresh replay has no canonical outcome",
                )
            }),
        LedgerRefreshOutcome::PredecessorTerminal(grant) => {
            if grant.expires_at <= now {
                return Err(ArkretRouteError::session_grant_replay_expired(
                    grant.grant_id,
                ));
            }
            let state = super::replay_terminal_state(grant.lifecycle_state)
                .expect("lifecycle state checked to be terminal above");
            Err(ArkretRouteError::session_grant_replay_terminal(
                grant.grant_id,
                state,
            ))
        }
        LedgerRefreshOutcome::Indeterminate(_) => Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "refresh outcome is indeterminate",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_ID: &str = "ak:device:0196419b-0000-7000-8000-000000000001";
    const OTHER_DEVICE_ID: &str = "ak:device:0196419b-0000-7000-8000-000000000002";

    fn assert_coded(error: ArkretRouteError, expected_code: &'static str) -> String {
        match error {
            ArkretRouteError::Coded { code, message, .. } => {
                assert_eq!(code, expected_code);
                message
            }
            other => panic!("expected coded error, got {other:?}"),
        }
    }

    #[test]
    fn human_refresh_requires_presented_device_id() {
        let err = require_bound_device_id(None, Some(DEVICE_ID))
            .expect_err("missing presented device_id must fail accepted-device proof validation");

        assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[test]
    fn human_refresh_requires_persisted_session_grant_device() {
        let err = require_bound_device_id(Some(DEVICE_ID), None)
            .expect_err("a grant with no persisted device binding must not be recoverable");

        assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[test]
    fn human_refresh_rejects_device_binding_mismatch() {
        let err = require_bound_device_id(Some(OTHER_DEVICE_ID), Some(DEVICE_ID))
            .expect_err("presented device_id must match the grant binding");

        assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[test]
    fn human_refresh_accepts_persisted_device_binding_match() {
        let device_id = require_bound_device_id(Some(DEVICE_ID), Some(DEVICE_ID))
            .expect("matching device bindings should pass");

        assert_eq!(device_id, DEVICE_ID);
    }

    #[test]
    fn recovery_session_grant_is_never_refreshable() {
        let error =
            ensure_refreshable_credential_class(SessionGrantCredentialClass::RecoverySession)
                .expect_err("recovery completion must issue a distinct Standard grant");
        let message = assert_coded(error, arkret_wire::ErrorCode::FAILED_PRECONDITION);
        assert!(message.contains("non-refreshable"));
        ensure_refreshable_credential_class(SessionGrantCredentialClass::Standard).unwrap();
    }
}
