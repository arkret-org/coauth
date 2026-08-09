use coauth_data::user::PrincipalDidRepository as _;
use coauth_data::{
    NewSessionGrantOperation, RepositoryAccess as _, SessionGrantCommitOutcome,
    SessionGrantOperation, SessionGrantOperationKind, SessionGrantReserveOutcome,
};
use salvo::prelude::*;
use sha2::Digest as _;

use super::*;
use crate::handlers::arkret::*;

type SessionGrantOutcome = arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome;

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

fn canonical_json_response(
    outcome: &SessionGrantOutcome,
) -> Result<CanonicalJsonResponse, ArkretRouteError> {
    arkret_canonical::canonical_json_bytes(outcome)
        .map(CanonicalJsonResponse)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

fn redact_session_grant_intent(
    body: &arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody,
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
    Ok(value)
}

async fn reserve_issue_operation(
    depot: &Depot,
    body: &arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody,
    holder_jkt: &str,
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
    let identity_material = match body.proof.proof_kind {
        arkret_models_identity::SessionGrantProofKind::OidcCodeExchange => serde_json::json!({
            "proof_kind": "oidc_code_exchange",
            "issuer": body.proof.issuer,
            "client_id": body.proof.client_id,
            "authorization_code": body.proof.authorization_code,
        }),
        arkret_models_identity::SessionGrantProofKind::PreRegistrationHandoff => {
            serde_json::json!({
                "proof_kind": "pre_registration_handoff",
                "handoff_grant": body.proof.challenge,
            })
        }
        arkret_models_identity::SessionGrantProofKind::AgentKeyProof => serde_json::json!({
            "proof_kind": "agent_key_proof",
            "authorization_ref": body.agent_key_authorization_ref,
            "verification_method": body.proof.verification_method,
            "challenge": body.proof.challenge,
        }),
        proof_kind => serde_json::json!({
            "proof_kind": proof_kind,
            "challenge": body.proof.challenge,
            "request_canonical_digest": body.proof.request_canonical_digest,
        }),
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
    if body.proof.proof_kind == arkret_models_identity::SessionGrantProofKind::AgentKeyProof {
        grant_ttl = grant_ttl.min(crate::handlers::account::agents::AGENT_SESSION_MAX_TTL);
    }
    let grant_expires_at = now + grant_ttl;
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
    let issuer = issuer_did_for(&depot.arkret_config()?).to_string();
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer: &issuer,
                operation_kind: SessionGrantOperationKind::Issue,
                proof_kind: Some(body.proof.proof_kind),
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                operation_selector: None,
                target_grant_id: None,
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
            if operation.state == coauth_data::SessionGrantOperationState::Reserved
                && operation.proof_kind
                    != Some(arkret_models_identity::SessionGrantProofKind::OidcCodeExchange) =>
        {
            repo.cancel().await.ok();
            Ok(Ok(operation))
        }
        SessionGrantReserveOutcome::Pending(operation)
            if operation.state == coauth_data::SessionGrantOperationState::Authorized
                && operation.proof_kind
                    == Some(arkret_models_identity::SessionGrantProofKind::OidcCodeExchange) =>
        {
            let checkpoint = operation
                .proof_authorization_checkpoint
                .clone()
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "authorized OIDC operation has no durable checkpoint",
                    )
                })?;
            let material: SessionGrantMaterial =
                serde_json::from_value(checkpoint.get("material").cloned().ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "OIDC checkpoint has no prepared issuance material",
                    )
                })?)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            let outcome: SessionGrantOutcome = serde_json::from_value(
                checkpoint.get("wire_outcome").cloned().ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "OIDC checkpoint has no exact wire outcome",
                    )
                })?,
            )
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            let browser_session_id = checkpoint
                .get("browser_session_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<ulid::Ulid>().ok())
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "OIDC checkpoint has no valid browser session identity",
                    )
                })?;
            let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            let authorization_ref =
                operation
                    .proof_authorization_ref
                    .as_deref()
                    .ok_or_else(|| {
                        ArkretRouteError::coded(
                            StatusCode::SERVICE_UNAVAILABLE,
                            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                            "OIDC checkpoint has no authorization reference",
                        )
                    })?;
            let proof_expires_at = operation.proof_expires_at.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "OIDC checkpoint has no proof expiry",
                )
            })?;
            let committed = commit_session_grant_issuance(
                &mut repo,
                &mut rng,
                &*clock,
                operation.id,
                authorization_ref,
                &checkpoint,
                proof_expires_at,
                &canonical_outcome,
                Some(browser_session_id),
                &material,
            )
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            repo.save().await?;
            if matches!(&committed, SessionGrantCommitOutcome::Committed(_)) {
                super::super::test_chaos::maybe_delay_post_commit(
                    "session_grant_issue_post_commit_pre_response",
                    &operation.request_identity,
                )
                .await;
            }
            match committed {
                SessionGrantCommitOutcome::Committed(_) => Ok(Err(canonical_outcome)),
                SessionGrantCommitOutcome::Replay(replayed) => {
                    let bytes = replayed.canonical_outcome.ok_or_else(|| {
                        ArkretRouteError::coded(
                            StatusCode::SERVICE_UNAVAILABLE,
                            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                            "replayed OIDC operation has no canonical outcome",
                        )
                    })?;
                    Ok(Err(bytes))
                }
                SessionGrantCommitOutcome::Indeterminate(_) => Err(ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "OIDC session-grant commit remains indeterminate",
                )),
            }
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
// `POST /_arkret/gate/account/session-grants` — the single client-visible
// bridge from a standard authentication result into a Arkret
// `ak.session.grant` (service-surface.md §2.5.1). The request body is the
// SDK-canonical `SessionGrantRequestBody`; the proof's `proof_kind` selects
// the validator. coauth implements the `oidc_code_exchange` branch (the
// former `/_coauth/.../auth/oidc/exchange` bridge logic, now moved here):
// the Account Authority exchanges `authorization_code` + `code_verifier` at
// the issuer token_endpoint and validates issuer / state / nonce /
// redirect_uri / id_token nonce / principal binding / device binding
// (`cnf.jkt`) / audience before minting the device-bound grant.

/// `POST /_arkret/gate/account/session-grants` — canonical session-grant
/// issuance. Returns the SDK `SessionGrantOutcome`.
#[handler]
pub async fn issue_session_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<CanonicalJsonResponse, ArkretRouteError> {
    use crate::handlers::account::auth::oidc_bridge::{
        OidcCodeExchangeInput, exchange_oidc_code_for_session_grant,
    };

    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    require_principal_id(&raw_body)?;
    let body: arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody =
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
    match body.proof.proof_kind {
        arkret_models_identity::SessionGrantProofKind::OidcCodeExchange => {
            let dpop_binding = extract_kickoff_dpop(req, depot).await?;
            let holder_jkt = dpop_binding
                .as_ref()
                .map(|binding| binding.jkt.as_str())
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::UNAUTHORIZED,
                        arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
                        "OIDC session grant requires a holder DPoP proof",
                    )
                })?;
            let operation = match reserve_issue_operation(depot, &body, holder_jkt).await? {
                Ok(operation) => operation,
                Err(outcome) => return Ok(CanonicalJsonResponse(outcome)),
            };
            let proof = &body.proof;
            let expected_principal_id = body.principal_id.as_str().to_owned();
            let input = OidcCodeExchangeInput {
                authorization_code: proof.authorization_code.clone().unwrap_or_default(),
                code_verifier: proof.code_verifier.clone().unwrap_or_default(),
                redirect_uri: proof.redirect_uri.clone().unwrap_or_default(),
                issuer: proof.issuer.clone().unwrap_or_default(),
                client_id: proof.client_id.clone().unwrap_or_default(),
                state: proof.state.clone().unwrap_or_default(),
                nonce: proof.nonce.clone().unwrap_or_default(),
                device_id: body
                    .device_id
                    .as_ref()
                    .map(|id| id.as_str().to_owned())
                    .unwrap_or_default(),
                expected_principal_id,
                // The proof carries the requested audience; the grant target
                // resolver intersects it with the configured principal servers.
                requested_audience: Some(proof.audience.to_string()),
            };

            let success =
                exchange_oidc_code_for_session_grant(req, depot, dpop_binding, input, operation)
                    .await
                    .map_err(map_oidc_exchange_error)?;

            let device_id =
                arkret_identifiers::DeviceId::new(success.device_id.clone()).map_err(|e| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-protocol device_id: {e}"),
                    ))
                })?;
            let principal_id = arkret_identifiers::Did::new(success.principal_did.clone())
                .map_err(|e| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-DID principal_id: {e}"),
                    ))
                })?;

            // Human (OIDC) grant: grant_id / session_public_key / audience are
            // SessionGrantOutcome top-level fields (mirroring
            // SessionGrantRefreshOutcome). `scope_details` is the agent-only
            // overlay and MUST be omitted (None) for human grants — the prior
            // code wrote these three into `scope_details`, violating its
            // `additionalProperties:false` agent-only schema.
            let grant_id =
                arkret_identifiers::SessionGrantId::new(success.persisted_grant_id.clone())
                    .map_err(|e| {
                        ArkretRouteError::Internal(
                            Box::<dyn std::error::Error + Send + Sync>::from(format!(
                                "issued grant carried a non-protocol grant_id: {e}"
                            )),
                        )
                    })?;
            let audience = arkret_identifiers::Did::new(success.session_grant.audience.clone())
                .map_err(|e| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-DID audience: {e}"),
                    ))
                })?;

            canonical_json_response(
                &arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome {
                    principal_id,
                    device_id: Some(device_id),
                    session_grant: success.session_grant.grant_jwt.clone(),
                    expires_at: success.session_grant.expires_at_timestamp,
                    grant_id,
                    session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
                        &success.session_grant.session_public_key,
                    )
                    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
                    audience,
                    granted_scope: success.session_grant.scopes.clone(),
                    scope_details: None,
                },
            )
        }
        arkret_models_identity::SessionGrantProofKind::AgentKeyProof => {
            require_agent_runtime_device_id(&body)?;
            let dpop_binding = extract_kickoff_dpop(req, depot).await?;
            // AKP-0008 §4.6: independent agent_key_proof validator. MUST NOT
            // fall back to any human proof validator. The grant-binding DPoP proof is
            // still required so the issued grant is device/runtime-bound
            // (`cnf.jkt`), exactly like the OIDC branch.
            let binding = require_agent_key_proof_dpop_binding(
                dpop_binding,
                body.dpop_binding_proof.as_ref(),
            )?;
            let operation =
                match reserve_issue_operation(depot, &body, binding.jkt.as_str()).await? {
                    Ok(operation) => operation,
                    Err(outcome) => return Ok(CanonicalJsonResponse(outcome)),
                };
            issue_agent_key_proof_session_grant(req, depot, binding, &body, operation).await
        }
        other => Err(ArkretRouteError::coded(
            StatusCode::NOT_IMPLEMENTED,
            arkret_wire::ErrorCode::UNSUPPORTED_FEATURE,
            format!(
                "reason_code=unsupported_proof_kind; this Account Authority only issues session grants via oidc_code_exchange or agent_key_proof; proof_kind={other:?} is not implemented here"
            ),
        )),
    }
}

fn require_agent_runtime_device_id(
    body: &arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody,
) -> Result<(), ArkretRouteError> {
    if body.device_id.is_none() {
        return Err(ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            "agent_key_proof session grant requires a stable device_id",
        ));
    }
    Ok(())
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
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            format!("reason_code=proof_invalid; invalid grant-binding DPoP proof: {error}"),
        )
    })
}

fn require_agent_key_proof_dpop_binding(
    binding: Option<crate::handlers::account::auth::DpopSessionBinding>,
    body_binding: Option<
        &arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof,
    >,
) -> Result<crate::handlers::account::auth::DpopSessionBinding, ArkretRouteError> {
    let binding = binding.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
            "agent_key_proof session grant requires a grant-binding DPoP proof",
        )
    })?;
    let body_binding = body_binding.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; agent_key_proof body must carry dpop_binding_proof",
        )
    })?;
    if body_binding.proof_jwt != binding.proof_jwt {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
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
    body: &arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody,
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
        body.device_id
            .as_ref()
            .expect("agent device id was required before proof validation"),
        audience.to_string(),
        authorization.granted_scope.clone(),
        dpop_binding.jkt.clone(),
        session_public_key,
        authorization.scope_details.clone(),
        arkret_identifiers::EventId::new(
            body.agent_key_authorization_ref
                .clone()
                .expect("agent authorization ref was validated"),
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        body.proof
            .verification_method
            .clone()
            .expect("agent verification method was validated"),
        now,
        expires_at,
    )
    .map_err(map_session_grant_material_error)?;

    let principal_id =
        arkret_identifiers::Did::new(authorization.agent_id.clone()).map_err(|e| {
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
    let wire_audience = arkret_identifiers::Did::new(material.audience.clone()).map_err(|e| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "issued agent grant carried a non-DID audience: {e}"
        )))
    })?;

    let wire_outcome = SessionGrantOutcome {
        principal_id,
        device_id: body.device_id.clone(),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        grant_id,
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
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; agent DPoP JTI was already consumed",
        ));
    }
    let checkpoint = serde_json::json!({
        "kind": "agent_key_proof",
        "agent_key_authorization_ref": body.agent_key_authorization_ref,
        "verification_method": body.proof.verification_method,
        "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&dpop_binding.jti),
    });
    let authorization_ref = format!(
        "agent:{}",
        body.agent_key_authorization_ref
            .as_deref()
            .expect("agent authorization ref was validated")
    );
    let committed = commit_session_grant_issuance(
        &mut repo,
        &mut rng,
        &*clock,
        operation.id,
        &authorization_ref,
        &checkpoint,
        body.proof
            .expires_at
            .expect("agent proof expiry was validated"),
        &canonical_outcome,
        None,
        &material,
    )
    .await
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    repo.save()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if matches!(&committed, SessionGrantCommitOutcome::Committed(_)) {
        super::super::test_chaos::maybe_delay_post_commit(
            "session_grant_issue_post_commit_pre_response",
            &operation.request_identity,
        )
        .await;
    }
    match committed {
        SessionGrantCommitOutcome::Committed(_) => Ok(CanonicalJsonResponse(canonical_outcome)),
        SessionGrantCommitOutcome::Replay(operation) => {
            let bytes = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "replayed agent operation has no canonical outcome",
                )
            })?;
            Ok(CanonicalJsonResponse(bytes))
        }
        SessionGrantCommitOutcome::Indeterminate(_) => Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "agent issuance outcome is indeterminate",
        )),
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
        error @ SessionGrantError::DidWebPrincipalNotExplicit => ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            error.to_string(),
        ),
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
    let (status, code) = match error.code {
        "internal_error" => (
            StatusCode::INTERNAL_SERVER_ERROR,
            arkret_wire::ErrorCode::INTERNAL_ERROR,
        ),
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
            Some(
                &arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof {
                    proof_jwt: "proof.jwt".to_owned(),
                },
            ),
        ));

        assert_coded(
            err,
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
        );
    }

    #[test]
    fn agent_key_proof_session_grant_requires_body_dpop_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            Some(test_dpop_binding("proof.jwt")),
            None,
        ));

        assert_coded(
            err,
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
        );
    }

    #[test]
    fn agent_key_proof_session_grant_rejects_mismatched_body_dpop_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            Some(test_dpop_binding("header.proof.jwt")),
            Some(
                &arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof {
                    proof_jwt: "body.proof.jwt".to_owned(),
                },
            ),
        ));

        assert_coded(
            err,
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
        );
    }
}
