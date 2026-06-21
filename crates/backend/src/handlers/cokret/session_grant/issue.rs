use cokret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_CLAIM_REQUIRED, ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_INTERNAL_ERROR, ERROR_CODE_INVALID_SIGNATURE, ERROR_CODE_POLICY_DENIED,
    ERROR_CODE_SCHEMA_VIOLATION, ERROR_CODE_SERVICE_UNAVAILABLE, ERROR_CODE_UNSUPPORTED_FEATURE,
};
use salvo::prelude::*;

use super::*;
use crate::handlers::cokret::*;

// ── Canonical Account Authority session-grant issuance ─────────────
//
// `POST /_cokret/gate/account/session-grants` — the single client-visible
// bridge from a standard authentication result into a Cokret
// `ck.session.grant` (service-surface.md §2.5.1). The request body is the
// SDK-canonical `SessionGrantRequestBody`; the proof's `proof_kind` selects
// the validator. coauth implements the `oidc_code_exchange` branch (the
// former `/_coauth/.../auth/oidc/exchange` bridge logic, now moved here):
// the Account Authority exchanges `authorization_code` + `code_verifier` at
// the issuer token_endpoint and validates issuer / state / nonce /
// redirect_uri / id_token nonce / principal binding / device binding
// (`cnf.jkt`) / audience before minting the device-bound grant.

/// `POST /_cokret/gate/account/session-grants` — canonical session-grant
/// issuance. Returns the SDK `SessionGrantOutcome`.
#[handler]
pub async fn issue_session_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<cokret_core::SessionGrantOutcome>, CokretRouteError> {
    use crate::handlers::account::auth::extract_dpop_binding_for_kickoff;
    use crate::handlers::account::auth::oidc_bridge::{
        OidcCodeExchangeInput, exchange_oidc_code_for_session_grant,
    };

    let url_builder = depot.url_builder()?;

    // Holder proof (DPoP) extraction. A present-but-malformed proof is a hard
    // rejection: an OIDC-issued grant MUST be device-bound (`cnf.jkt`).
    let dpop_binding = extract_dpop_binding_for_kickoff(req, &url_builder)
        .await
        .map_err(|error| {
            CokretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_INVALID_SIGNATURE,
                format!("reason_code=proof_invalid; invalid DPoP holder proof: {error}"),
            )
        })?;

    let body: cokret_core::SessionGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;

    match body.proof.proof_kind {
        cokret_core::SessionGrantProofKind::OidcCodeExchange => {
            let proof = &body.proof;
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
                // Optional at first sign-in (② contract D5): the client may
                // omit `principal_id`; the AA derives the DID and returns it in
                // `SessionGrantOutcome.principal_id`. When present it is the
                // binding the exchange must match exactly.
                expected_principal_id: body.principal_id.as_ref().map(|id| id.as_str().to_owned()),
                // The proof carries the requested audience; the grant target
                // resolver intersects it with the configured principal servers.
                requested_audience: Some(proof.audience.clone()),
            };

            let success = exchange_oidc_code_for_session_grant(req, depot, dpop_binding, input)
                .await
                .map_err(map_oidc_exchange_error)?;

            let device_id = cokret_core::DeviceId::new(success.device_id.clone()).map_err(|e| {
                CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    format!("issued grant carried a non-protocol device_id: {e}"),
                ))
            })?;
            let principal_id =
                cokret_core::Did::new(success.principal_did.clone()).map_err(|e| {
                    CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-DID principal_id: {e}"),
                    ))
                })?;

            Ok(Json(cokret_core::SessionGrantOutcome {
                principal_id,
                device_id: Some(device_id),
                session_grant: success.session_grant.grant_jwt.clone(),
                expires_at: success.session_grant.expires_at_timestamp,
                granted_scope: success.session_grant.scopes.clone(),
                scope_details: serde_json::json!({
                    "grant_id": success.persisted_grant_id,
                    "session_public_key": success.session_grant.session_public_key,
                    "audience": success.session_grant.audience,
                }),
            }))
        }
        cokret_core::SessionGrantProofKind::AgentKeyProof => {
            // CKP-0008 §4.6: independent agent_key_proof validator. MUST NOT
            // fall back to any human proof validator. The DPoP holder proof is
            // still required so the issued grant is device/runtime-bound
            // (`cnf.jkt`), exactly like the OIDC branch.
            let binding = dpop_binding.ok_or_else(|| {
                CokretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    cokret_core::error::ERROR_CODE_DID_PROOF_REQUIRED,
                    "agent_key_proof session grant requires a DPoP holder proof",
                )
            })?;
            issue_agent_key_proof_session_grant(req, depot, binding, &body).await
        }
        other => Err(CokretRouteError::coded(
            StatusCode::NOT_IMPLEMENTED,
            ERROR_CODE_UNSUPPORTED_FEATURE,
            format!(
                "reason_code=unsupported_proof_kind; this Account Authority only issues session grants via oidc_code_exchange or agent_key_proof; proof_kind={other:?} is not implemented here"
            ),
        )),
    }
}

/// CKP-0008 §4.6 agent runtime authentication branch. Validates the
/// `agent_key_proof`, intersects scope, and mints a ≤ 15-minute device-bound
/// session grant. Returns the SDK `SessionGrantOutcome` with the
/// `scope_details` overlay. Human-approval and fail-closed rejections surface
/// as structured errors.
async fn issue_agent_key_proof_session_grant(
    _req: &mut Request,
    depot: &Depot,
    dpop_binding: crate::handlers::account::auth::DpopSessionBinding,
    body: &cokret_core::SessionGrantRequestBody,
) -> Result<Json<cokret_core::SessionGrantOutcome>, CokretRouteError> {
    use crate::handlers::account::agents::{AgentSessionProofError, validate_agent_session_proof};

    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    let mut repo = depot.repo().await?;
    let authorization = match validate_agent_session_proof(
        &mut repo,
        &mut rng,
        &*clock,
        &url_builder,
        &cokret_config,
        body,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(AgentSessionProofError::Rejection(rejection)) => {
            repo.cancel().await.ok();
            let status = rejection.http_status();
            return Err(CokretRouteError::coded(
                status,
                rejection.code(),
                rejection.code(),
            ));
        }
        Err(AgentSessionProofError::HumanApprovalRequired(approval)) => {
            repo.cancel().await.ok();
            // CKP-0008 §4.6: structured claim_required — agent runtime is never
            // shown CAPTCHA/OTP. The reason_code + approval_request_id ride the
            // message so the conformant runtime can route the controller to the
            // out-of-band approval surface.
            return Err(CokretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                cokret_core::error::ERROR_CODE_CLAIM_REQUIRED,
                serde_json::json!({
                    "reason_code": "human_approval_required",
                    "approval_request_id": approval.approval_request_id,
                })
                .to_string(),
            ));
        }
    };

    // Controller lifecycle gate: a deactivated / suspended controller fails
    // closed (CKP-0008 §4.6). Resolve the controller's local user record when
    // the DID maps to a coauth-hosted account. Bind the lookup to an owned
    // value so the sub-repo borrow is released before `repo.cancel()`.
    let controller_blocked = if let Some(user_id) =
        parse_local_user_did_for(&url_builder, &cokret_config, &authorization.controller_did)
    {
        let user = repo
            .user()
            .lookup(user_id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        user.is_some_and(|user| user.locked_at.is_some() || user.deactivated_at.is_some())
    } else {
        false
    };
    if controller_blocked {
        repo.cancel().await.ok();
        return Err(CokretRouteError::coded(
            StatusCode::FORBIDDEN,
            ERROR_CODE_FAILED_PRECONDITION,
            "accountable controller is deactivated or suspended",
        ));
    }

    // The agent runtime authenticates with its own key, not a human browser
    // session, so there is no browser-session anchor to persist against. The
    // grant is a self-validating signed `ck.session.grant` JWT bound to the
    // runtime's DPoP key with the capped agent TTL; soland verifies the coauth
    // issuer signature and rechecks agent status inside the revocation
    // freshness window (CKP-0008 §4.11 natural-expiry path), bounded by the
    // ≤ 15-minute TTL.
    let _ = &mut repo;
    repo.cancel().await.ok();

    let audience = body.proof.audience.clone();
    let now = clock.now();
    let expires_at = now + authorization.ttl;

    let session_public_key = serde_json::to_string(&dpop_binding.public_jwk).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(error))
    })?;
    let mut token_scope_details = authorization.scope_details.clone();
    token_scope_details["audience"] = serde_json::Value::String(audience.clone());

    let material = mint_agent_session_grant(
        &url_builder,
        &cokret_config,
        &key_store,
        &authorization.agent_principal_id,
        audience,
        authorization.granted_scope.clone(),
        dpop_binding.jkt.clone(),
        session_public_key,
        token_scope_details.clone(),
        now,
        expires_at,
    )
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let _ = &mut rng;

    let principal_id =
        cokret_core::Did::new(authorization.agent_principal_id.clone()).map_err(|e| {
            CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "agent principal is not a valid DID: {e}"
            )))
        })?;

    let mut scope_details = token_scope_details;
    scope_details["session_public_key"] =
        serde_json::Value::String(material.session_public_key.clone());

    Ok(Json(cokret_core::SessionGrantOutcome {
        principal_id,
        device_id: None,
        session_grant: material.grant_jwt,
        expires_at: material.expires_at_timestamp,
        granted_scope: material.scopes,
        scope_details,
    }))
}

fn map_oidc_exchange_error(
    error: crate::handlers::account::auth::oidc_bridge::OidcExchangeError,
) -> CokretRouteError {
    let (status, code) = match error.code {
        "internal_error" => (StatusCode::INTERNAL_SERVER_ERROR, ERROR_CODE_INTERNAL_ERROR),
        "proof_invalid" | "invalid_authorization_code" | "invalid_client" => {
            (StatusCode::UNAUTHORIZED, ERROR_CODE_INVALID_SIGNATURE)
        }
        "invalid_audience" => (StatusCode::BAD_REQUEST, ERROR_CODE_AUDIENCE_MISMATCH),
        "invalid_request" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            ERROR_CODE_SCHEMA_VIOLATION,
        ),
        "invalid_discovery_binding" => (StatusCode::CONFLICT, ERROR_CODE_FAILED_PRECONDITION),
        "upstream_link_required" => (StatusCode::FORBIDDEN, ERROR_CODE_CLAIM_REQUIRED),
        "account_unavailable"
        | "principal_did_minting_failed"
        | "principal_account_registration_failed" => (
            StatusCode::SERVICE_UNAVAILABLE,
            ERROR_CODE_SERVICE_UNAVAILABLE,
        ),
        "session_grant_denied" => (StatusCode::FORBIDDEN, ERROR_CODE_POLICY_DENIED),
        _ => (
            StatusCode::UNPROCESSABLE_ENTITY,
            ERROR_CODE_SCHEMA_VIOLATION,
        ),
    };
    let message = if error.code == code {
        error.message
    } else {
        format!("reason_code={}; {}", error.code, error.message)
    };
    CokretRouteError::coded(status, code, message)
}
