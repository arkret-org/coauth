use arkret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_CLAIM_REQUIRED, ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_INTERNAL_ERROR, ERROR_CODE_INVALID_PARAM, ERROR_CODE_INVALID_SIGNATURE,
    ERROR_CODE_POLICY_DENIED, ERROR_CODE_SCHEMA_VIOLATION, ERROR_CODE_SERVICE_UNAVAILABLE,
    ERROR_CODE_UNSUPPORTED_FEATURE, REASON_PROOF_INVALID,
};
use salvo::prelude::*;

use super::*;
use crate::handlers::arkret::*;

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
) -> Result<Json<arkret_core::SessionGrantOutcome>, ArkretRouteError> {
    use crate::handlers::account::auth::extract_dpop_binding_for_kickoff;
    use crate::handlers::account::auth::oidc_bridge::{
        OidcCodeExchangeInput, exchange_oidc_code_for_session_grant,
    };

    let url_builder = depot.url_builder()?;

    // Grant-binding proof (DPoP) extraction. A present-but-malformed proof is a hard
    // rejection: an OIDC-issued grant MUST be device-bound (`cnf.jkt`).
    let dpop_binding = extract_dpop_binding_for_kickoff(req, depot, &url_builder)
        .await
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_INVALID_SIGNATURE,
                format!("reason_code=proof_invalid; invalid grant-binding DPoP proof: {error}"),
            )
        })?;

    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    let body: arkret_core::SessionGrantRequestBody = serde_json::from_value(raw_body.clone())
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    enforce_session_grant_inception_key_window(&body, &raw_body)?;
    match body.proof.proof_kind {
        arkret_core::SessionGrantProofKind::OidcCodeExchange => {
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

            let device_id = arkret_core::DeviceId::new(success.device_id.clone()).map_err(|e| {
                ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    format!("issued grant carried a non-protocol device_id: {e}"),
                ))
            })?;
            let principal_id =
                arkret_core::Did::new(success.principal_did.clone()).map_err(|e| {
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
                arkret_core::GrantId::new(success.persisted_grant_id.clone()).map_err(|e| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-protocol grant_id: {e}"),
                    ))
                })?;

            Ok(Json(arkret_core::SessionGrantOutcome {
                principal_id,
                device_id: Some(device_id),
                session_grant: success.session_grant.grant_jwt.clone(),
                expires_at: success.session_grant.expires_at_timestamp,
                grant_id: Some(grant_id),
                session_public_key: Some(success.session_grant.session_public_key.clone()),
                audience: Some(success.session_grant.audience.clone()),
                granted_scope: success.session_grant.scopes.clone(),
                scope_details: None,
            }))
        }
        arkret_core::SessionGrantProofKind::AgentKeyProof => {
            // AKP-0008 §4.6: independent agent_key_proof validator. MUST NOT
            // fall back to any human proof validator. The grant-binding DPoP proof is
            // still required so the issued grant is device/runtime-bound
            // (`cnf.jkt`), exactly like the OIDC branch.
            let binding = require_agent_key_proof_dpop_binding(
                dpop_binding,
                body.dpop_binding_proof.as_ref(),
            )?;
            issue_agent_key_proof_session_grant(req, depot, binding, &body).await
        }
        other => Err(ArkretRouteError::coded(
            StatusCode::NOT_IMPLEMENTED,
            ERROR_CODE_UNSUPPORTED_FEATURE,
            format!(
                "reason_code=unsupported_proof_kind; this Account Authority only issues session grants via oidc_code_exchange or agent_key_proof; proof_kind={other:?} is not implemented here"
            ),
        )),
    }
}

fn require_agent_key_proof_dpop_binding(
    binding: Option<crate::handlers::account::auth::DpopSessionBinding>,
    body_binding: Option<&arkret_core::SessionGrantDpopBindingProof>,
) -> Result<crate::handlers::account::auth::DpopSessionBinding, ArkretRouteError> {
    let binding = binding.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_core::error::ERROR_CODE_DID_PROOF_REQUIRED,
            "agent_key_proof session grant requires a grant-binding DPoP proof",
        )
    })?;
    let body_binding = body_binding.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_INVALID_SIGNATURE,
            "reason_code=proof_invalid; agent_key_proof body must carry dpop_binding_proof",
        )
    })?;
    if body_binding.proof_jwt != binding.proof_jwt {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_INVALID_SIGNATURE,
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
fn enforce_session_grant_inception_key_window(
    body: &arkret_core::SessionGrantRequestBody,
    raw_body: &serde_json::Value,
) -> Result<(), ArkretRouteError> {
    if !matches!(
        body.proof.proof_kind,
        arkret_core::SessionGrantProofKind::DidBoundSignature
            | arkret_core::SessionGrantProofKind::PairedDeviceProof
    ) {
        return Ok(());
    }
    let clock = crate::handlers::make_clock();
    crate::services::inception_key_window::enforce_inception_key_window_rfc3339(
        crate::services::inception_key_window::session_grant_request_anchor(raw_body),
        clock.now(),
    )
    .map_err(inception_key_window_error)
}

fn inception_key_window_error(
    error: crate::services::inception_key_window::InceptionKeyWindowError,
) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::FORBIDDEN,
        ERROR_CODE_FAILED_PRECONDITION,
        format!("reason_code={}; {error}", error.reason_code()),
    )
}

async fn issue_agent_key_proof_session_grant(
    _req: &mut Request,
    depot: &Depot,
    dpop_binding: crate::handlers::account::auth::DpopSessionBinding,
    body: &arkret_core::SessionGrantRequestBody,
) -> Result<Json<arkret_core::SessionGrantOutcome>, ArkretRouteError> {
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
    let agent_id = body
        .principal_id
        .as_ref()
        .map(arkret_core::Did::as_str)
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                REASON_PROOF_INVALID,
                "reason_code=proof_invalid; agent principal_id is required",
            )
        })?;
    if let Err(rejection) =
        enforce_authoritative_agent_lifecycle(&http_client, &arkret_config, agent_id).await
    {
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
    let authorization = match validate_agent_session_proof(
        &mut repo,
        &mut rng,
        &*clock,
        &url_builder,
        &arkret_config,
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

    // Controller lifecycle gate: a deactivated / suspended controller fails
    // closed (AKP-0008 §4.6). Resolve the controller's local user record when
    // the DID maps to a coauth-hosted account. Bind the lookup to an owned
    // value so the sub-repo borrow is released before `repo.cancel()`.
    let controller_blocked = if let Some(user_id) =
        parse_local_user_did_for(&arkret_config, &authorization.controller_id)
    {
        let user = repo
            .user()
            .lookup(user_id)
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
            ERROR_CODE_FAILED_PRECONDITION,
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
    let audience = body.proof.audience.clone();
    let now = clock.now();
    let expires_at = now + authorization.ttl;

    let session_public_key = serde_json::to_string(&dpop_binding.public_jwk).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(error))
    })?;
    let material = mint_agent_session_grant(
        &arkret_config,
        &key_store,
        &authorization.agent_id,
        audience,
        authorization.granted_scope.clone(),
        dpop_binding.jkt.clone(),
        session_public_key,
        authorization.scope_details.clone(),
        now,
        expires_at,
    )
    .map_err(map_session_grant_material_error)?;

    let persisted = persist_unbound_session_grant(&mut repo, &mut rng, &*clock, &material)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    repo.save()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let principal_id = arkret_core::Did::new(authorization.agent_id.clone()).map_err(|e| {
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
    let grant_id = arkret_core::GrantId::new(persisted.grant_id.to_string()).map_err(|e| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "issued agent grant carried a non-protocol grant_id: {e}"
        )))
    })?;

    Ok(Json(arkret_core::SessionGrantOutcome {
        principal_id,
        device_id: None,
        session_grant: material.grant_jwt,
        expires_at: material.expires_at_timestamp,
        grant_id: Some(grant_id),
        session_public_key: Some(material.session_public_key.clone()),
        audience: Some(material.audience.clone()),
        granted_scope: material.scopes,
        scope_details: Some(authorization.wire_scope_details),
    }))
}

fn map_session_grant_material_error(error: SessionGrantError) -> ArkretRouteError {
    match error {
        error @ SessionGrantError::DidWebPrincipalNotExplicit => ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_INVALID_PARAM,
            error.to_string(),
        ),
        SessionGrantError::InceptionKeyWindowExceeded(error) => inception_key_window_error(error),
        other => ArkretRouteError::Internal(Box::new(other)),
    }
}

fn map_oidc_exchange_error(
    error: crate::handlers::account::auth::oidc_bridge::OidcExchangeError,
) -> ArkretRouteError {
    let (status, code) = match error.code {
        "internal_error" => (StatusCode::INTERNAL_SERVER_ERROR, ERROR_CODE_INTERNAL_ERROR),
        REASON_PROOF_INVALID | "invalid_authorization_code" | "invalid_client" => {
            (StatusCode::UNAUTHORIZED, REASON_PROOF_INVALID)
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
                .with_alg(JsonWebSignatureAlg::EdDsa);
        DpopSessionBinding {
            proof_jwt: proof_jwt.to_owned(),
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
                assert_eq!(code, REASON_PROOF_INVALID);
                assert!(message.contains("reason_code=invalid_authorization_code"));
            }
            other => panic!("expected coded error, got {other:?}"),
        }
    }

    #[test]
    fn agent_key_proof_session_grant_requires_dpop_header_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            None,
            Some(&arkret_core::SessionGrantDpopBindingProof {
                proof_jwt: "proof.jwt".to_owned(),
            }),
        ));

        assert_coded(
            err,
            StatusCode::UNAUTHORIZED,
            arkret_core::error::ERROR_CODE_DID_PROOF_REQUIRED,
        );
    }

    #[test]
    fn agent_key_proof_session_grant_requires_body_dpop_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            Some(test_dpop_binding("proof.jwt")),
            None,
        ));

        assert_coded(err, StatusCode::UNAUTHORIZED, ERROR_CODE_INVALID_SIGNATURE);
    }

    #[test]
    fn agent_key_proof_session_grant_rejects_mismatched_body_dpop_binding() {
        let err = unwrap_binding_error(require_agent_key_proof_dpop_binding(
            Some(test_dpop_binding("header.proof.jwt")),
            Some(&arkret_core::SessionGrantDpopBindingProof {
                proof_jwt: "body.proof.jwt".to_owned(),
            }),
        ));

        assert_coded(err, StatusCode::UNAUTHORIZED, ERROR_CODE_INVALID_SIGNATURE);
    }
}
