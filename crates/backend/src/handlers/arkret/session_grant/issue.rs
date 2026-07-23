use coauth_data::user::PrincipalDidRepository as _;
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
) -> Result<
    Json<arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome>,
    ArkretRouteError,
> {
    use crate::handlers::account::auth::oidc_bridge::{
        OidcCodeExchangeInput, exchange_oidc_code_for_session_grant,
    };

    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    require_principal_id(&raw_body)?;
    let body: arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody =
        serde_json::from_value(raw_body.clone())
            .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    match body.proof.proof_kind {
        arkret_models_identity::SessionGrantProofKind::OidcCodeExchange => {
            let dpop_binding = extract_kickoff_dpop(req, depot).await?;
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

            let success = exchange_oidc_code_for_session_grant(req, depot, dpop_binding, input)
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
            let grant_id = arkret_identifiers::GrantId::new(success.persisted_grant_id.clone())
                .map_err(|e| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-protocol grant_id: {e}"),
                    ))
                })?;
            let audience = arkret_identifiers::Did::new(success.session_grant.audience.clone())
                .map_err(|e| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("issued grant carried a non-DID audience: {e}"),
                    ))
                })?;

            Ok(Json(
                arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome {
                    principal_id,
                    device_id: Some(device_id),
                    session_grant: success.session_grant.grant_jwt.clone(),
                    expires_at: success.session_grant.expires_at_timestamp,
                    grant_id: Some(grant_id),
                    session_public_key: Some(success.session_grant.session_public_key.clone()),
                    audience: Some(audience),
                    granted_scope: success.session_grant.scopes.clone(),
                    scope_details: None,
                },
            ))
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
            issue_agent_key_proof_session_grant(req, depot, binding, &body).await
        }
        arkret_models_identity::SessionGrantProofKind::PreRegistrationHandoff => {
            issue_pre_registration_handoff_session_grant(req, depot, &body).await
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
    crate::handlers::account::auth::extract_dpop_binding_for_kickoff(req, depot, &url_builder)
        .await
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::INVALID_SIGNATURE,
                format!("reason_code=proof_invalid; invalid grant-binding DPoP proof: {error}"),
            )
        })
}

async fn issue_pre_registration_handoff_session_grant(
    req: &Request,
    depot: &Depot,
    body: &arkret_models_collaboration::session_grant_bodies::SessionGrantRequestBody,
) -> Result<
    Json<arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome>,
    ArkretRouteError,
> {
    use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
    use coauth_data::RepositoryAccess as _;
    use coauth_data::user::{
        BrowserSessionRepository as _, PrincipalDidRepository as _, UserRepository as _,
    };

    let (handoff, dpop) = super::super::account_handoff::authenticate_account_handoff(
        req,
        depot,
        arkret_models_identity::AccountHandoffAllowedOperation::IssueSessionGrant,
    )
    .await?;
    super::super::account_handoff::enforce_handoff_operation(
        &handoff,
        arkret_models_identity::AccountHandoffAllowedOperation::IssueSessionGrant,
    )?;
    let proof = &body.proof;
    if proof.audience.as_str() != handoff.audience
        || proof.challenge != handoff.account_handoff_grant
        || body.agent_key_authorization_ref.is_some()
        || body.agent_scope_request.is_some()
        || body.dpop_binding_proof.is_some()
        || body.applet_delegation.is_some()
        || proof.verification_method.is_some()
        || proof.issuer.is_some()
        || proof.client_id.is_some()
        || proof.redirect_uri.is_some()
        || proof.state.is_some()
        || proof.nonce.is_some()
        || proof.authorization_code.is_some()
        || proof.code_verifier.is_some()
    {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; pre-registration handoff transcript is malformed",
        ));
    }
    let now = chrono::Utc::now();
    let expires_at = proof.expires_at.ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; pre-registration handoff proof expiry is required",
        )
    })?;
    if expires_at <= now || expires_at - now > chrono::Duration::minutes(5) {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; pre-registration handoff proof is expired or too long-lived",
        ));
    }
    let expected_digest = body.canonical_request_digest().map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            error.to_string(),
        )
    })?;
    if proof.request_canonical_digest != expected_digest {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; session request canonical digest does not match",
        ));
    }
    let public_key = PublicKeyMaterial::Jwk {
        value: serde_json::to_value(&dpop.jwk)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    };
    let signing_bytes = proof
        .canonical_signing_bytes()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    if !verify_detached_ed25519_signature(&public_key, &signing_bytes, &proof.signature) {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            "reason_code=proof_invalid; handoff holder signature is invalid",
        ));
    }

    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;
    let user = repo
        .user()
        .lookup(handoff.service_account_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, &handoff.audience)
        .await?
        .filter(|binding| binding.principal_id == body.principal_id.as_str())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "principal_unknown",
            )
        })?;
    let browser_session = match handoff.browser_session_id {
        Some(id) => repo
            .browser_session()
            .lookup(id)
            .await?
            .filter(|session| session.user.id == user.id && session.finished_at.is_none())
            .ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::FAILED_PRECONDITION,
                    "account handoff browser session is no longer active",
                )
            })?,
        None => {
            repo.browser_session()
                .add(
                    &mut *rng,
                    &*clock,
                    &user,
                    Some("account-handoff".to_owned()),
                )
                .await?
        }
    };
    let scopes = if body.requested_scope.is_empty() {
        match body.device_id.as_ref() {
            Some(device_id) => vec![
                PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(),
                format!("urn:arkret:client:device:{}", device_id.as_str()),
            ],
            None => vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
        }
    } else {
        body.requested_scope.clone()
    };
    let arkret_config = depot.arkret_config()?;
    let principal_endpoint = arkret_config
        .principal_servers
        .iter()
        .find(|server| {
            crate::services::resolved_principal_audiences::effective_audience_shared(server)
                .as_ref()
                .is_some_and(|audience| audience.as_str() == handoff.audience)
        })
        .map(|server| server.endpoint.to_string());
    let operation_bearer =
        crate::handlers::account::auth::oidc_bridge::principal_server_operation_bearer(
            &arkret_config,
            &handoff.audience,
        );
    crate::handlers::account::auth::oidc_bridge::ensure_soland_account_registered(
        &depot.http_client()?,
        principal_endpoint.as_deref(),
        &binding.principal_id,
        operation_bearer,
        user.display_name.as_deref(),
        body.device_id
            .as_ref()
            .map(arkret_identifiers::DeviceId::as_str),
        user.localpart.as_str(),
    )
    .await
    .map_err(|message| {
        ArkretRouteError::coded(
            StatusCode::BAD_GATEWAY,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            format!("principal account registration failed: {message}"),
        )
    })?;
    let material = issue_session_grant_for_audience(
        &*clock,
        &arkret_config,
        &depot.key_store()?,
        &browser_session,
        dpop.jwk,
        handoff.audience.clone(),
        scopes,
        Some(&binding.principal_id),
        dpop.jkt,
    )
    .map_err(map_session_grant_material_error)?;
    let persisted =
        persist_session_grant(&mut repo, &mut *rng, &*clock, &browser_session, &material).await?;
    if !repo
        .account_handoff()
        .consume_grant(&handoff, clock.now())
        .await?
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "account handoff was already consumed",
        ));
    }
    repo.save().await?;

    Ok(Json(
        arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome {
            principal_id: body.principal_id.clone(),
            device_id: body.device_id.clone(),
            session_grant: material.grant_jwt,
            expires_at: material.expires_at_timestamp,
            grant_id: Some(
                arkret_identifiers::GrantId::new(persisted.grant_id.to_string())
                    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            ),
            session_public_key: Some(material.session_public_key),
            audience: Some(proof.audience.clone()),
            granted_scope: material.scopes,
            scope_details: None,
        },
    ))
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
) -> Result<
    Json<arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome>,
    ArkretRouteError,
> {
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
    let material = mint_agent_session_grant(
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
    let grant_id =
        arkret_identifiers::GrantId::new(persisted.grant_id.to_string()).map_err(|e| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "issued agent grant carried a non-protocol grant_id: {e}"
            )))
        })?;
    let wire_audience = arkret_identifiers::Did::new(material.audience.clone()).map_err(|e| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "issued agent grant carried a non-DID audience: {e}"
        )))
    })?;

    Ok(Json(
        arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome {
            principal_id,
            device_id: body.device_id.clone(),
            session_grant: material.grant_jwt,
            expires_at: material.expires_at_timestamp,
            grant_id: Some(grant_id),
            session_public_key: Some(material.session_public_key.clone()),
            audience: Some(wire_audience),
            granted_scope: material.scopes,
            scope_details: Some(authorization.wire_scope_details),
        },
    ))
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
