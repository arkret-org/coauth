use arkret_identifiers::{DeviceId, ServiceId};
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantRefreshOutcome, SessionGrantRefreshProof, SessionGrantRefreshRequestBody,
    session_grant_refresh_proof_signing_bytes, session_grant_refresh_request_digest,
};
use arkret_models_identity::SessionGrantProofKind;
use chrono::{DateTime, Utc};
use coauth_data::{
    NewSessionGrantOperation, SessionGrantExactOutcome, SessionGrantProofAuthorization,
    SessionGrantRefreshOutcome as LedgerRefreshOutcome, SessionGrantReserveOutcome,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;
use sha2::Digest as _;

use super::*;
use crate::handlers::arkret::*;
use crate::services::device_signing_directory::{
    ResolvedDeviceSigningKey, resolve_authorized_device_signing_key,
};
use crate::services::resolved_principal_audiences;

const SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS: i64 = 300;
const SOFT_LOGOUT_DID_PROOF_REPLAY_REASON: &str = "did_proof_replay_window_exceeded";

pub struct RefreshCanonicalJson(Vec<u8>);

impl Scribe for RefreshCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical JSON is writable");
    }
}

fn did_proof_required(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
        message,
    )
}

fn did_proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ReasonCode::PROOF_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn did_proof_replay_window_exceeded(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ReasonCode::PROOF_INVALID,
        format!(
            "reason_code={}; {}",
            SOFT_LOGOUT_DID_PROOF_REPLAY_REASON,
            message.into()
        ),
    )
}

/// The closed refresh DTO always carries the proof; presence is a parse-time
/// guarantee, so only its field contents still need validating.
fn required_soft_logout_proof(body: &SessionGrantRefreshRequestBody) -> &SessionGrantRefreshProof {
    &body.proof
}

/// A required proof string may still arrive present-but-blank.
fn required_proof_str<'a>(value: &'a str, field: &str) -> Result<&'a str, ArkretRouteError> {
    Some(value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| did_proof_required(format!("soft logout DID proof requires {field}")))
}

fn validate_soft_logout_proof_kind(
    proof_kind: SessionGrantProofKind,
) -> Result<(), ArkretRouteError> {
    match proof_kind {
        SessionGrantProofKind::DidBoundSignature | SessionGrantProofKind::PairedDeviceProof => {
            Ok(())
        }
        other => Err(did_proof_invalid(format!(
            "unsupported soft logout DID proof_kind {other:?}"
        ))),
    }
}

fn require_soft_logout_bound_device_id<'a>(
    presented_device_id: Option<&'a str>,
    persisted_device_id: Option<&'a str>,
) -> Result<&'a str, ArkretRouteError> {
    let presented = presented_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            did_proof_required("soft logout recovery requires the presented device_id")
        })?;
    DeviceId::new(presented.to_owned()).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            format!("device_id is not a protocol device identifier: {error}"),
        )
    })?;

    let persisted = persisted_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            did_proof_required("session grant has no device_id binding for soft logout recovery")
        })?;
    if presented != persisted {
        return Err(did_proof_invalid(
            "presented device_id does not match the persisted session grant binding",
        ));
    }

    Ok(persisted)
}

fn validate_soft_logout_did_proof_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    let freshness_secs = (expires_at - issued_at).num_seconds();
    if freshness_secs <= 0 || freshness_secs > SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS {
        return Err(did_proof_replay_window_exceeded(format!(
            "DID proof expires_at - issued_at must be within 1..={SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS} seconds"
        )));
    }

    let skew_secs = (issued_at - now).num_seconds().abs();
    if skew_secs > SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS {
        return Err(did_proof_replay_window_exceeded(format!(
            "DID proof issued_at is outside the {SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS} second receiver skew window"
        )));
    }

    if now >= expires_at {
        return Err(did_proof_replay_window_exceeded(
            "DID proof has expired and cannot restore a soft-logged-out session",
        ));
    }

    Ok(())
}

fn soft_logout_restore_request_canonical_digest(
    grant_jwt: &str,
    principal_id: &str,
    device_id: &str,
    audience: &str,
    grant_binding_key_id: &str,
) -> Result<String, ArkretRouteError> {
    let audience = ServiceId::new(audience.to_owned()).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session grant audience is not a service core_id: {error}"
        )))
    })?;
    session_grant_refresh_request_digest(
        grant_jwt,
        principal_id,
        device_id,
        &audience,
        grant_binding_key_id,
    )
    .map(|digest| digest.as_str().to_owned())
    .map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "soft logout restore request canonicalization failed: {error}"
        )))
    })
}

fn verification_method_did(verification_method: &str) -> &str {
    let without_fragment = verification_method
        .split_once('#')
        .map_or(verification_method, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
}

/// Verify the soft-logout proof against the device signing key resolved from
/// the Principal Server directory and return its protected-header `kid`.
fn verify_detached_jws_with_device_key(
    detached_jws: &str,
    payload_bytes: &[u8],
    device_multibase: &str,
) -> Result<String, String> {
    use arkret_signatures::proof::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};

    let material = PublicKeyMaterial::Ed25519Multibase {
        value: device_multibase.to_owned(),
    };
    let verified = Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws_with_metadata(detached_jws, payload_bytes, &material)
        .map_err(|error| error.to_string())?;
    verified
        .key_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "protected header missing kid".to_owned())
}

async fn verify_soft_logout_did_proof(
    http_client: &reqwest::Client,
    arkret_config: &coauth_config::ArkretConfig,
    body: &SessionGrantRefreshRequestBody,
    prior_grant: &coauth_data::SessionGrant,
    device_id: &str,
    now: DateTime<Utc>,
) -> Result<ResolvedDeviceSigningKey, ArkretRouteError> {
    let proof = required_soft_logout_proof(body);
    validate_soft_logout_proof_kind(proof.proof_kind)?;

    let challenge = required_proof_str(&proof.challenge, "challenge")?;
    let proof_audience = &proof.audience;
    let request_canonical_digest = proof.request_canonical_digest.as_str();
    let proof_jws = required_proof_str(&proof.signature, "signature")?;
    let issued_at = proof.issued_at;
    let expires_at = proof.expires_at;

    if proof_audience.as_str() != prior_grant.audience {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "soft logout DID proof audience must match the session grant audience",
        ));
    }

    validate_soft_logout_did_proof_window(issued_at, expires_at, now)?;

    let payload = session_grant_refresh_proof_signing_bytes(
        &prior_grant.subject,
        device_id,
        proof_audience,
        challenge,
        request_canonical_digest,
        issued_at,
        expires_at,
    )
    .map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "soft logout DID proof canonicalization failed: {error}"
        )))
    })?;

    // Device-identity source of truth is the Principal Server's device directory,
    // NOT the principal DID document. The device signing key was authorized by a
    // `ak.device.authorize` event and projected into soland's device directory; a
    // `ak.device.revoke` masks it. Resolve the authorized, non-revoked key for
    // this human `(principal, device)` and verify the detached DID-proof JWS
    // against it. Agent runtimes use the separate `agent_key_proof` branch.
    // The directory only surfaces verified, non-revoked devices, so a resolved
    // key is itself proof the device is currently authorized.
    let resolved = resolve_authorized_device_signing_key(
        http_client,
        arkret_config,
        resolved_principal_audiences::shared(),
        &prior_grant.audience,
        &prior_grant.subject,
        device_id,
    )
    .await
    .map_err(|error| did_proof_invalid(format!("device signing key resolution failed: {error}")))?;

    let verification_method =
        verify_detached_jws_with_device_key(proof_jws, &payload, &resolved.multibase)
            .map_err(|error| did_proof_invalid(format!("DID proof JWS invalid: {error}")))?;
    if let Some(expected_method) = proof
        .verification_method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && expected_method != verification_method.as_str()
    {
        return Err(did_proof_invalid(
            "DID proof verification_method does not match the detached JWS kid",
        ));
    }
    // The kid principal MUST still be the session-grant subject, so a proof
    // signed under a different principal's device key cannot restore this
    // session. The kid may carry either the principal DID prefix
    // (`{principal}#{device}`) or the bare device `did:key`; accept either, but
    // when it is principal-prefixed it MUST match the subject.
    let kid_principal = verification_method_did(&verification_method);
    let kid_is_principal_prefixed =
        kid_principal.starts_with("did:webvh:") || kid_principal.starts_with("did:web:");
    if kid_is_principal_prefixed && kid_principal != prior_grant.subject {
        return Err(did_proof_invalid(
            "DID proof verification_method principal does not match the session grant subject",
        ));
    }
    if !kid_is_principal_prefixed
        && !kid_principal.starts_with("did:key:")
        && verification_method.as_str() != resolved.device_signing_key_did
    {
        return Err(did_proof_invalid(
            "DID proof verification_method does not match the authorized device signing key",
        ));
    }

    let expected_digest = soft_logout_restore_request_canonical_digest(
        &body.grant_jwt,
        &prior_grant.subject,
        device_id,
        proof_audience.as_str(),
        &verification_method,
    )?;
    if request_canonical_digest != expected_digest {
        return Err(did_proof_invalid(
            "DID proof request_canonical_digest does not match the presented restore request",
        ));
    }

    Ok(resolved)
}

// ── DPoP-bound session-grant refresh + debug seed ──────────────
//
// These two handlers were added in G3.C1 to complete the device-bound
// session-grant story: `refresh_session_grant` rotates an existing
// DPoP-bound grant onto a new access token (keeping `cnf.jkt` constant),
// and `debug_issue_dpop_grant` is the cotest harness seam that mints a
// fully signed grant without going through OIDC.

/// `POST /_arkret/gate/account/session-grants/refresh` — exchange a near-expiry
/// DPoP-bound session grant for a fresh one. The caller MUST present:
///
/// * A `DPoP` header that proves possession of the same key the existing grant is bound to
///   (`cnf.jkt` on the old grant must match the new proof's `jkt`).
/// * A request body carrying the prior grant JWT, the bound `device_id`, and a fresh human-device
///   DID proof over the soft-logout restore transcript.
///
/// On success the old grant is revoked (single-use semantics — its
/// `revoked_at` is persisted) and a new grant is issued with the same
/// `cnf.jkt`, a rotated id, and a fresh expiry.
#[handler]
pub async fn refresh_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<RefreshCanonicalJson, ArkretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
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

    if body.grant_jwt.trim().is_empty() {
        return Err(ArkretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    // 2. Parse + load the existing grant. We never verify the JWT signature here — the persisted
    //    row IS the source of truth — but we DO read the `cnf.jkt` claim out of the JWT payload to
    //    bind the proof.
    let jwt: Jwt<'_, SignedSessionGrantClaims> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| ArkretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let prior_payload = jwt.payload().clone();
    prior_payload
        .validate()
        .map_err(|error| ArkretRouteError::BadRequest(format!("invalid grant_jwt: {error}")))?;
    let expected_jkt = prior_payload.cnf.jkt.clone();

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&body.grant_jwt)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
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
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification =
        DpopVerifier::verify_without_replay(&dpop_header, &htm, &htu, now, Some(&body.grant_jwt))
            .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::INVALID_SIGNATURE,
                error.to_string(),
            )
        })?;

    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;

    let proof = &body.proof;
    let request_digest = &proof.request_canonical_digest;
    let request_identity = format!(
        "refresh:{}:{}",
        prior_grant.grant_id,
        request_digest.as_str()
    );
    let mut redacted =
        serde_json::to_value(&body).map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if let Some(proof) = redacted
        .get_mut("proof")
        .and_then(serde_json::Value::as_object_mut)
    {
        for field in ["challenge", "signature"] {
            if let Some(secret) = proof.get(field) {
                let bytes = arkret_canonical::canonical_json_bytes(secret)
                    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
                proof.insert(
                    field.to_owned(),
                    serde_json::Value::String(format!(
                        "sha256:{}",
                        hex::encode(sha2::Sha256::digest(bytes))
                    )),
                );
            }
        }
    }
    let canonical_intent = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "request": redacted,
        "holder_jkt": verification.jkt,
    }))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let canonical_intent_digest: [u8; 32] = sha2::Sha256::digest(&canonical_intent).into();
    let grant_not_before = arkret_canonical::normalize_timestamp_canonical(now);
    let ttl = if prior_payload.proof_kind == Some(SessionGrantProofKind::AgentKeyProof) {
        arkret_config
            .session_grant_ttl
            .min(crate::handlers::account::agents::AGENT_SESSION_MAX_TTL)
    } else {
        arkret_config.session_grant_ttl
    };
    let grant_expires_at = grant_not_before + ttl;
    let (_, signing_key) = preferred_signing_key(&key_store)
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?;
    let signing_key_id = signing_key
        .kid()
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?;
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer: &prior_grant.issuer,
                operation: coauth_data::SessionGrantOperationDescriptor::Refresh {
                    predecessor_grant_id: prior_grant.grant_id.clone(),
                },
                proof_kind: None,
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_grant_id: Some(&prior_grant.grant_id),
                issuance_nonce: None,
                session_id: Some(&prior_payload.session_id),
                grant_not_before: Some(grant_not_before),
                grant_expires_at: Some(grant_expires_at),
                signing_key_id: Some(signing_key_id),
                retained_until: grant_expires_at + chrono::Duration::days(7),
            },
        )
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
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
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
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
                let state = match successor.lifecycle_state {
                    coauth_data::SessionGrantLifecycleState::Revoked => {
                        arkret_wire::SessionGrantReplayTerminalState::Revoked
                    }
                    coauth_data::SessionGrantLifecycleState::Superseded => {
                        arkret_wire::SessionGrantReplayTerminalState::Superseded
                    }
                    coauth_data::SessionGrantLifecycleState::Active => unreachable!(),
                };
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
            return Ok(RefreshCanonicalJson(bytes));
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
        let state = match prior_grant.lifecycle_state {
            coauth_data::SessionGrantLifecycleState::Revoked => {
                arkret_wire::SessionGrantReplayTerminalState::Revoked
            }
            coauth_data::SessionGrantLifecycleState::Superseded => {
                arkret_wire::SessionGrantReplayTerminalState::Superseded
            }
            coauth_data::SessionGrantLifecycleState::Active => unreachable!(),
        };
        return Err(ArkretRouteError::session_grant_replay_terminal(
            prior_grant.grant_id,
            state,
        ));
    }

    // Audience and stable device binding are common to both human and Agent
    // grant chains. Check them before dispatching to the credential-specific
    // fresh-proof validator.
    if let Some(requested) = body.audience.as_ref()
        && requested.as_str() != prior_grant.audience
    {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "session-grant rotation MUST NOT change the bound audience",
        ));
    }
    let device_id = require_soft_logout_bound_device_id(
        Some(body.device_id.as_str()),
        prior_grant.device_id.as_deref(),
    )?;

    if prior_payload.proof_kind == Some(SessionGrantProofKind::AgentKeyProof) {
        use crate::handlers::account::agents::{
            AgentSessionProofError, enforce_authoritative_agent_lifecycle,
            validate_agent_session_refresh_proof,
        };

        let authoritative_agent = match enforce_authoritative_agent_lifecycle(
            &http_client,
            &arkret_config,
            prior_payload.subject.as_str(),
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
        let proof = &body.proof;
        let device_id = DeviceId::new(device_id.to_owned()).map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::INVALID_PARAM,
                format!("device_id is not a protocol device identifier: {error}"),
            )
        })?;
        let authorization = match validate_agent_session_refresh_proof(
            &mut repo,
            &mut rng,
            &*clock,
            &authoritative_agent,
            &prior_payload,
            &body.grant_jwt,
            &device_id,
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
                return Err(did_proof_invalid(
                    "Agent session refresh cannot request expanded human-approved scope",
                ));
            }
        };

        let controller_binding = repo
            .principal_did()
            .get_by_did_and_audience(
                &authorization.accountable_principal_id,
                prior_grant.audience.as_str(),
            )
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

        let scopes: Vec<String> = prior_grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect();
        let scope_details = prior_payload.scope_details.clone().ok_or_else(|| {
            did_proof_invalid("Agent session grant is missing its authorization scope binding")
        })?;
        let session_public_key = serde_json::to_string(&verification.jwk)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        let new_material = mint_agent_session_grant(
            &issuance_seed,
            &arkret_config,
            &key_store,
            prior_payload.subject.as_str(),
            &device_id,
            prior_grant.audience.clone(),
            scopes,
            verification.jkt.clone(),
            session_public_key,
            scope_details,
            arkret_identifiers::EventId::new(authorization.authorized_event_id.clone())
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            arkret_wire::DidUrl::new(authorization.verification_method.clone()).map_err(
                |error| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        error.to_owned(),
                    ))
                },
            )?,
            issuance_seed.not_before,
            issuance_seed.expires_at,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        let audience = ServiceId::new(new_material.audience.clone()).map_err(|error| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "refreshed Agent grant carried an invalid service core_id audience: {error}"
            )))
        })?;
        let outcome = SessionGrantRefreshOutcome {
            grant_id: new_material.grant_id.clone(),
            grant_jwt: new_material.grant_jwt.clone(),
            session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
                &new_material.session_public_key,
            )
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            expires_at: new_material.expires_at_timestamp,
            audience,
            scopes: new_material.scopes.clone(),
            dpop_jkt: verification.jkt.clone(),
            previous_grant_id: prior_grant.grant_id.clone(),
        };
        let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        let inserted = repo
            .dpop_replay()
            .consume_jti(crate::services::dpop::dpop_replay_record(
                &verification.claims.jti,
                now,
            ))
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        if !inserted {
            repo.cancel().await.ok();
            return Err(did_proof_invalid("refresh DPoP JTI was already consumed"));
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
            response_digest: sha2::Sha256::digest(&canonical_outcome).into(),
        };
        let committed = repo
            .oauth_session_grant()
            .commit_refresh(
                &mut rng,
                &*clock,
                operation.id,
                SessionGrantProofAuthorization {
                    authorization_ref: &authorization_ref,
                    checkpoint: &checkpoint,
                    proof_expires_at,
                },
                exact_outcome,
                &prior_grant.grant_id,
                new_session_grant_record(None, &new_material),
            )
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        repo.save().await?;
        if matches!(&committed, LedgerRefreshOutcome::Committed { .. }) {
            super::super::test_chaos::maybe_delay_post_commit(
                "session_grant_refresh_post_commit_pre_response",
                &request_identity,
            )
            .await;
        }
        return match committed {
            LedgerRefreshOutcome::Committed { .. } => Ok(RefreshCanonicalJson(canonical_outcome)),
            LedgerRefreshOutcome::Replay(operation) => operation
                .canonical_outcome
                .map(RefreshCanonicalJson)
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::SERVICE_UNAVAILABLE,
                        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                        "agent refresh replay has no canonical outcome",
                    )
                }),
            LedgerRefreshOutcome::PredecessorTerminal(grant) => {
                let state = match grant.lifecycle_state {
                    coauth_data::SessionGrantLifecycleState::Revoked => {
                        arkret_wire::SessionGrantReplayTerminalState::Revoked
                    }
                    coauth_data::SessionGrantLifecycleState::Superseded => {
                        arkret_wire::SessionGrantReplayTerminalState::Superseded
                    }
                    coauth_data::SessionGrantLifecycleState::Active => {
                        return Err(ArkretRouteError::session_grant_replay_expired(
                            grant.grant_id,
                        ));
                    }
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
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
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
        repo.cancel()
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
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
        arkret_models_collaboration::objects::account_status::AccountStatus::Active
        | arkret_models_collaboration::objects::account_status::AccountStatus::SoftLoggedOut => {
            None
        }
    };
    if let Some(code) = lifecycle_code {
        repo.cancel()
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        return Err(ArkretRouteError::coded(
            super::account_lifecycle_status(
                code,
                arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh,
            ),
            code.as_str(),
            "account status forbids session-grant refresh",
        ));
    }

    // 5. Mint a new grant with the same subject + scope + audience. The
    // audience MUST NOT change across rotation: a client holding a grant for
    // one Principal Server must not be able to rotate it into a grant for a
    // different audience (which it could then exchange there). Ignore any
    // client-supplied audience; reject an explicit mismatch defensively.
    let authorized_device = verify_soft_logout_did_proof(
        &http_client,
        &arkret_config,
        &body,
        &prior_grant,
        device_id,
        now,
    )
    .await?;

    // 6. Rebuild the successor solely from the durable reservation seed. The
    // signing window, nonce, chain id and signing key therefore remain byte
    // stable across a retry after an ambiguous transport failure.
    let audience = prior_grant.audience.clone();
    let scopes: Vec<String> = prior_grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let issuance_seed = SessionGrantIssuanceSeed::from_operation(&operation)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let proof_kind = prior_payload.proof_kind.ok_or_else(|| {
        did_proof_required("session-grant refresh predecessor is missing proof_kind")
    })?;
    let new_material = issue_session_grant_for_audience(
        &issuance_seed,
        &*clock,
        &arkret_config,
        &key_store,
        &browser_session,
        verification.jwk.clone(),
        audience,
        scopes,
        Some(&prior_grant.subject),
        verification.jkt.clone(),
        proof_kind,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let response_audience = ServiceId::new(new_material.audience.clone()).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "refreshed grant carried an invalid service core_id audience: {error}"
        )))
    })?;

    let outcome = SessionGrantRefreshOutcome {
        grant_id: new_material.grant_id.clone(),
        grant_jwt: new_material.grant_jwt.clone(),
        session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
            &new_material.session_public_key,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        expires_at: new_material.expires_at_timestamp,
        audience: response_audience,
        scopes: new_material.scopes.clone(),
        dpop_jkt: verification.jkt.clone(),
        previous_grant_id: prior_grant.grant_id.clone(),
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let inserted = repo
        .dpop_replay()
        .consume_jti(crate::services::dpop::dpop_replay_record(
            &verification.claims.jti,
            now,
        ))
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if !inserted {
        repo.cancel().await.ok();
        return Err(did_proof_invalid("refresh DPoP JTI was already consumed"));
    }
    let proof = &body.proof;
    let proof_expires_at = proof.expires_at;
    let challenge = proof.challenge.as_str();
    let authorization_ref = format!("device-refresh:{}", challenge);
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
            operation.id,
            SessionGrantProofAuthorization {
                authorization_ref: &authorization_ref,
                checkpoint: &checkpoint,
                proof_expires_at,
            },
            SessionGrantExactOutcome {
                canonical_response: &canonical_outcome,
                response_digest: sha2::Sha256::digest(&canonical_outcome).into(),
            },
            &prior_grant.grant_id,
            new_session_grant_record(Some(browser_session.id), &new_material),
        )
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    repo.save().await?;
    if matches!(&committed, LedgerRefreshOutcome::Committed { .. }) {
        super::super::test_chaos::maybe_delay_post_commit(
            "session_grant_refresh_post_commit_pre_response",
            &request_identity,
        )
        .await;
    }
    match committed {
        LedgerRefreshOutcome::Committed { .. } => Ok(RefreshCanonicalJson(canonical_outcome)),
        LedgerRefreshOutcome::Replay(operation) => operation
            .canonical_outcome
            .map(RefreshCanonicalJson)
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
            let state = match grant.lifecycle_state {
                coauth_data::SessionGrantLifecycleState::Revoked => {
                    arkret_wire::SessionGrantReplayTerminalState::Revoked
                }
                coauth_data::SessionGrantLifecycleState::Superseded => {
                    arkret_wire::SessionGrantReplayTerminalState::Superseded
                }
                coauth_data::SessionGrantLifecycleState::Active => unreachable!(),
            };
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
    use chrono::Duration;

    use super::*;

    const DEVICE_ID: &str = "ak:device:0196419b-0000-7000-8000-000000000001";
    const OTHER_DEVICE_ID: &str = "ak:device:0196419b-0000-7000-8000-000000000002";

    fn ts(seconds: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(seconds, 0).expect("test timestamp must be valid")
    }

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
    fn soft_logout_proof_window_rejects_more_than_300_seconds() {
        let issued_at = ts(1_700_000_000);
        let err = validate_soft_logout_did_proof_window(
            issued_at,
            issued_at + Duration::seconds(SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS + 1),
            issued_at,
        )
        .expect_err("oversized DID proof replay window must fail closed");

        let message = assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
        assert!(message.contains(SOFT_LOGOUT_DID_PROOF_REPLAY_REASON));
    }

    #[test]
    fn soft_logout_proof_window_rejects_expired_proof() {
        let issued_at = ts(1_700_000_000);
        let expires_at = issued_at + Duration::seconds(SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS);
        let err = validate_soft_logout_did_proof_window(issued_at, expires_at, expires_at)
            .expect_err("expired DID proof must fail closed");

        let message = assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
        assert!(message.contains(SOFT_LOGOUT_DID_PROOF_REPLAY_REASON));
    }

    #[test]
    fn soft_logout_proof_kind_rejects_unrelated_branches() {
        let err = validate_soft_logout_proof_kind(SessionGrantProofKind::AgentKeyProof)
            .expect_err("agent_key_proof must not restore a human soft-logged-out session");

        assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[test]
    fn soft_logout_device_binding_requires_presented_device_id() {
        let err = require_soft_logout_bound_device_id(None, Some(DEVICE_ID))
            .expect_err("missing presented device_id must require DID proof context");

        assert_coded(err, arkret_wire::ErrorCode::DID_PROOF_REQUIRED);
    }

    #[test]
    fn soft_logout_device_binding_requires_persisted_session_grant_device() {
        let err = require_soft_logout_bound_device_id(Some(DEVICE_ID), None)
            .expect_err("legacy unbound grant must not be recoverable");

        assert_coded(err, arkret_wire::ErrorCode::DID_PROOF_REQUIRED);
    }

    #[test]
    fn soft_logout_device_binding_rejects_device_mismatch() {
        let err = require_soft_logout_bound_device_id(Some(OTHER_DEVICE_ID), Some(DEVICE_ID))
            .expect_err("presented device_id must match the grant binding");

        assert_coded(err, arkret_wire::ReasonCode::PROOF_INVALID);
    }

    #[test]
    fn soft_logout_device_binding_accepts_persisted_match() {
        let device_id = require_soft_logout_bound_device_id(Some(DEVICE_ID), Some(DEVICE_ID))
            .expect("matching device bindings should pass");

        assert_eq!(device_id, DEVICE_ID);
    }

    #[test]
    fn soft_logout_restore_request_digest_binds_device_and_grant_binding_key() {
        let base = soft_logout_restore_request_canonical_digest(
            "grant.jwt.value",
            "did:web:alice.example",
            DEVICE_ID,
            "ak:did_core:web:auth.example",
            "did:web:alice.example#device-key-1",
        )
        .expect("request digest should compute");
        assert!(base.starts_with("sha256:"));

        let other_device = soft_logout_restore_request_canonical_digest(
            "grant.jwt.value",
            "did:web:alice.example",
            OTHER_DEVICE_ID,
            "ak:did_core:web:auth.example",
            "did:web:alice.example#device-key-1",
        )
        .expect("request digest should compute");
        let other_grant_binding_key = soft_logout_restore_request_canonical_digest(
            "grant.jwt.value",
            "did:web:alice.example",
            DEVICE_ID,
            "ak:did_core:web:auth.example",
            "did:web:alice.example#other-device-key",
        )
        .expect("request digest should compute");

        assert_ne!(base, other_device);
        assert_ne!(base, other_grant_binding_key);
    }
}
