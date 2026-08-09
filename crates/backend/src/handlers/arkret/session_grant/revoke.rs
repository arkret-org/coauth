use arkret_identifiers::{DeviceId, Did, SessionGrantId};
use arkret_models_collaboration::account_lifecycle::{
    AccountLifecycleProof, SessionRevokeRequestBody,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::{
    NewSessionGrantOperation, RepositoryAccess, SessionGrant, SessionGrantProofAuthorization,
    SessionGrantReserveOutcome, SessionGrantRevokeOutcome, SessionGrantRevokeSelector,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;
use sha2::Digest as _;

use super::*;
use crate::handlers::arkret::*;
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;

const SESSION_REVOKE_PROOF_MAX_WINDOW_SECS: i64 = 300;

fn empty_session_revoke_body() -> SessionRevokeRequestBody {
    SessionRevokeRequestBody {
        target_grant_id: None,
        target_device_id: None,
        all_sessions: None,
        applet_id: None,
        effective_scope: None,
        registration_epoch: None,
        service_id: None,
        capability_grant_refs: Vec::new(),
        proof: None,
    }
}

fn session_grant_not_found() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
        "session grant is unknown, inactive, or not owned by the current principal",
    )
}

fn selector_conflict(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SESSION_REVOKE_SELECTOR_CONFLICT,
        message,
    )
}

fn lifecycle_proof_required(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
        message,
    )
}

fn lifecycle_proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ReasonCode::PROOF_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn bearer_session_grant(req: &Request) -> Result<&str, ArkretRouteError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| ArkretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))
}

async fn parse_session_revoke_body(
    req: &mut Request,
) -> Result<SessionRevokeRequestBody, ArkretRouteError> {
    let has_json_content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    let content_length = req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());

    if content_length == Some(0) || (!has_json_content_type && content_length.is_none()) {
        return Ok(empty_session_revoke_body());
    }

    let body: Option<SessionRevokeRequestBody> = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    Ok(body.unwrap_or_else(empty_session_revoke_body))
}

enum RevokeSelector {
    Current,
    Grant(SessionGrantId),
    Device(DeviceId),
    All,
}

fn revoke_selector(body: &SessionRevokeRequestBody) -> Result<RevokeSelector, ArkretRouteError> {
    if body.all_sessions == Some(false) {
        return Err(selector_conflict(
            "all_sessions selector must be omitted or set to true",
        ));
    }

    let mut selector_count = 0;
    if body.target_grant_id.is_some() {
        selector_count += 1;
    }
    if body.target_device_id.is_some() {
        selector_count += 1;
    }
    if body.all_sessions == Some(true) {
        selector_count += 1;
    }
    if session_revoke_has_applet_selector(body) {
        selector_count += 1;
    }
    if selector_count > 1 {
        return Err(selector_conflict(
            "target_grant_id, target_device_id, all_sessions and applet selector are mutually exclusive",
        ));
    }
    if session_revoke_has_applet_selector(body) {
        return Err(selector_conflict(
            "applet selector session revoke is not supported by this Account Authority endpoint",
        ));
    }

    if let Some(target_grant_id) = body.target_grant_id.clone() {
        Ok(RevokeSelector::Grant(target_grant_id))
    } else if let Some(target_device_id) = body.target_device_id.clone() {
        Ok(RevokeSelector::Device(target_device_id))
    } else if body.all_sessions == Some(true) {
        Ok(RevokeSelector::All)
    } else {
        Ok(RevokeSelector::Current)
    }
}

fn session_revoke_has_applet_selector(body: &SessionRevokeRequestBody) -> bool {
    body.applet_id.is_some()
        || body.effective_scope.is_some()
        || body.registration_epoch.is_some()
        || body.service_id.is_some()
        || !body.capability_grant_refs.is_empty()
}

fn verification_method_did(verification_method: &str) -> &str {
    let without_fragment = verification_method
        .split_once('#')
        .map_or(verification_method, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
}

fn grant_payload(grant: &SessionGrant) -> Option<SignedSessionGrantClaims> {
    Jwt::<SignedSessionGrantClaims>::try_from(grant.grant_jwt.as_str())
        .ok()
        .map(|jwt| jwt.payload().clone())
}

fn grant_is_agent_delegated_to_controller(grant: &SessionGrant, controller_id: &str) -> bool {
    let Some(payload) = grant_payload(grant) else {
        return false;
    };
    if payload.proof_kind != Some(arkret_models_identity::SessionGrantProofKind::AgentKeyProof) {
        return false;
    }
    payload
        .scope_details
        .as_ref()
        .and_then(|details| details.get("controller_id"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == controller_id)
}

fn grant_is_owned_by_current_principal(grant: &SessionGrant, principal_did: &str) -> bool {
    grant.subject == principal_did || grant_is_agent_delegated_to_controller(grant, principal_did)
}

fn validate_lifecycle_proof_kind(proof_kind: &str) -> Result<(), ArkretRouteError> {
    match proof_kind {
        "did_bound_signature" | "paired_device_proof" | "agent_key_proof" => Ok(()),
        other => Err(lifecycle_proof_invalid(format!(
            "unsupported lifecycle proof_kind {other}"
        ))),
    }
}

fn validate_lifecycle_proof_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    if expires_at <= issued_at {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof expires_at must be after issued_at",
        ));
    }
    if expires_at - issued_at > Duration::seconds(SESSION_REVOKE_PROOF_MAX_WINDOW_SECS) {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof validity window exceeds 300 seconds",
        ));
    }
    if issued_at > now + Duration::seconds(30) {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof issued_at is in the future",
        ));
    }
    if expires_at <= now {
        return Err(lifecycle_proof_invalid("lifecycle proof has expired"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_cross_session_lifecycle_proof(
    http_client: &reqwest::Client,
    url_builder: &coauth_data::UrlBuilder,
    arkret_config: &coauth_config::ArkretConfig,
    key_store: &coauth_keystore::Keystore,
    repo: &mut coauth_data::BoxRepository,
    did_resolver: &dyn crate::services::did_resolver::DidResolverService,
    binding_store: &crate::services::did_binding::DurableVerifiedDidBindingStore,
    body: &SessionRevokeRequestBody,
    proof: &AccountLifecycleProof,
    current_grant: &SessionGrant,
    current_device_id: &DeviceId,
    service_id: &Did,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    validate_lifecycle_proof_kind(&proof.proof_kind)?;
    validate_lifecycle_proof_window(proof.issued_at, proof.expires_at, now)?;

    if proof.audience != current_grant.audience {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "session revoke lifecycle proof audience must match the current session grant audience",
        ));
    }

    let actor_id = Did::new(current_grant.subject.clone()).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            format!("current session grant subject is not a DID: {error}"),
        )
    })?;
    let expected_digest = AccountLifecycleProof::session_revoke_request_digest(
        &actor_id,
        service_id,
        current_device_id,
        body.target_grant_id.as_ref(),
        body.target_device_id.as_ref(),
        body.all_sessions.unwrap_or(false),
        None,
    )
    .map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session revoke request digest canonicalization failed: {error}"
        )))
    })?;
    if proof.request_canonical_digest != expected_digest {
        return Err(lifecycle_proof_invalid(
            "request_canonical_digest does not match the presented session revoke request",
        ));
    }

    let payload = proof.canonical_signing_bytes().map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session revoke lifecycle proof canonicalization failed: {error}"
        )))
    })?;

    // §4 row 7 — a cross-session revoke is a high-risk write, so it demands
    // `fresh_within(HIGH_RISK_MAX_AGE)` under the closed `Principal` purpose.
    // Degraded / fallback / unproven-controller evidence maps to
    // `Stale` / `Quarantined` and fails closed inside `authority_document`,
    // which replaces the previous `identity_fact_rejection` gate.
    let resolution = crate::services::did_binding::authority_document(
        http_client,
        url_builder,
        arkret_config,
        key_store,
        repo,
        did_resolver,
        binding_store,
        &current_grant.subject,
        arkret_identity::DidBindingPurpose::Principal,
        crate::services::did_binding::high_risk_freshness(),
        now,
    )
    .await
    .map_err(|error| {
        lifecycle_proof_invalid(format!(
            "no fresh accepted principal binding for the session subject: {error}"
        ))
    })?;
    if resolution.document.verification_method.is_empty() {
        return Err(lifecycle_proof_invalid(
            "DID document has no verificationMethod entries",
        ));
    }

    let verification_method = verify_detached_jws_with_sdk(
        &proof.signature,
        &payload,
        &resolution.document.verification_method,
    )
    .map_err(|error| lifecycle_proof_invalid(format!("lifecycle proof JWS invalid: {error}")))?;
    if let Some(expected_method) = proof
        .verification_method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && expected_method != verification_method.as_str()
    {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof verification_method does not match the detached JWS kid",
        ));
    }
    if verification_method_did(&verification_method) != current_grant.subject {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof verification_method principal does not match the current session grant subject",
        ));
    }

    Ok(())
}

pub struct RevokeCanonicalJson(Vec<u8>);

impl Scribe for RevokeCanonicalJson {
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

#[handler]
pub async fn revoke_session_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<RevokeCanonicalJson, ArkretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let binding_store = depot.verified_did_binding_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    let presented_grant_jwt = bearer_session_grant(req)?.to_owned();
    let body = parse_session_revoke_body(req).await?;
    let selector = revoke_selector(&body)?;
    let dpop_header = dpop_header_from_request(req)
        .ok_or_else(|| lifecycle_proof_required("session revoke requires holder DPoP proof"))?;
    let presented_claims = Jwt::<SignedSessionGrantClaims>::try_from(presented_grant_jwt.as_str())
        .map_err(|_| ArkretRouteError::Unauthorized("session grant is not parseable".to_owned()))?
        .payload()
        .clone();
    presented_claims.validate().map_err(|error| {
        ArkretRouteError::Unauthorized(format!("invalid session grant: {error}"))
    })?;

    let service_id = service_id_for(&arkret_config);

    let mut repo = depot.repo().await?;
    let current_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&presented_grant_jwt)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
        .ok_or_else(session_grant_not_found)?;
    if presented_claims.grant_id != current_grant.grant_id
        || presented_claims.issuer.as_str() != current_grant.issuer
        || presented_claims.subject.as_str() != current_grant.subject
    {
        repo.cancel().await.ok();
        return Err(lifecycle_proof_invalid(
            "presented session grant does not match the issuer ledger",
        ));
    }
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let htu = dpop_htu(&url_builder.http_base(), req);
    let dpop = DpopVerifier::verify_without_replay(
        &dpop_header,
        &htm,
        &htu,
        now,
        Some(&presented_grant_jwt),
    )
    .map_err(|error| lifecycle_proof_invalid(error.to_string()))?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, &presented_claims.cnf.jkt)
        .map_err(|error| lifecycle_proof_invalid(error.to_string()))?;

    let current_device_id = current_grant
        .device_id
        .as_ref()
        .map(|value| DeviceId::new(value.clone()))
        .transpose()
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::INVALID_PARAM,
                format!("current session grant device_id is invalid: {error}"),
            )
        })?;

    let proof_required = match &selector {
        RevokeSelector::Current => false,
        RevokeSelector::Grant(target_grant_id) => target_grant_id != &current_grant.grant_id,
        RevokeSelector::Device(_) | RevokeSelector::All => true,
    };
    if proof_required {
        let current_device_id = current_device_id.as_ref().ok_or_else(|| {
            lifecycle_proof_required(
                "cross-session revoke requires the current session grant to be device-bound",
            )
        })?;
        let proof = body.proof.as_ref().ok_or_else(|| {
            lifecycle_proof_required("cross-session revoke requires a fresh lifecycle proof")
        })?;
        verify_cross_session_lifecycle_proof(
            &http_client,
            &url_builder,
            &arkret_config,
            &key_store,
            &mut repo,
            &*did_resolver,
            binding_store.as_ref(),
            &body,
            proof,
            &current_grant,
            current_device_id,
            &service_id,
            now,
        )
        .await?;
    }

    let current_principal_did = current_grant.subject.clone();
    let target_grant_id = match &selector {
        RevokeSelector::Current => Some(current_grant.grant_id.clone()),
        RevokeSelector::Grant(target_grant_id) => {
            let target = repo
                .oauth_session_grant()
                .lookup_by_grant_id(target_grant_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .filter(|grant| grant_is_owned_by_current_principal(grant, &current_principal_did))
                .ok_or_else(session_grant_not_found)?;
            Some(target.grant_id)
        }
        RevokeSelector::Device(_) | RevokeSelector::All => None,
    };
    let operation_selector = match &selector {
        RevokeSelector::Current | RevokeSelector::Grant(_) => {
            coauth_data::SessionGrantRevokeTarget::Grant {
                grant_id: target_grant_id
                    .as_ref()
                    .expect("grant selector has an id")
                    .clone(),
            }
        }
        RevokeSelector::Device(target_device_id) => coauth_data::SessionGrantRevokeTarget::Device {
            subject: current_principal_did.to_string(),
            device_id: target_device_id.to_string(),
        },
        RevokeSelector::All => coauth_data::SessionGrantRevokeTarget::AllForSubject {
            subject: current_principal_did.to_string(),
        },
    };
    let mut redacted_body =
        serde_json::to_value(&body).map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if let Some(proof) = redacted_body
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
        "presented_grant_id": current_grant.grant_id,
        "holder_jkt": dpop.jkt,
        "selector": operation_selector,
        "request": redacted_body,
    }))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let canonical_intent_digest: [u8; 32] = sha2::Sha256::digest(&canonical_intent).into();
    let proof_identity = body
        .proof
        .as_ref()
        .map(|proof| proof.challenge.as_str())
        .unwrap_or(dpop.claims.jti.as_str());
    let request_identity = format!(
        "revoke:{}",
        hex::encode(sha2::Sha256::digest(proof_identity.as_bytes()))
    );
    let proof_expires_at = body.proof.as_ref().map_or(
        now + Duration::seconds(SESSION_REVOKE_PROOF_MAX_WINDOW_SECS),
        |proof| proof.expires_at,
    );
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            NewSessionGrantOperation {
                issuer: &current_grant.issuer,
                operation: coauth_data::SessionGrantOperationDescriptor::Revoke {
                    selector: operation_selector,
                },
                proof_kind: None,
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_grant_id: None,
                issuance_nonce: None,
                session_id: None,
                grant_not_before: None,
                grant_expires_at: None,
                signing_key_id: None,
                retained_until: proof_expires_at + Duration::days(7),
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
            let bytes = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "revoke replay has no canonical outcome",
                )
            })?;
            repo.cancel().await.ok();
            return Ok(RevokeCanonicalJson(bytes));
        }
        SessionGrantReserveOutcome::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "revoke proof identity conflicts with a different canonical intent",
            ));
        }
        SessionGrantReserveOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "revoke replay material is unavailable",
            ));
        }
        SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "revoke authorization checkpoint is incomplete",
            ));
        }
    };

    // Lifecycle checks happen only after reserve, so an exact retry of a
    // committed revoke reaches Replay instead of being hidden by the terminal
    // state created by its first attempt.
    if !current_grant.is_active(&clock) {
        repo.cancel().await.ok();
        if current_grant.expires_at <= now {
            return Err(ArkretRouteError::session_grant_replay_expired(
                current_grant.grant_id,
            ));
        }
        let state = match current_grant.lifecycle_state {
            coauth_data::SessionGrantLifecycleState::Revoked => {
                arkret_wire::SessionGrantReplayTerminalState::Revoked
            }
            coauth_data::SessionGrantLifecycleState::Superseded => {
                arkret_wire::SessionGrantReplayTerminalState::Superseded
            }
            coauth_data::SessionGrantLifecycleState::Active => unreachable!(),
        };
        return Err(ArkretRouteError::session_grant_replay_terminal(
            current_grant.grant_id,
            state,
        ));
    }
    let inserted = repo
        .dpop_replay()
        .consume_jti(crate::services::dpop::dpop_replay_record(
            &dpop.claims.jti,
            now,
        ))
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if !inserted {
        repo.cancel().await.ok();
        return Err(lifecycle_proof_invalid(
            "session revoke DPoP JTI was already consumed",
        ));
    }
    let authorization_ref = format!("revoke-proof:{request_identity}");
    let checkpoint = serde_json::json!({
        "kind": "session_revoke",
        "request_identity": request_identity,
        "dpop_jti_digest": crate::services::dpop::dpop_jti_digest(&dpop.claims.jti),
        "request_canonical_digest": body.proof.as_ref().map(|proof| &proof.request_canonical_digest),
    });
    let durable_selector = match &selector {
        RevokeSelector::Current | RevokeSelector::Grant(_) => SessionGrantRevokeSelector::Grant(
            target_grant_id.as_ref().expect("grant selector has an id"),
        ),
        RevokeSelector::Device(device_id) => SessionGrantRevokeSelector::Device {
            subject: &current_principal_did,
            device_id: device_id.as_str(),
        },
        RevokeSelector::All => SessionGrantRevokeSelector::AllForSubject {
            subject: &current_principal_did,
        },
    };
    let committed = repo
        .oauth_session_grant()
        .commit_revoke(
            &*clock,
            operation.id,
            SessionGrantProofAuthorization {
                authorization_ref: &authorization_ref,
                checkpoint: &checkpoint,
                proof_expires_at,
            },
            durable_selector,
        )
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let chaos_committed = matches!(&committed, SessionGrantRevokeOutcome::Revoked { .. });
    let response = match committed {
        SessionGrantRevokeOutcome::Revoked { operation, .. } => {
            operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "revoke commit has no repository canonical outcome",
                )
            })?
        }
        SessionGrantRevokeOutcome::Replay(operation) => {
            operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "revoke commit replay has no canonical outcome",
                )
            })?
        }
        SessionGrantRevokeOutcome::AlreadyTerminal { operation, .. } => {
            operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "terminal revoke commit has no repository canonical outcome",
                )
            })?
        }
        SessionGrantRevokeOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "revoke outcome is indeterminate",
            ));
        }
    };

    repo.save().await?;
    if chaos_committed {
        super::super::test_chaos::maybe_delay_post_commit(
            "session_grant_revoke_post_commit_pre_response",
            &request_identity,
        )
        .await;
    }
    Ok(RevokeCanonicalJson(response))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use coauth_config::{ArkretConfig, DeploymentProfileConfig, PrincipalMethodConfig};
    use coauth_iana::jose::{JsonWebKeyOperation, JsonWebKeyUse, JsonWebSignatureAlg};
    use coauth_jose::jwk::JsonWebKeyPublicParameters;
    use coauth_keystore::{JsonWebKeySet, Keystore, PrivateKey};
    use coauth_oauth_types::scope::Scope;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(0x4e17);
        let ed25519 = coauth_keystore::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("test-ed25519");
        Keystore::new(JsonWebKeySet::new(vec![ed25519]))
    }

    fn personal_did_web_config() -> ArkretConfig {
        ArkretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            principal_method: PrincipalMethodConfig::DidWeb,
            runtime_service_identity: coauth_config::RuntimeServiceIdentity::fixture(
                "did:web:auth.example",
            ),
            ..ArkretConfig::default()
        }
    }

    fn agent_session_grant(controller_id: &str) -> SessionGrant {
        let now = Utc::now();
        let mut session_rng = ChaChaRng::seed_from_u64(0x4e18);
        let session_key = PrivateKey::generate_ed25519(&mut session_rng);
        let session_public_key = serde_json::to_string(
            &coauth_keystore::JsonWebKey::new(JsonWebKeyPublicParameters::from(&session_key))
                .with_use(JsonWebKeyUse::Sig)
                .with_key_ops(vec![JsonWebKeyOperation::Verify])
                .with_alg(JsonWebSignatureAlg::Ed25519)
                .with_kid("agent-revoke-session-key"),
        )
        .unwrap();
        let issuance_seed = SessionGrantIssuanceSeed::new(
            arkret_models_identity::SessionGrantIssuanceNonce::from_bytes([0x51; 32]).to_string(),
            "agent-revoke-test-session",
            now,
            now + Duration::minutes(15),
            "test-ed25519",
        )
        .unwrap();
        let material = mint_agent_session_grant(
            &issuance_seed,
            &personal_did_web_config(),
            &test_keystore(),
            "did:web:agent.example",
            &DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000006").unwrap(),
            "did:web:soland.example".to_owned(),
            vec!["ak.self.events.stream.subscribe".to_owned()],
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            session_public_key,
            serde_json::json!({
                "controller_id": controller_id,
                "resources": {
                    "realm_refs": ["ak:realm:team"],
                },
            }),
            arkret_identifiers::EventId::new(
                "ak:event:AQilOsNi6WF7kBMfOVLw4LjFp75pXSq5WJ0WMmJw3kgK",
            )
            .unwrap(),
            arkret_wire::DidUrl::new("did:web:agent.example#runtime-key").unwrap(),
            now,
            now + Duration::minutes(15),
        )
        .expect("agent grant should mint");

        SessionGrant {
            id: ulid::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
            grant_id: material.grant_id,
            browser_session_id: None,
            issuer: material.issuer,
            subject: material.subject,
            device_id: material.device_id,
            applet_id: None,
            effective_scope: None,
            registration_epoch: None,
            service_id: None,
            capability_grant_refs: Vec::new(),
            audience: material.audience,
            scope: Scope::from_iter(["ak.self.events.stream.subscribe".parse().unwrap()]),
            grant_jwt: material.grant_jwt,
            session_id: material.session_id,
            issuance_nonce: material.issuance_nonce,
            issuance_preimage: material.issuance_preimage,
            issuance_digest: material.issuance_digest,
            signing_key_id: material.signing_key_id,
            session_public_key: material.session_public_key,
            credential_class: material.credential_class,
            created_at: now,
            expires_at: now + Duration::minutes(15),
            lifecycle_state: coauth_data::SessionGrantLifecycleState::Active,
            revoked_at: None,
            superseded_at: None,
            successor_grant_id: None,
            issuance_operation_id: ulid::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap(),
        }
    }

    #[test]
    fn agent_key_proof_grant_is_owned_by_accountable_controller_only() {
        let grant = agent_session_grant("did:web:controller.example");

        assert_eq!(
            grant.device_id.as_deref(),
            Some("ak:device:0196419b-0000-7000-8000-000000000006")
        );

        assert!(grant_is_agent_delegated_to_controller(
            &grant,
            "did:web:controller.example"
        ));
        assert!(grant_is_owned_by_current_principal(
            &grant,
            "did:web:controller.example"
        ));
        assert!(!grant_is_agent_delegated_to_controller(
            &grant,
            "did:web:other-controller.example"
        ));
        assert!(!grant_is_owned_by_current_principal(
            &grant,
            "did:web:other-controller.example"
        ));
    }

    #[test]
    fn malformed_or_non_agent_grant_is_not_controller_delegated() {
        let mut grant = agent_session_grant("did:web:controller.example");
        grant.grant_jwt = "header.payload.signature".to_owned();

        assert!(!grant_is_agent_delegated_to_controller(
            &grant,
            "did:web:controller.example"
        ));
    }
}
