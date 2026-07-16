//! AKP-0008 §4.5 runtime key pairing (`ak.gate.account.command.pair_agent_key`).
//!
//! `POST /_arkret/gate/account/agent-key-pair`. The agent runtime generated a
//! key pair locally and submits the public key plus a proof-of-possession. The
//! controller supplies the signed `ak.agent.key.authorize` event; coauth only
//! validates the request binding, persists the pending local authorization for
//! `agent_key_proof`, and commits the unchanged signed request to the
//! authoritative Principal Server before reporting success.

use arkret_signatures::proof::{PublicKeyMaterial, verify_eddsa_detached_jws_proof};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_config::ArkretConfig;
use coauth_data::accountability::AccountabilityGrantFanoutState;
use coauth_data::agent_key::NewAgentKeyAuthorization;
use coauth_data::audit::AdminOperation;
use coauth_data::queue::{AgentKeyPairCommitJob, QueueJobRepositoryExt as _};
use coauth_data::{BoxRepository, RepositoryAccess, UrlBuilder};
use coauth_keystore::Keystore;
use coauth_principal::PrincipalAgentKeyPairCommitRequest;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::Value;

use super::error_matrix::{AgentAuthRejection, enforce_verification_method_binding};
use super::proof::{ProofSignedFields, canonical_digest, verify_proof_signature};
use crate::AppError;
use crate::handlers::account::{DepotExt, make_clock, make_rng};
use crate::handlers::admin::audit_helper::record_service_admin_operation_signed;
use crate::handlers::arkret::{
    ArkretRouteError, VerificationMethod, is_allowed_session_grant_audience, service_id_for,
};
use crate::services::device_signing_directory::resolve_authorized_device_signing_key;
use crate::services::did_binding_proof::normalize_did_for_binding;
use crate::services::did_resolver::DidResolverService;

/// Durable retry queue used when the authoritative Principal Server cannot be
/// reached after the exact pairing request has been persisted locally.
const AGENT_KEY_PAIR_COMMIT_QUEUE: &str = "principal-agent-key-pair-commit";

#[derive(Debug)]
struct ValidatedRuntimePublicKey {
    public_key: Value,
    verification_public_key: String,
}

/// Proof-of-possession over the pairing request (AKP-0008 §4.5
/// `proof_of_possession`). The `signature` covers the canonical bytes of the
/// remaining fields and is NOT part of those bytes.
#[derive(Debug, Clone, Deserialize)]
struct ProofOfPossessionInput {
    challenge: String,
    audience: String,
    request_canonical_digest: String,
    expires_at: DateTime<Utc>,
    signature: String,
}

/// `POST /_arkret/gate/account/agent-key-pair`
/// (`ak.gate.account.command.pair_agent_key`).
///
/// Validates the runtime key pairing proof-of-possession and, on success,
/// records a pending local agent key authorization, commits the exact same
/// canonical operation to the authoritative Principal Server, and returns only
/// after that server durably accepts the supplied Event and activates the
/// Agent. Runtime replacement re-pairing is expressed atomically by the
/// controller-signed `authorize_event.payload.supersedes[]`; Coauth never
/// fabricates controller-authored revoke Events. Returns the SDK
/// [`AgentKeyPairOutcome`] carrying the accepted authorization Event ref.
#[handler]
#[tracing::instrument(name = "handler.account.agents.agent_key_pair", skip_all)]
pub async fn post_agent_key_pair(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<arkret_core::AgentKeyPairOutcome>, ArkretRouteError> {
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let did_resolver = depot.did_resolver_service()?;

    let body: arkret_core::AgentKeyPairRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("Idempotency-Key is required"))?;
    if idempotency_key != body.authorize_event.event_id.as_str() {
        return Err(
            AppError::bad_request("Idempotency-Key must equal authorize_event.event_id").into(),
        );
    }

    let agent_id = normalize_did_for_binding(body.agent_id.as_str())
        .map_err(|error| AppError::bad_request(format!("agent_id invalid: {error}")))?;
    ensure_body_pairing_request_id_present(&body.pairing_request_id)?;

    enforce_verification_method_binding(&body.verification_method, &agent_id)
        .map_err(AgentAuthRejection::into_app_error)?;

    let public_key_value = serde_json::to_value(&body.public_key)
        .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;
    let public_key =
        validate_runtime_public_key(&public_key_value, body.verification_method.as_str())?;

    let pop: ProofOfPossessionInput =
        serde_json::from_value(serde_json::to_value(&body.proof_of_possession).map_err(
            |error| AppError::bad_request(format!("proof_of_possession invalid: {error}")),
        )?)
        .map_err(|error| AppError::bad_request(format!("proof_of_possession invalid: {error}")))?;
    if pop.challenge != body.pairing_request_id.as_str() {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }

    // The SDK DTO closes runtime_attestation to the v1 `self_asserted` branch;
    // unknown kinds and fields already fail during request decoding.
    let runtime_attestation_value = body
        .runtime_attestation
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::bad_request(format!("runtime_attestation invalid: {error}")))?;

    // Final pairing idempotency is the controller-minted authorize Event id,
    // not the one-time pairing handle. Resolve an exact persisted retry before
    // current-handle/recovery gates: a successful first commit consumes the
    // handle and advances the Agent PCR frontier to stale, but the identical
    // request must still return the original outcome after a lost response.
    let authorized_event_id = body.authorize_event.event_id.to_string();
    let request_digest = canonical_digest(&body)?;
    let mut idempotency_repo = depot.repo().await?;
    let existing_authorization = idempotency_repo
        .agent_key_authorization()
        .lookup_by_event_id(&authorized_event_id)
        .await?;
    if let Some(existing) = existing_authorization {
        let same_request = existing.agent_id == agent_id
            && existing.verification_method == body.verification_method.as_str()
            && existing.public_key == public_key.public_key
            && existing.pairing_request_id == body.pairing_request_id.as_str()
            && existing.request_canonical_digest == pop.request_canonical_digest
            && existing.authorized_event_id == authorized_event_id
            && existing.raw_payload_digest == request_digest;
        if !same_request {
            idempotency_repo.cancel().await?;
            return Err(AppError::conflict(
                "authorize Event id is already bound to a different Agent authorization",
            )
            .into());
        }
        let stored_body: arkret_core::AgentKeyPairRequestBody =
            serde_json::from_value(existing.soland_fanout_payload.clone()).map_err(|error| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("stored Agent key-pair request is invalid: {error}"),
                )
            })?;
        idempotency_repo.cancel().await?;
        let authorized_event_ref = arkret_core::EventId::new(existing.authorized_event_id.clone())
            .map_err(|error| AppError::internal_box(Box::new(error)))?;
        if existing.soland_fanout_state == AccountabilityGrantFanoutState::Delivered {
            return Ok(Json(arkret_core::AgentKeyPairOutcome {
                ok: true,
                authorized_event_ref,
            }));
        }
        let (_, authoritative_server) = super::session_proof::fetch_authoritative_agent_view(
            &http_client,
            &arkret_config,
            &agent_id,
        )
        .await
        .map_err(AgentAuthRejection::into_app_error)?;
        commit_and_mark_agent_key_authorization(
            depot,
            &existing.authorized_event_id,
            &existing.soland_fanout_idempotency_key,
            &existing.raw_payload_digest,
            &authoritative_server.name,
            stored_body,
        )
        .await?;
        return Ok(Json(arkret_core::AgentKeyPairOutcome {
            ok: true,
            authorized_event_ref,
        }));
    }
    idempotency_repo.cancel().await?;

    let clock = make_clock();
    let now = clock.now();

    let (authoritative_view, authoritative_server) = super::enforce_authoritative_pairing_handle(
        &http_client,
        &arkret_config,
        &agent_id,
        &body.pairing_request_id,
        now,
    )
    .await
    .map_err(AgentAuthRejection::into_app_error)?;

    // Expiry: a stale pairing PoP is rejected as `pairing_request_expired`.
    if pop.expires_at <= now {
        return Err(AgentAuthRejection::PairingRequestExpired
            .into_app_error()
            .into());
    }

    // Audience MUST be this service (the coauth issuer audience or a configured
    // principal-server audience).
    if !is_allowed_session_grant_audience(
        &url_builder,
        &arkret_config,
        crate::services::resolved_principal_audiences::shared(),
        &pop.audience,
    ) {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }

    // The PoP MUST bind the request canonical digest (AKP-0008 §4.5). It is an
    // opaque `sha256:<hex>` the client computed over the pairing request body;
    // we re-bind it into the signed-fields so the signature covers it.
    if !pop.request_canonical_digest.starts_with("sha256:") {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }
    let agent_did = arkret_core::Did::new(agent_id.clone())
        .map_err(|error| AppError::bad_request(format!("agent_id invalid: {error}")))?;
    let expected_pop_digest = arkret_core::agent_key_pair_proof_request_binding_digest(
        &body.pairing_request_id,
        &agent_did,
        &body.verification_method,
        &public_key.public_key,
        runtime_attestation_value.as_ref(),
    )
    .map_err(|error| {
        AppError::bad_request(format!(
            "proof_of_possession request binding failed: {error}"
        ))
    })?;
    if pop.request_canonical_digest != expected_pop_digest.as_str() {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }

    let signed_fields = ProofSignedFields {
        audience: &pop.audience,
        challenge: &pop.challenge,
        nonce: None,
        expires_at: pop.expires_at,
        request_canonical_digest: &pop.request_canonical_digest,
        verification_method: &body.verification_method,
    };
    verify_proof_signature(
        &public_key.verification_public_key,
        &signed_fields,
        &pop.signature,
    )
    .map_err(AgentAuthRejection::into_app_error)?;

    let mut repo = depot.repo().await?;

    let runtime_public_key_digest =
        runtime_public_key_digest(&public_key.public_key, body.verification_method.as_str())?;
    let authorize_event_value = serde_json::to_value(&body.authorize_event)
        .map_err(|error| AppError::internal_box(Box::new(error)))?;
    let authoritative_key_state = authoritative_view
        .key_state
        .as_ref()
        .ok_or_else(|| AppError::forbidden("authoritative Agent key state is missing"))?;
    let authorize_event = validate_controller_authorize_event(
        &authorize_event_value,
        &agent_id,
        &body.verification_method,
        &runtime_public_key_digest,
        &body.pairing_request_id,
        &pop.audience,
        authoritative_key_state,
        now,
    )?;

    if let Err(error) = verify_authorize_event_controller_signature(
        &authorize_event_value,
        &agent_id,
        &authorize_event.controller_id,
        &pop.audience,
        &http_client,
        &url_builder,
        &arkret_config,
        &key_store,
        &mut repo,
        did_resolver.as_ref(),
    )
    .await
    {
        repo.cancel().await.ok();
        return Err(error.into());
    }

    // `pair_agent_key` validates the current Principal-Server pairing handle
    // above and the controller-signed authorization here. Accountability-grant
    // issuance is a precondition of the aggregate `provision` operation, not
    // an operation-specific precondition of runtime-key pairing. In
    // particular, Coauth's local grant table is not the protocol truth source
    // for the controller-authored `ak.identity.accountability_grant` already
    // accepted by Soland. Requiring a duplicate row here makes every normal
    // Soland-orchestrated pairing fail with `accountability_grant_missing`.
    // Agent session issuance still performs its required accountability gate.

    let mut rng = make_rng();
    let key_id = authorize_event.key_id.clone();
    let issued_at = authorize_event.issued_at;
    let expires_at = authorize_event.expires_at;

    // Runtime replacement re-pairing (key-management §3.6.1): accepting a new
    // runtime key supersedes every previously accepted active key of the
    // agent in the same accepted transaction (reason
    // `superseded_by_repairing`). Sessions already issued from a superseded
    // key fail closed through the existing revocation freshness check — the
    // session-grant branch re-reads `revoked_at` on every issuance. First
    // pairing (no prior active key) is a no-op here.
    let superseded_authorizations = repo
        .agent_key_authorization()
        .list_active_for_agent(&agent_id)
        .await?;
    let service_id = service_id_for(&arkret_config);
    let outcome_event_id = arkret_core::EventId::new(authorized_event_id.clone())
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    let raw_payload_digest = request_digest;
    let fanout_payload =
        serde_json::to_value(&body).map_err(|error| AppError::internal_box(Box::new(error)))?;
    let idempotency_key = authorized_event_id.clone();
    let agent_key_scope = serde_json::to_string(authorize_event.agent_key_scope)
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    repo.agent_key_authorization()
        .add(
            &mut *rng,
            &*clock,
            NewAgentKeyAuthorization {
                authorized_event_id: authorized_event_id.clone(),
                agent_id: agent_id.clone(),
                key_id: key_id.clone(),
                verification_method: body.verification_method.to_string(),
                public_key: public_key.public_key.clone(),
                accountable_principal_id: authorize_event.controller_id.clone(),
                agent_key_scope,
                audience: vec![pop.audience.clone()],
                issued_at,
                expires_at,
                pairing_request_id: body.pairing_request_id.to_string(),
                request_canonical_digest: pop.request_canonical_digest.clone(),
                raw_payload_digest: raw_payload_digest.clone(),
                soland_fanout_state: AccountabilityGrantFanoutState::Queued,
                soland_fanout_idempotency_key: idempotency_key.clone(),
                soland_fanout_payload: fanout_payload.clone(),
                soland_fanout_attempt: 0,
                soland_fanout_next_retry_at: Some(issued_at),
                soland_fanout_dead_letter_reason: None,
            },
        )
        .await?;

    let superseded_keys: Vec<_> = superseded_authorizations
        .iter()
        .map(|superseded| {
            serde_json::json!({
                "authorized_event_id": &superseded.authorized_event_id,
                "key_id": &superseded.key_id,
                "verification_method": &superseded.verification_method,
                "revoked_reason": arkret_core::error::ReasonCode::SUPERSEDED_BY_REPAIRING,
            })
        })
        .collect();
    let audit_details = serde_json::json!({
        "actor": { "kind": "service", "service_id": &service_id },
        "operation": "agent_key_authorize_issued",
        "authorized_event_id": &authorized_event_id,
        "agent_id": &agent_id,
        "controller_id": &authorize_event.controller_id,
        "verification_method": &body.verification_method,
        "audience": &pop.audience,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "superseded_active_keys": superseded_keys,
        "raw_payload_digest": &raw_payload_digest,
        "principal_commit": {
            "state": AccountabilityGrantFanoutState::Queued,
            "idempotency_key": &idempotency_key,
            "queue": AGENT_KEY_PAIR_COMMIT_QUEUE,
            "principal_server": &authoritative_server.name,
            "next_retry_at": issued_at,
        }
    });
    let key_store = depot.key_store()?;
    record_service_admin_operation_signed(
        &mut repo,
        &mut *rng,
        &*clock,
        &key_store,
        service_id.as_str(),
        arkret_config.audit_signature_fail_closed,
        AdminOperation::Other("agent_key_authorize_issued".to_owned()),
        "agent",
        None,
        audit_details,
    )
    .await?;

    repo.queue_job()
        .schedule_job(
            &mut *rng,
            &*clock,
            AgentKeyPairCommitJob::new(
                idempotency_key.clone(),
                authorized_event_id.clone(),
                raw_payload_digest.clone(),
                authoritative_server.name.clone(),
                body.clone(),
            ),
        )
        .await?;
    repo.save().await?;

    commit_and_mark_agent_key_authorization(
        depot,
        &authorized_event_id,
        &idempotency_key,
        &raw_payload_digest,
        &authoritative_server.name,
        body,
    )
    .await?;

    Ok(Json(arkret_core::AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref: outcome_event_id,
    }))
}

#[derive(Debug)]
struct ValidatedAuthorizeEvent<'a> {
    controller_id: String,
    key_id: String,
    agent_key_scope: &'a Value,
    issued_at: DateTime<Utc>,
    /// Optional authorization expiry (key-management §3.6.1): absent means
    /// the key authorization never expires by time and is governed solely by
    /// the revocation chain.
    expires_at: Option<DateTime<Utc>>,
}

fn validate_runtime_public_key(
    public_key: &Value,
    verification_method: &str,
) -> Result<ValidatedRuntimePublicKey, AppError> {
    let key: arkret_core::PublicKey = serde_json::from_value(public_key.clone())
        .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;
    if key.kty.as_str() != "OKP" {
        return Err(AppError::bad_request("public_key.kty must be OKP"));
    }
    if key.kid.as_str() != verification_method {
        return Err(AppError::bad_request(
            "public_key.kid must match verification_method",
        ));
    }
    if key.alg.as_str() != "Ed25519" && key.alg.as_str() != "EdDSA" {
        return Err(AppError::bad_request(
            "public_key.alg must be Ed25519 or EdDSA",
        ));
    }
    let raw = Base64UrlUnpadded::decode_vec(key.key.as_str())
        .map_err(|_| AppError::bad_request("public_key.key must be base64url"))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| AppError::bad_request("public_key.key must decode to 32 bytes"))?;
    Ok(ValidatedRuntimePublicKey {
        public_key: public_key.clone(),
        verification_public_key: arkret_core::ed25519_pubkey_to_did_key_multibase(&raw),
    })
}

fn runtime_public_key_digest(
    public_key: &Value,
    verification_method: &str,
) -> Result<String, AppError> {
    validate_runtime_public_key(public_key, verification_method)?;
    arkret_core::agent_runtime_public_key_digest(public_key)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|error| AppError::bad_request(format!("public_key is invalid: {error}")))
}

fn validate_controller_authorize_event<'a>(
    envelope: &'a Value,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    pairing_request_id: &str,
    audience: &str,
    authoritative_key_state: &arkret_core::KeyState,
    now: DateTime<Utc>,
) -> Result<ValidatedAuthorizeEvent<'a>, AppError> {
    if !envelope.is_object() {
        return Err(AppError::bad_request(
            "authorize_event must be a controller-signed event object",
        ));
    }
    if envelope.get("kind").and_then(Value::as_str) != Some("ak.agent.key.authorize") {
        return Err(AppError::bad_request(
            "authorize_event.kind must be ak.agent.key.authorize",
        ));
    }

    let event_id = envelope
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("authorize_event.event_id is required"))?;
    arkret_core::EventId::new(event_id.to_owned())
        .map_err(|err| AppError::bad_request(format!("authorize_event.event_id invalid: {err}")))?;
    if envelope.get("actor_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::forbidden(
            "authorize_event.actor_id must equal the managed Agent DID",
        ));
    }
    let controller_id = envelope
        .get("executed_by")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("authorize_event.executed_by is required"))?;
    arkret_core::Did::new(controller_id.to_owned()).map_err(|err| {
        AppError::bad_request(format!("authorize_event.executed_by invalid: {err}"))
    })?;
    if authoritative_key_state.agent_id.as_str() != agent_id
        || authoritative_key_state.controller_id.as_str() != controller_id
    {
        return Err(AppError::forbidden(
            "authorize_event controller does not match the authoritative Agent binding",
        ));
    }
    let expected_realm = authoritative_key_state.principal_control_realm_id.as_str();
    if envelope.get("realm_id").and_then(Value::as_str) != Some(expected_realm) {
        return Err(AppError::forbidden(
            "authorize_event.realm_id must equal the authoritative Agent PCR",
        ));
    }
    let expected_authorization_ref = authoritative_key_state
        .controller_authorization_ref
        .as_str();
    if envelope.get("authorization_ref").and_then(Value::as_str) != Some(expected_authorization_ref)
    {
        return Err(AppError::forbidden(
            "authorize_event.authorization_ref must match the authoritative controller delegation",
        ));
    }
    ensure_authorize_event_has_controller_signature(envelope, controller_id)?;

    let payload = envelope
        .get("payload")
        .ok_or_else(|| AppError::bad_request("authorize_event.payload is required"))?;
    if payload.get("agent_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::bad_request(
            "authorize_event.payload.agent_id must match the request",
        ));
    }
    if payload.get("verification_method").and_then(Value::as_str) != Some(verification_method) {
        return Err(AppError::bad_request(
            "authorize_event.payload.verification_method must match the request",
        ));
    }
    if payload
        .get("accountable_principal_id")
        .and_then(Value::as_str)
        != Some(controller_id)
    {
        return Err(AppError::forbidden(
            "authorize_event.payload.accountable_principal_id must match executed_by",
        ));
    }
    if payload.get("public_key_digest").and_then(Value::as_str) != Some(runtime_public_key_digest) {
        return Err(AppError::bad_request(
            "authorize_event.payload.public_key_digest must bind the runtime public_key",
        ));
    }
    let payload_audience = payload
        .get("audience")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::bad_request("authorize_event.payload.audience is required"))?;
    if !payload_audience
        .iter()
        .any(|value| value.as_str() == Some(audience))
    {
        return Err(AppError::bad_request(
            "authorize_event.payload.audience must include proof_of_possession.audience",
        ));
    }

    let key_id = payload
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("authorize_event.payload.key_id is required"))?;
    validate_authorize_event_supersedes(payload, authoritative_key_state)?;
    let agent_key_scope = payload.get("agent_key_scope").ok_or_else(|| {
        AppError::bad_request("authorize_event.payload.agent_key_scope is required")
    })?;
    ensure_authorize_event_scope_is_action_object(agent_key_scope)?;
    let issued_at = payload
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .ok_or_else(|| {
            AppError::bad_request("authorize_event.payload.issued_at must be rfc3339")
        })?;
    let expires_at = match payload.get("expires_at") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .ok_or_else(|| {
                    AppError::bad_request("authorize_event.payload.expires_at must be rfc3339")
                })?,
        ),
    };
    if let Some(expires_at) = expires_at {
        if expires_at <= now {
            return Err(AgentAuthRejection::PairingRequestExpired.into_app_error());
        }
        let authorization_lifetime = expires_at.signed_duration_since(issued_at);
        if authorization_lifetime <= chrono::Duration::zero() {
            return Err(AppError::bad_request(
                "authorize_event.payload.expires_at must be after issued_at",
            ));
        }
    }
    let approval = payload.get("approval_evidence").ok_or_else(|| {
        AppError::bad_request("authorize_event.payload.approval_evidence is required")
    })?;
    if approval.get("kind").and_then(Value::as_str) != Some("pairing_request") {
        return Err(AppError::bad_request(
            "authorize_event.payload.approval_evidence.kind must be pairing_request",
        ));
    }
    if approval.get("evidence_ref").is_some() {
        return Err(AppError::bad_request(
            "authorize_event.payload.approval_evidence.evidence_ref must be absent for pairing_request evidence",
        ));
    }
    if approval
        .get("request_canonical_digest")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(AppError::bad_request(
            "authorize_event.payload.approval_evidence.request_canonical_digest is required",
        ));
    }
    if approval.get("pairing_request_id").and_then(Value::as_str) != Some(pairing_request_id) {
        return Err(AppError::bad_request(
            "authorize_event.payload.approval_evidence.pairing_request_id must match the request",
        ));
    }
    if approval.get("approved_by").and_then(Value::as_str) != Some(controller_id) {
        return Err(AppError::forbidden(
            "authorize_event.payload.approval_evidence.approved_by must match executed_by",
        ));
    }

    Ok(ValidatedAuthorizeEvent {
        controller_id: controller_id.to_owned(),
        key_id: key_id.to_owned(),
        agent_key_scope,
        issued_at,
        expires_at,
    })
}

fn validate_authorize_event_supersedes(
    payload: &Value,
    authoritative_key_state: &arkret_core::KeyState,
) -> Result<(), AppError> {
    let active_authorizations = &authoritative_key_state.active_authorizations;
    let expected: std::collections::BTreeSet<(String, String)> = active_authorizations
        .iter()
        .map(|authorization| {
            (
                authorization.key_id.clone(),
                authorization.authorized_event_ref.to_string(),
            )
        })
        .collect();
    if expected.len() != active_authorizations.len() {
        return Err(AppError::forbidden(
            "authoritative Agent active authorization set contains duplicates",
        ));
    }
    let values = match payload.get("supersedes") {
        None => &[][..],
        Some(Value::Array(values)) => values.as_slice(),
        Some(_) => {
            return Err(AppError::bad_request(
                "authorize_event.payload.supersedes must be an array",
            ));
        }
    };
    let supplied: std::collections::BTreeSet<(String, String)> = values
        .iter()
        .map(|value| {
            let key_id = value
                .get("key_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AppError::bad_request("authorize_event.payload.supersedes[].key_id is required")
                })?;
            let event_ref = value
                .get("authorized_event_ref")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AppError::bad_request(
                        "authorize_event.payload.supersedes[].authorized_event_ref is required",
                    )
                })?;
            Ok((key_id.to_owned(), event_ref.to_owned()))
        })
        .collect::<Result<_, AppError>>()?;
    if supplied.len() != values.len() || supplied != expected {
        return Err(AppError::conflict(
            "authorize_event.payload.supersedes does not match the authoritative active key set",
        ));
    }
    Ok(())
}

fn ensure_body_pairing_request_id_present(pairing_request_id: &str) -> Result<(), AppError> {
    if pairing_request_id.trim().is_empty() {
        return Err(AppError::bad_request("pairing_request_id is required"));
    }
    Ok(())
}

fn ensure_authorize_event_has_controller_signature(
    envelope: &Value,
    controller_id: &str,
) -> Result<(), AppError> {
    let proofs = envelope
        .get("proofs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppError::bad_request("authorize_event must carry controller signature proofs")
        })?;
    if proofs.is_empty() {
        return Err(AppError::bad_request(
            "authorize_event must carry controller signature proofs",
        ));
    }
    let signed_by_controller = proofs.iter().any(|proof| {
        proof
            .get("verification_method")
            .and_then(Value::as_str)
            .is_some_and(|verification_method| {
                verification_method_controller(verification_method) == controller_id
            })
    });
    if !signed_by_controller {
        return Err(AppError::bad_request(
            "authorize_event proof verification_method must be controlled by actor_id",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_authorize_event_controller_signature(
    envelope: &Value,
    agent_id: &str,
    controller_id: &str,
    audience: &str,
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
) -> Result<(), AppError> {
    let (event, canonical_bytes) =
        authorize_event_signature_input(envelope, agent_id, controller_id)?;
    let mut has_controller_key_proof = false;
    let mut saw_controller_proof = false;

    for proof in &event.proofs {
        if verification_method_controller(&proof.verification_method) != controller_id {
            continue;
        }
        saw_controller_proof = true;
        let Some(device_id) = verification_method_device_id(&proof.verification_method) else {
            has_controller_key_proof = true;
            continue;
        };
        let resolved = match resolve_authorized_device_signing_key(
            http_client,
            arkret_config,
            crate::services::resolved_principal_audiences::shared(),
            audience,
            controller_id,
            &device_id,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(error) => {
                tracing::warn!(
                    %controller_id,
                    %device_id,
                    %error,
                    "authorize_event controller device key resolution failed"
                );
                continue;
            }
        };
        let public_key = PublicKeyMaterial::Ed25519Multibase {
            value: resolved.multibase,
        };
        if verify_eddsa_detached_jws_proof(proof, &canonical_bytes, &event.actor_id, &public_key)
            .is_ok()
        {
            return Ok(());
        }
    }

    if !saw_controller_proof {
        return Err(AppError::bad_request(
            "authorize_event proof verification_method must be controlled by actor_id",
        ));
    }
    if !has_controller_key_proof {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            arkret_config,
            key_store,
            repo,
            controller_id,
        )
        .await
        .map_err(|error| {
            AppError::unauthorized(format!(
                "proof_invalid: authorize_event controller DID could not be resolved: {error}"
            ))
        })?;
    if let Some(rejection) = resolution.identity_fact_rejection() {
        return Err(AppError::unauthorized(format!(
            "proof_invalid: authorize_event controller DID resolution is degraded: {}",
            rejection.as_str()
        )));
    }
    verify_authorize_event_controller_signature_with_methods(
        envelope,
        agent_id,
        controller_id,
        &resolution.document.verification_method,
    )
}

fn verify_authorize_event_controller_signature_with_methods(
    envelope: &Value,
    agent_id: &str,
    controller_id: &str,
    verification_methods: &[VerificationMethod],
) -> Result<(), AppError> {
    let (event, canonical_bytes) =
        authorize_event_signature_input(envelope, agent_id, controller_id)?;

    let mut saw_controller_proof = false;
    for proof in &event.proofs {
        if verification_method_controller(&proof.verification_method) != controller_id {
            continue;
        }
        saw_controller_proof = true;
        let Some(method) = verification_methods
            .iter()
            .find(|method| method.id == proof.verification_method)
        else {
            continue;
        };
        let public_key = method.public_key_material().map_err(|error| {
            AppError::bad_request(format!(
                "authorize_event controller verification method invalid: {error}"
            ))
        })?;
        if verify_eddsa_detached_jws_proof(proof, &canonical_bytes, &event.actor_id, &public_key)
            .is_ok()
        {
            return Ok(());
        }
    }

    if saw_controller_proof {
        Err(AgentAuthRejection::ProofInvalid.into_app_error())
    } else {
        Err(AppError::bad_request(
            "authorize_event proof verification_method must be controlled by actor_id",
        ))
    }
}

fn authorize_event_signature_input(
    envelope: &Value,
    agent_id: &str,
    controller_id: &str,
) -> Result<(arkret_core::Event, Vec<u8>), AppError> {
    let event: arkret_core::Event = serde_json::from_value(envelope.clone()).map_err(|error| {
        AppError::bad_request(format!(
            "authorize_event must be a complete signed Event envelope: {error}"
        ))
    })?;
    if event.actor_id.as_str() != agent_id {
        return Err(AppError::bad_request(
            "authorize_event.actor_id must match the managed Agent DID",
        ));
    }
    if event.executed_by.as_ref().map(arkret_core::Did::as_str) != Some(controller_id) {
        return Err(AppError::bad_request(
            "authorize_event.executed_by must match the resolved controller DID",
        ));
    }
    event.validate_proof_bindings().map_err(|error| {
        AppError::bad_request(format!("authorize_event proof binding invalid: {error}"))
    })?;
    let digest_payload = event.digest_payload().map_err(|error| {
        AppError::bad_request(format!(
            "authorize_event digest payload could not be built: {error}"
        ))
    })?;
    let canonical_bytes =
        arkret_core::canonical::canonical_json_bytes(&digest_payload).map_err(|error| {
            AppError::bad_request(format!(
                "authorize_event canonical payload could not be encoded: {error}"
            ))
        })?;
    Ok((event, canonical_bytes))
}

fn verification_method_controller(verification_method: &str) -> &str {
    verification_method
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

fn verification_method_device_id(verification_method: &str) -> Option<String> {
    let (_, fragment) = verification_method.split_once('#')?;
    let fragment = fragment.split('?').next().unwrap_or("").trim();
    arkret_core::DeviceId::new(fragment.to_owned())
        .ok()
        .map(|device_id| device_id.to_string())
}

fn ensure_authorize_event_scope_is_action_object(scope: &Value) -> Result<(), AppError> {
    let actions = scope
        .get("actions")
        .and_then(Value::as_array)
        .filter(|actions| !actions.is_empty())
        .ok_or_else(|| {
            AppError::bad_request("authorize_event.payload.agent_key_scope.actions is required")
        })?;
    if actions
        .iter()
        .any(|action| action.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(AppError::bad_request(
            "authorize_event.payload.agent_key_scope.actions must be non-empty strings",
        ));
    }
    Ok(())
}

async fn commit_and_mark_agent_key_authorization(
    depot: &Depot,
    authorized_event_id: &str,
    idempotency_key: &str,
    request_digest: &str,
    principal_server_name: &str,
    body: arkret_core::AgentKeyPairRequestBody,
) -> Result<(), AppError> {
    let superseded_event_refs = pairing_superseded_event_refs(&body)?;
    let http_client = depot.http_client()?;
    let arkret_config = depot.arkret_config()?;
    let request = PrincipalAgentKeyPairCommitRequest::new(
        idempotency_key.to_owned(),
        request_digest.to_owned(),
        principal_server_name.to_owned(),
        body,
    );
    crate::services::principal_facade::commit_agent_key_pair_to_principal_server(
        &http_client,
        &arkret_config,
        &request,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%authorized_event_id, %error, "Agent key-pair commit deferred");
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Agent key-pair request is durable but the authoritative Principal Server has not accepted it: {error}"
            ),
        )
    })?;

    let clock = make_clock();
    let mut repo = depot.repo().await?;
    let updated = repo
        .agent_key_authorization()
        .mark_fanout_delivered_and_revoke(
            &*clock,
            authorized_event_id,
            &superseded_event_refs,
            arkret_core::error::ReasonCode::SUPERSEDED_BY_REPAIRING,
        )
        .await?;
    if !updated {
        return Err(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Principal Server accepted the Agent key, but local reconciliation is pending",
        ));
    }
    repo.save().await?;
    Ok(())
}

fn pairing_superseded_event_refs(
    body: &arkret_core::AgentKeyPairRequestBody,
) -> Result<Vec<String>, AppError> {
    match body.authorize_event.payload.get("supersedes") {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .get("authorized_event_ref")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| {
                        AppError::bad_request(
                            "authorize_event.payload.supersedes[].authorized_event_ref is required",
                        )
                    })
            })
            .collect(),
        Some(_) => Err(AppError::bad_request(
            "authorize_event.payload.supersedes must be an array",
        )),
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use chrono::DateTime;
    use serde_json::json;

    use super::*;

    const AGENT: &str = "did:web:agent.example";
    const CONTROLLER: &str = "did:web:controller.example";
    const VM: &str = "did:web:agent.example#runtime-key-1";
    const AUDIENCE: &str = "did:web:soland.local";
    const PAIRING_REQUEST_ID: &str = "agent_pairing_request:01999999-0000-7000-8000-00000000feed";
    const PUBLIC_KEY_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn valid_public_key() -> Value {
        json!({
            "kty": "OKP",
            "kid": VM,
            "alg": "Ed25519",
            "key": Base64UrlUnpadded::encode_string(&[42u8; 32]),
        })
    }

    fn test_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-06T00:05:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn authoritative_key_state() -> arkret_core::KeyState {
        serde_json::from_value(json!({
            "agent_id": AGENT,
            "controller_id": CONTROLLER,
            "principal_control_realm_id": "ak:realm:01999999-0000-7000-8000-000000000010",
            "controller_authorization_ref": format!("{AGENT}#managed-controller"),
            "status": "pending_runtime_key",
            "pcr_recovery": {
                "status": "ready",
                "backup_id": "ak:backup:01999999-0000-7000-8000-000000000020",
                "series_id": "ak:backup_series:01999999-0000-7000-8000-000000000021",
                "series_seq": 1,
                "managed_frontier_ref": {
                    "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "seal_ref": "ak:seal:01999999-0000-7000-8000-000000000022",
                    "mls_epoch": 0
                }
            },
            "requested_scope": {
                "actions": [
                    "ak.self.events.stream.subscribe",
                    "ak.event.read"
                ],
                "resources": []
            },
            "requested_scope_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "active_authorizations": [],
        }))
        .unwrap()
    }

    fn valid_authorize_event(pairing_request_id: &str) -> Value {
        json!({
            "event_id": "ak:event:01999999-0000-7000-8000-000000000001",
            "kind": "ak.agent.key.authorize",
            "realm_id": "ak:realm:01999999-0000-7000-8000-000000000010",
            "actor_id": AGENT,
            "executed_by": CONTROLLER,
            "authorization_ref": format!("{AGENT}#managed-controller"),
            "actor_seq": 1,
            "created_at": "2026-07-06T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "agent_id": AGENT,
                "key_id": "runtime-key-1",
                "verification_method": VM,
                "public_key_digest": PUBLIC_KEY_DIGEST,
                "accountable_principal_id": CONTROLLER,
                "agent_key_scope": {
                    "actions": [
                        "ak.self.events.stream.subscribe",
                        "ak.event.read"
                    ],
                    "resources": []
                },
                "audience": [AUDIENCE],
                "issued_at": "2026-07-06T00:00:00Z",
                "expires_at": "2026-07-06T00:10:00Z",
                "approval_evidence": {
                    "kind": "pairing_request",
                    "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "pairing_request_id": pairing_request_id,
                    "approved_by": CONTROLLER
                }
            },
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": "did:web:controller.example#key-1",
                "jws": "header..signature"
            }]
        })
    }

    #[test]
    fn runtime_public_key_requires_spec_okp_shape() {
        validate_runtime_public_key(&valid_public_key(), VM).expect("spec public_key accepts");

        let legacy = json!({
            "key_type": "Ed25519",
            "public_key_multibase": "z6Mki6bBq1N3X3G3sT2xLwSPrm5Tg7EwjZwJ4oXb9qQ7z1Uu",
        });
        let err = validate_runtime_public_key(&legacy, VM)
            .expect_err("legacy multibase pairing key shape must reject");
        assert!(err.message().contains("public_key invalid"));
    }

    #[test]
    fn agent_key_pair_rejects_missing_authorize_event() {
        let err = validate_controller_authorize_event(
            &Value::Null,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("missing authorize_event must fail closed");

        assert!(err.message().contains("authorize_event"));
    }

    #[test]
    fn agent_key_pair_rejects_query_only_pairing_id() {
        let err = ensure_body_pairing_request_id_present("")
            .expect_err("body pairing_request_id is required");

        assert_eq!(err.message(), "pairing_request_id is required");
    }

    #[test]
    fn authorize_event_binds_body_pairing_request_id() {
        validate_controller_authorize_event(
            &valid_authorize_event(PAIRING_REQUEST_ID),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect("matching pairing_request_id accepts");

        let err = validate_controller_authorize_event(
            &valid_authorize_event("agent_pairing_request:wrong"),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("authorize_event pairing id mismatch must reject");

        assert!(err.message().contains("pairing_request_id"));
    }

    #[test]
    fn replacement_pairing_supersedes_same_key_authorization_dot() {
        let old_event = "ak:event:01999999-0000-7000-8000-000000000099";
        let mut key_state = authoritative_key_state();
        key_state.active_authorizations.push(
            serde_json::from_value(json!({
                "key_id": "runtime-key-1",
                "verification_method": VM,
                "authorized_event_ref": old_event,
            }))
            .unwrap(),
        );
        let payload = json!({
            "supersedes": [{
                "key_id": "runtime-key-1",
                "authorized_event_ref": old_event,
            }],
        });

        validate_authorize_event_supersedes(&payload, &key_state)
            .expect("same key_id replacement must observe-remove the old authorization dot");
    }

    #[test]
    fn replacement_pairing_rejects_omitted_same_key_authorization_dot() {
        let mut key_state = authoritative_key_state();
        key_state.active_authorizations.push(
            serde_json::from_value(json!({
                "key_id": "runtime-key-1",
                "verification_method": VM,
                "authorized_event_ref": "ak:event:01999999-0000-7000-8000-000000000099",
            }))
            .unwrap(),
        );

        let err = validate_authorize_event_supersedes(&json!({}), &key_state)
            .expect_err("omitting the old same-key authorization dot must fail closed");

        assert_eq!(err.status(), http::StatusCode::CONFLICT);
        assert!(err.message().contains("active key set"));
    }

    #[test]
    fn authorize_event_pairing_evidence_rejects_durable_ref() {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["approval_evidence"]["evidence_ref"] =
            json!("ak:event:01999999-0000-7000-8000-000000000099");

        let err = validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("pairing evidence must not masquerade as a durable object reference");

        assert!(err.message().contains("ref must be absent"));
    }

    #[test]
    fn authorize_event_accepts_absent_expires_at_as_non_expiring() {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]
            .as_object_mut()
            .unwrap()
            .remove("expires_at");

        let validated = validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect("absent expires_at means a non-expiring durable key authorization");

        assert!(validated.expires_at.is_none());
    }

    #[test]
    fn authorize_event_rejects_malformed_expires_at() {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["expires_at"] = json!("not-a-timestamp");

        let err = validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("present but malformed expires_at must fail closed");

        assert!(err.message().contains("expires_at must be rfc3339"));
    }

    #[test]
    fn authorize_event_accepts_lifetime_longer_than_session_ttl() {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["expires_at"] = json!("2026-08-05T00:00:00Z");

        validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect("durable key authorization must outlive individual session grants");
    }

    #[test]
    fn authorize_event_rejects_non_positive_authorization_lifetime() {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["issued_at"] = json!("2026-07-06T00:06:00Z");
        event["payload"]["expires_at"] = json!("2026-07-06T00:06:00Z");

        let err = validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("key authorization must end after it is issued");

        assert!(err.message().contains("must be after issued_at"));
    }

    #[test]
    fn authorize_event_rejects_fake_controller_jws() {
        let event = full_fake_signed_authorize_event();
        let method = controller_verification_method();

        let err = verify_authorize_event_controller_signature_with_methods(
            &event,
            AGENT,
            CONTROLLER,
            std::slice::from_ref(&method),
        )
        .expect_err("fake detached JWS must fail closed");

        assert_eq!(err.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn controller_device_verification_method_uses_device_directory_identity() {
        let device_id = "ak:device:01999999-0000-7000-8000-000000000042";
        let verification_method = format!("{CONTROLLER}#{device_id}");

        assert_eq!(
            verification_method_device_id(&verification_method).as_deref(),
            Some(device_id)
        );
        assert!(verification_method_device_id(&format!("{CONTROLLER}#key-1")).is_none());
    }

    #[test]
    fn authorize_event_accepts_controller_device_multibase_signature() {
        let device_id = "ak:device:01999999-0000-7000-8000-000000000042";
        let verification_method = format!("{CONTROLLER}#{device_id}");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let multibase = arkret_core::ed25519_pubkey_to_did_key_multibase(
            &signing_key.verifying_key().to_bytes(),
        );
        let mut unsigned_event = valid_authorize_event(PAIRING_REQUEST_ID);
        unsigned_event["proofs"] = json!([]);
        let mut event: arkret_core::Event = serde_json::from_value(unsigned_event).unwrap();
        let canonical_bytes =
            arkret_core::canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let mut proof = arkret_core::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.clone(),
            event_digest: arkret_core::Hash::new(arkret_core::canonical::sha256_digest(
                &canonical_bytes,
            ))
            .unwrap(),
            created_at: "2026-07-06T00:01:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: String::new(),
        };
        let binding_bytes = proof.canonical_binding_bytes(&event.actor_id).unwrap();
        proof.jws = arkret_signatures::proof::sign_eddsa_detached_jws(&signing_key, &binding_bytes)
            .unwrap();
        event.proofs.push(proof);
        let method = VerificationMethod {
            id: verification_method,
            kind: "Multikey".to_owned(),
            controller: CONTROLLER.to_owned(),
            public_key_jwk: None,
            public_key_multibase: Some(multibase),
        };

        verify_authorize_event_controller_signature_with_methods(
            &serde_json::to_value(event).unwrap(),
            AGENT,
            CONTROLLER,
            &[method],
        )
        .expect("authorized controller device signature accepts");
    }

    fn full_fake_signed_authorize_event() -> Value {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["proofs"] = json!([{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:controller.example#key-1",
            "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": "2026-07-06T00:01:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
        }]);
        let parsed: arkret_core::Event = serde_json::from_value(event.clone()).unwrap();
        event["proofs"][0]["event_digest"] = json!(parsed.event_digest().unwrap());
        event
    }

    fn controller_verification_method() -> VerificationMethod {
        let x = Base64UrlUnpadded::encode_string(&[7u8; 32]);
        VerificationMethod {
            id: "did:web:controller.example#key-1".to_owned(),
            kind: "JsonWebKey2020".to_owned(),
            controller: CONTROLLER.to_owned(),
            public_key_jwk: Some(
                serde_json::from_value(json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                }))
                .unwrap(),
            ),
            public_key_multibase: None,
        }
    }
}
