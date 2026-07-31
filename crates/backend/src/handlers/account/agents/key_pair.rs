//! AKP-0008 §4.5 runtime key pairing (`ak.gate.account.command.pair_agent_key`).
//!
//! `POST /_arkret/gate/account/agent-key-pair`. The agent runtime generated a
//! key pair locally and submits the public key plus a proof-of-possession. The
//! controller supplies the signed `ak.agent.key.authorize` event; coauth only
//! validates the request binding, persists the pending local authorization for
//! `agent_key_proof`, and commits the unchanged signed request to the
//! authoritative Principal Server before reporting success.

use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
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
    #[serde(deserialize_with = "arkret_canonical::deserialize_canonical_timestamp")]
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
/// controller-signed `authorize_event.event.payload.supersedes[]`; Coauth never
/// fabricates controller-authored revoke Events. Returns the SDK
/// [`AgentKeyPairOutcome`] carrying the accepted authorization Event ref.
#[handler]
#[tracing::instrument(name = "handler.account.agents.agent_key_pair", skip_all)]
pub async fn post_agent_key_pair(
    req: &mut Request,
    depot: &Depot,
) -> Result<
    Json<arkret_models_collaboration::agent_operations::AgentKeyPairOutcome>,
    ArkretRouteError,
> {
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let did_resolver = depot.did_resolver_service()?;
    let binding_store = depot.verified_did_binding_store()?;

    let body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("Idempotency-Key is required"))?;
    if idempotency_key != body.authorize_event.event.event_id.as_str() {
        return Err(AppError::bad_request(
            "Idempotency-Key must equal authorize_event.event.event_id",
        )
        .into());
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
    let authorized_event_id = body.authorize_event.event.event_id.to_string();
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
        let stored_body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody =
            serde_json::from_value(existing.soland_fanout_payload.clone()).map_err(|error| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("stored Agent key-pair request is invalid: {error}"),
                )
            })?;
        idempotency_repo.cancel().await?;
        let authorized_event_ref =
            arkret_identifiers::EventId::new(existing.authorized_event_id.clone())
                .map_err(|error| AppError::internal_box(Box::new(error)))?;
        if existing.soland_fanout_state == AccountabilityGrantFanoutState::Delivered {
            return Ok(Json(
                arkret_models_collaboration::agent_operations::AgentKeyPairOutcome {
                    ok: true,
                    authorized_event_ref,
                    signing_key_binding: stored_body.signing_key_binding,
                },
            ));
        }
        let signing_key_binding = stored_body.signing_key_binding.clone();
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
        return Ok(Json(
            arkret_models_collaboration::agent_operations::AgentKeyPairOutcome {
                ok: true,
                authorized_event_ref,
                signing_key_binding,
            },
        ));
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
    let agent_did = arkret_identifiers::Did::new(agent_id.clone())
        .map_err(|error| AppError::bad_request(format!("agent_id invalid: {error}")))?;
    let expected_pop_digest =
        arkret_signatures::agent::agent_key_pair_proof_request_binding_digest(
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
    let authoritative_key_state = authoritative_view
        .key_state
        .as_ref()
        .ok_or_else(|| AppError::forbidden("authoritative Agent key state is missing"))?;
    let authorize_event = validate_controller_authorize_event(
        &body.authorize_event.event,
        &agent_id,
        &body.verification_method,
        &runtime_public_key_digest,
        &body.signing_key_binding,
        &body.pairing_request_id,
        &pop.audience,
        authoritative_key_state,
        now,
    )?;

    if let Err(error) = verify_authorize_event_controller_signature(
        &body.authorize_event.event,
        &agent_id,
        &authorize_event.controller_id,
        &pop.audience,
        &http_client,
        &url_builder,
        &arkret_config,
        &key_store,
        &mut repo,
        did_resolver.as_ref(),
        binding_store.as_ref(),
        now,
    )
    .await
    {
        repo.cancel().await.ok();
        return Err(error.into());
    }
    if let Err(error) = verify_pairing_signing_key_binding(
        &body.signing_key_binding,
        &authorize_event.controller_id,
        &body.agent_id,
        authorize_event.payload.key_id.as_str(),
        &body.verification_method,
        &body.authorize_event.event.event_id,
        &authorize_event.payload.signing_key_binding_digest,
        &pop.audience,
        &http_client,
        &url_builder,
        &arkret_config,
        &key_store,
        &mut repo,
        did_resolver.as_ref(),
        binding_store.as_ref(),
        now,
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
    let key_id = authorize_event.payload.key_id.to_string();
    let issued_at = authorize_event.payload.issued_at;
    let expires_at = authorize_event.payload.expires_at;

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
    let outcome_event_id = arkret_identifiers::EventId::new(authorized_event_id.clone())
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    let raw_payload_digest = request_digest;
    let fanout_payload =
        serde_json::to_value(&body).map_err(|error| AppError::internal_box(Box::new(error)))?;
    let idempotency_key = authorized_event_id.clone();
    let agent_key_scope = serde_json::to_string(&authorize_event.payload.agent_key_scope)
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
                "revoked_reason": arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING,
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
        // Two orthogonal axes (key-management.md §3.6.1): the controller
        // lifecycle intent is preserved by pairing completion (an active agent
        // needs no resume), while the derived runtime_state advances to ready.
        "agent_lifecycle": authoritative_view.status.as_wire_str(),
        "runtime_state_before": if superseded_authorizations.is_empty() {
            arkret_models_collaboration::agent_operations::AgentRuntimeState::PendingRuntimeKey
        } else {
            arkret_models_collaboration::agent_operations::AgentRuntimeState::Replacing
        }
        .as_wire_str(),
        "runtime_state_after":
            arkret_models_collaboration::agent_operations::AgentRuntimeState::Ready.as_wire_str(),
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

    let signing_key_binding = body.signing_key_binding.clone();
    commit_and_mark_agent_key_authorization(
        depot,
        &authorized_event_id,
        &idempotency_key,
        &raw_payload_digest,
        &authoritative_server.name,
        body,
    )
    .await?;

    Ok(Json(
        arkret_models_collaboration::agent_operations::AgentKeyPairOutcome {
            ok: true,
            authorized_event_ref: outcome_event_id,
            signing_key_binding,
        },
    ))
}

/// The controller-signed authorize Event after every business-field check.
///
/// `payload` is the SDK's closed `ak.agent.key.authorize` type, so the
/// downstream persistence and audit code reads typed fields — a payload
/// rename in the spec becomes a compile error here rather than a check that
/// silently stops matching.
#[derive(Debug)]
struct ValidatedAuthorizeEvent {
    controller_id: String,
    payload: AgentKeyAuthorizePayload,
}

fn validate_runtime_public_key(
    public_key: &Value,
    verification_method: &str,
) -> Result<ValidatedRuntimePublicKey, AppError> {
    let key: arkret_models_collaboration::governance::agent_artifacts::PublicKey =
        serde_json::from_value(public_key.clone())
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
        verification_public_key: arkret_canonical::ed25519_pubkey_to_did_key_multibase(&raw),
    })
}

fn runtime_public_key_digest(
    public_key: &Value,
    verification_method: &str,
) -> Result<String, AppError> {
    validate_runtime_public_key(public_key, verification_method)?;
    arkret_signatures::agent::agent_runtime_public_key_digest(public_key)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|error| AppError::bad_request(format!("public_key is invalid: {error}")))
}

fn validate_controller_authorize_event(
    event: &arkret_wire::Event,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    signing_key_binding: &arkret_models_collaboration::agent_signer_evidence::AgentSigningKeyBinding,
    pairing_request_id: &str,
    audience: &str,
    authoritative_key_state: &arkret_models_collaboration::agent_operations::KeyState,
    now: DateTime<Utc>,
) -> Result<ValidatedAuthorizeEvent, AppError> {
    // Closes the payload once, here. Every business check below reads a typed
    // field; unknown payload fields are already rejected by the SDK type.
    let payload = AgentKeyAuthorizePayload::try_from(event)
        .map_err(|error| AppError::bad_request(format!("authorize_event.event {error}")))?;

    if event.actor_id.as_str() != agent_id {
        return Err(AppError::forbidden(
            "authorize_event.event.actor_id must equal the managed Agent DID",
        ));
    }
    let controller_id = event
        .executed_by
        .as_ref()
        .map(arkret_identifiers::Did::as_str)
        .ok_or_else(|| AppError::bad_request("authorize_event.event.executed_by is required"))?;
    if authoritative_key_state.agent_id.as_str() != agent_id
        || authoritative_key_state.controller_id.as_str() != controller_id
    {
        return Err(AppError::forbidden(
            "authorize_event controller does not match the authoritative Agent binding",
        ));
    }
    if event.realm_id.as_str() != authoritative_key_state.principal_control_realm_id.as_str() {
        return Err(AppError::forbidden(
            "authorize_event.event.realm_id must equal the authoritative Agent PCR",
        ));
    }
    if event.authorization_ref.as_deref()
        != Some(
            authoritative_key_state
                .controller_authorization_ref
                .as_str(),
        )
    {
        return Err(AppError::forbidden(
            "authorize_event.event.authorization_ref must match the authoritative controller delegation",
        ));
    }
    ensure_authorize_event_has_controller_signature(event, controller_id)?;

    if payload.agent_id.as_str() != agent_id {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.agent_id must match the request",
        ));
    }
    if payload.verification_method.as_str() != verification_method {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.verification_method must match the request",
        ));
    }
    if payload.accountable_principal_id.as_str() != controller_id {
        return Err(AppError::forbidden(
            "authorize_event.event.payload.accountable_principal_id must match executed_by",
        ));
    }
    if payload.public_key_digest.as_str() != runtime_public_key_digest {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.public_key_digest must bind the runtime public_key",
        ));
    }
    let actual_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(signing_key_binding)
            .map_err(|reason| AppError::bad_request(reason.as_str()))?;
    if payload.signing_key_binding_digest != actual_binding_digest {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.signing_key_binding_digest must bind signing_key_binding",
        ));
    }
    if signing_key_binding.agent_id.as_str() != agent_id
        || signing_key_binding.verification_method.as_str() != verification_method
        || signing_key_binding.agent_key_authorize_event_id.as_str() != event.event_id.as_str()
        || signing_key_binding.public_key_digest.as_str() != runtime_public_key_digest
        || signing_key_binding.controller_id.as_str() != controller_id
    {
        return Err(AppError::bad_request(
            "signing_key_binding does not match the pairing authorization",
        ));
    }
    if !payload
        .audience
        .iter()
        .any(|candidate| candidate == audience)
    {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.audience must include proof_of_possession.audience",
        ));
    }
    if signing_key_binding.agent_key_id.as_str() != payload.key_id.as_str() {
        return Err(AppError::bad_request(
            "signing_key_binding.agent_key_id must match authorize_event.event.payload.key_id",
        ));
    }
    validate_authorize_event_supersedes(&payload, authoritative_key_state)?;
    if payload.agent_key_scope.actions.is_empty()
        || payload
            .agent_key_scope
            .actions
            .iter()
            .any(|action| action.trim().is_empty())
    {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.agent_key_scope.actions must be non-empty strings",
        ));
    }
    if let Some(expires_at) = payload.expires_at {
        if expires_at <= now {
            return Err(AgentAuthRejection::PairingRequestExpired.into_app_error());
        }
        if expires_at <= payload.issued_at {
            return Err(AppError::bad_request(
                "authorize_event.event.payload.expires_at must be after issued_at",
            ));
        }
    }
    if signing_key_binding.issued_at != payload.issued_at
        || signing_key_binding.expires_at != payload.expires_at
    {
        return Err(AppError::bad_request(
            "signing_key_binding validity must match the authorize Event",
        ));
    }
    let approval = &payload.approval_evidence;
    if approval.kind
        != arkret_models_collaboration::events_payloads::agent::AgentKeyApprovalEvidenceKind::PairingRequest
    {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.approval_evidence.kind must be pairing_request",
        ));
    }
    if approval.evidence_ref.is_some() {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.approval_evidence.evidence_ref must be absent for pairing_request evidence",
        ));
    }
    if approval.request_canonical_digest.is_none() {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.approval_evidence.request_canonical_digest is required",
        ));
    }
    if approval
        .pairing_request_id
        .as_ref()
        .map(arkret_wire::OpaqueLocalId::as_str)
        != Some(pairing_request_id)
    {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.approval_evidence.pairing_request_id must match the request",
        ));
    }
    if approval
        .approved_by
        .as_ref()
        .map(arkret_identifiers::Did::as_str)
        != Some(controller_id)
    {
        return Err(AppError::forbidden(
            "authorize_event.event.payload.approval_evidence.approved_by must match executed_by",
        ));
    }

    Ok(ValidatedAuthorizeEvent {
        controller_id: controller_id.to_owned(),
        payload,
    })
}

fn validate_authorize_event_supersedes(
    payload: &AgentKeyAuthorizePayload,
    authoritative_key_state: &arkret_models_collaboration::agent_operations::KeyState,
) -> Result<(), AppError> {
    let active_authorizations = &authoritative_key_state.active_authorizations;
    let expected: std::collections::BTreeSet<(String, String)> = active_authorizations
        .iter()
        .map(|authorization| {
            (
                authorization.key_id.to_string(),
                authorization.authorized_event_ref.to_string(),
            )
        })
        .collect();
    if expected.len() != active_authorizations.len() {
        return Err(AppError::forbidden(
            "authoritative Agent active authorization set contains duplicates",
        ));
    }
    let supplied: std::collections::BTreeSet<(String, String)> = payload
        .supersedes
        .iter()
        .map(|supersession| {
            (
                supersession.key_id.to_string(),
                supersession.authorized_event_ref.to_string(),
            )
        })
        .collect();
    if supplied.len() != payload.supersedes.len() || supplied != expected {
        return Err(AppError::conflict(
            "authorize_event.event.payload.supersedes does not match the authoritative active key set",
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
    event: &arkret_wire::Event,
    controller_id: &str,
) -> Result<(), AppError> {
    if event.proofs.is_empty() {
        return Err(AppError::bad_request(
            "authorize_event must carry controller signature proofs",
        ));
    }
    let signed_by_controller = event
        .proofs
        .iter()
        .any(|proof| verification_method_controller(&proof.verification_method) == controller_id);
    if !signed_by_controller {
        return Err(AppError::bad_request(
            "authorize_event proof verification_method must be controlled by actor_id",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_authorize_event_controller_signature(
    event: &arkret_wire::Event,
    agent_id: &str,
    controller_id: &str,
    audience: &str,
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    binding_store: &crate::services::did_binding::DurableVerifiedDidBindingStore,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let canonical_bytes = authorize_event_signature_input(event, agent_id, controller_id)?;
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

    // §4 row 3 — a new agent signer epoch / verification method is an
    // authority trigger, so this resolves under the closed `Controller`
    // purpose. Degraded / fallback / unproven-controller evidence lands as
    // `Stale` / `Quarantined` and fails closed inside `authority_document`,
    // which subsumes the previous `identity_fact_rejection` gate.
    let binding = crate::services::did_binding::authority_document(
        http_client,
        url_builder,
        arkret_config,
        key_store,
        repo,
        did_resolver,
        binding_store,
        controller_id,
        arkret_identity::DidBindingPurpose::Controller,
        crate::services::did_binding::CONTROLLER_MAX_AGE,
        now,
    )
    .await
    .map_err(|error| {
        AppError::unauthorized(format!(
            "proof_invalid: authorize_event controller DID has no fresh accepted binding: {error}"
        ))
    })?;
    let resolution = binding;
    verify_authorize_event_controller_signature_with_methods(
        event,
        agent_id,
        controller_id,
        &resolution.document.verification_method,
    )
}

fn verify_authorize_event_controller_signature_with_methods(
    event: &arkret_wire::Event,
    agent_id: &str,
    controller_id: &str,
    verification_methods: &[VerificationMethod],
) -> Result<(), AppError> {
    let canonical_bytes = authorize_event_signature_input(event, agent_id, controller_id)?;

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

#[allow(clippy::too_many_arguments)]
async fn verify_pairing_signing_key_binding(
    binding: &arkret_models_collaboration::agent_signer_evidence::AgentSigningKeyBinding,
    expected_controller_id: &str,
    agent_id: &arkret_identifiers::Did,
    agent_key_id: &str,
    verification_method: &arkret_wire::DidUrl,
    authorize_event_id: &arkret_identifiers::EventId,
    expected_binding_digest: &arkret_identifiers::Hash,
    audience: &str,
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    binding_store: &crate::services::did_binding::DurableVerifiedDidBindingStore,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let controller_id = expected_controller_id;
    let expected_controller = arkret_identifiers::Did::new(controller_id.to_owned())
        .map_err(|error| AppError::bad_request(format!("controller DID invalid: {error}")))?;
    let controller_method = binding.controller_proof.verification_method.as_str();
    let public_key = if let Some(device_id) = verification_method_device_id(controller_method) {
        let resolved = resolve_authorized_device_signing_key(
            http_client,
            arkret_config,
            crate::services::resolved_principal_audiences::shared(),
            audience,
            controller_id,
            &device_id,
        )
        .await
        .map_err(|error| {
            AppError::unauthorized(format!(
                "agent_signing_key_mismatch: controller device key could not be resolved: {error}"
            ))
        })?;
        PublicKeyMaterial::Ed25519Multibase {
            value: resolved.multibase,
        }
    } else {
        // Same §4 row 3 trigger and same closed `Controller` purpose as
        // `verify_authorize_event_controller_signature`; within
        // `CONTROLLER_MAX_AGE` the two share one acceptance and perform a
        // single network fetch between them.
        let resolution = crate::services::did_binding::authority_document(
            http_client,
            url_builder,
            arkret_config,
            key_store,
            repo,
            did_resolver,
            binding_store,
            controller_id,
            arkret_identity::DidBindingPurpose::Controller,
            crate::services::did_binding::CONTROLLER_MAX_AGE,
            now,
        )
        .await
        .map_err(|error| {
            AppError::unauthorized(format!(
                "agent_signing_key_mismatch: controller DID has no fresh accepted binding: {error}"
            ))
        })?;
        resolution
            .document
            .verification_method
            .iter()
            .find(|method| method.id == controller_method)
            .ok_or_else(|| {
                AppError::unauthorized(
                    "agent_signing_key_mismatch: controller verification method is absent",
                )
            })?
            .public_key_material()
            .map_err(|error| {
                AppError::bad_request(format!(
                    "agent_signing_key_mismatch: controller verification method invalid: {error}"
                ))
            })?
    };
    arkret_signatures::agent_evidence::verify_agent_signing_key_binding(
        binding,
        agent_id,
        &arkret_wire::NonEmptyString::new(agent_key_id.to_owned()).map_err(|error| {
            AppError::bad_request(format!("authorize_event payload key_id invalid: {error}"))
        })?,
        &expected_controller,
        verification_method,
        authorize_event_id,
        &binding.public_key_digest,
        expected_binding_digest,
        &public_key,
    )
    .map(|_| ())
    .map_err(|reason| AppError::unauthorized(reason.as_str()))
}

/// Canonical signing transcript for the authorize Event.
///
/// Deliberately derived from the caller-supplied Event envelope itself: the
/// typed payload above is for business checks only and MUST NOT be
/// re-serialized to stand in for the signed bytes.
fn authorize_event_signature_input(
    event: &arkret_wire::Event,
    agent_id: &str,
    controller_id: &str,
) -> Result<Vec<u8>, AppError> {
    if event.actor_id.as_str() != agent_id {
        return Err(AppError::bad_request(
            "authorize_event.event.actor_id must match the managed Agent DID",
        ));
    }
    if event
        .executed_by
        .as_ref()
        .map(arkret_identifiers::Did::as_str)
        != Some(controller_id)
    {
        return Err(AppError::bad_request(
            "authorize_event.event.executed_by must match the resolved controller DID",
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
    arkret_canonical::canonical_json_bytes(&digest_payload).map_err(|error| {
        AppError::bad_request(format!(
            "authorize_event canonical payload could not be encoded: {error}"
        ))
    })
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
    arkret_identifiers::DeviceId::new(fragment.to_owned())
        .ok()
        .map(|device_id| device_id.to_string())
}

async fn commit_and_mark_agent_key_authorization(
    depot: &Depot,
    authorized_event_id: &str,
    idempotency_key: &str,
    request_digest: &str,
    principal_server_name: &str,
    body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
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
            arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING,
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
    body: &arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
) -> Result<Vec<String>, AppError> {
    let payload = AgentKeyAuthorizePayload::try_from(&body.authorize_event.event)
        .map_err(|error| AppError::bad_request(format!("authorize_event.event {error}")))?;
    Ok(payload
        .supersedes
        .into_iter()
        .map(|supersession| supersession.authorized_event_ref.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use base64ct::Base64UrlUnpadded;
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
        DateTime::parse_from_rfc3339("2026-07-06T00:05:00.000Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn authoritative_key_state() -> arkret_models_collaboration::agent_operations::KeyState {
        serde_json::from_value(json!({
            "agent_id": AGENT,
            "controller_id": CONTROLLER,
            "principal_control_realm_id": "ak:realm:01999999-0000-7000-8000-000000000010",
            "controller_authorization_ref": format!("{AGENT}#managed-controller"),
            "status": "active",
            "runtime_state": "pending_runtime_key",
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

    fn valid_signing_key_binding()
    -> arkret_models_collaboration::agent_signer_evidence::AgentSigningKeyBinding {
        serde_json::from_value(json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": AGENT,
            "agent_key_id": "runtime-key-1",
            "verification_method": VM,
            "public_key": {
                "kty": "OKP",
                "alg": "Ed25519",
                "key": Base64UrlUnpadded::encode_string(&[42u8; 32])
            },
            "public_key_digest": PUBLIC_KEY_DIGEST,
            "agent_key_authorize_event_id":
                "ak:event:01999999-0000-7000-8000-000000000001",
            "issued_at": "2026-07-06T00:00:00.000Z",
            "expires_at": "2026-07-06T00:10:00.000Z",
            "controller_id": CONTROLLER,
            "controller_proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:controller.example#key-1",
                "jws": "header..signature"
            }
        }))
        .unwrap()
    }

    fn valid_authorize_event(pairing_request_id: &str) -> Value {
        let binding_digest = arkret_signatures::agent_evidence::agent_signing_key_binding_digest(
            &valid_signing_key_binding(),
        )
        .unwrap();
        json!({
            "event_id": "ak:event:01999999-0000-7000-8000-000000000001",
            "kind": "ak.agent.key.authorize",
            "realm_id": "ak:realm:01999999-0000-7000-8000-000000000010",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:01999999-0000-7000-8000-000000000010"
            },
            "actor_id": AGENT,
            "executed_by": CONTROLLER,
            "authorization_ref": format!("{AGENT}#managed-controller"),
            "actor_seq": 1,
            "created_at": "2026-07-06T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "agent_id": AGENT,
                "key_id": "runtime-key-1",
                "verification_method": VM,
                "public_key_digest": PUBLIC_KEY_DIGEST,
                "signing_key_binding_digest": binding_digest,
                "accountable_principal_id": CONTROLLER,
                "agent_key_scope": {
                    "actions": [
                        "ak.self.events.stream.subscribe",
                        "ak.event.read"
                    ],
                    "resources": []
                },
                "audience": [AUDIENCE],
                "issued_at": "2026-07-06T00:00:00.000Z",
                "expires_at": "2026-07-06T00:10:00.000Z",
                "approval_evidence": {
                    "kind": "pairing_request",
                    "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "pairing_request_id": pairing_request_id,
                    "approved_by": CONTROLLER
                }
            },
            // `event-envelope.schema.json#/$defs/event_proof` requires kind,
            // verification_method, alg, event_digest, created_at and jws. The
            // digest here is a placeholder: callers that need a proof actually
            // bound to this envelope rebind it from `Event::event_digest`.
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:controller.example#key-1",
                "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": "2026-07-06T00:01:00.000Z",
                "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
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

    /// Parse a test envelope into the wire Event the handler actually receives.
    fn authorize_event(value: Value) -> arkret_wire::Event {
        serde_json::from_value(value).expect("test authorize_event envelope is a wire Event")
    }

    /// The closed `ak.agent.key.authorize` payload carried by `value`.
    fn authorize_payload(value: Value) -> AgentKeyAuthorizePayload {
        AgentKeyAuthorizePayload::try_from(&authorize_event(value))
            .expect("test authorize_event carries a valid authorize payload")
    }

    #[test]
    fn agent_key_pair_rejects_authorize_event_of_another_kind() {
        let binding = valid_signing_key_binding();
        let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
        envelope["kind"] = json!("ak.agent.key.revoke");

        let err = validate_controller_authorize_event(
            &authorize_event(envelope),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("an Event of another kind must fail closed");

        assert!(err.message().contains("ak.agent.key.authorize"));
    }

    #[test]
    fn agent_key_pair_rejects_unregistered_authorize_payload_field() {
        let binding = valid_signing_key_binding();
        let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
        envelope["payload"]["unregistered_field"] = json!(true);

        let err = validate_controller_authorize_event(
            &authorize_event(envelope),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("the closed payload type must reject unregistered fields");

        assert!(err.message().contains("payload is invalid"));
    }

    #[test]
    fn agent_key_pair_rejects_query_only_pairing_id() {
        let err = ensure_body_pairing_request_id_present("")
            .expect_err("body pairing_request_id is required");

        assert_eq!(err.message(), "pairing_request_id is required");
    }

    #[test]
    fn authorize_event_binds_body_pairing_request_id() {
        let binding = valid_signing_key_binding();
        validate_controller_authorize_event(
            &authorize_event(valid_authorize_event(PAIRING_REQUEST_ID)),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect("matching pairing_request_id accepts");

        let err = validate_controller_authorize_event(
            &authorize_event(valid_authorize_event("agent_pairing_request:wrong")),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
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
        let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
        envelope["payload"]["supersedes"] = json!([{
            "key_id": "runtime-key-1",
            "authorized_event_ref": old_event,
        }]);

        validate_authorize_event_supersedes(&authorize_payload(envelope), &key_state)
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

        let err = validate_authorize_event_supersedes(
            &authorize_payload(valid_authorize_event(PAIRING_REQUEST_ID)),
            &key_state,
        )
        .expect_err("omitting the old same-key authorization dot must fail closed");

        assert_eq!(err.status(), http::StatusCode::CONFLICT);
        assert!(err.message().contains("active key set"));
    }

    #[test]
    fn authorize_event_pairing_evidence_rejects_durable_ref() {
        let binding = valid_signing_key_binding();
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["approval_evidence"]["evidence_ref"] =
            json!("ak:event:01999999-0000-7000-8000-000000000099");

        let err = validate_controller_authorize_event(
            &authorize_event(event),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
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
        let mut binding = valid_signing_key_binding();
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]
            .as_object_mut()
            .unwrap()
            .remove("expires_at");
        binding.expires_at = None;
        event["payload"]["signing_key_binding_digest"] = json!(
            arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding).unwrap()
        );

        let validated = validate_controller_authorize_event(
            &authorize_event(event),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect("absent expires_at means a non-expiring durable key authorization");

        assert!(validated.payload.expires_at.is_none());
    }

    #[test]
    fn authorize_event_rejects_malformed_expires_at() {
        let binding = valid_signing_key_binding();
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["expires_at"] = json!("not-a-timestamp");

        let err = validate_controller_authorize_event(
            &authorize_event(event),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect_err("present but malformed expires_at must fail closed");

        // The SDK payload deserializer reports the canonical-timestamp
        // violation without echoing the field path, so assert the reason
        // rather than the field name — the point of the test is that a present
        // but malformed `expires_at` fails closed instead of being treated as
        // absent (which `authorize_event_accepts_absent_expires_at_as_non_expiring`
        // shows would mean "non-expiring").
        assert!(
            err.message()
                .contains("canonical millisecond timestamp must be"),
            "unexpected rejection message: {}",
            err.message()
        );
    }

    #[test]
    fn authorize_event_accepts_lifetime_longer_than_session_ttl() {
        let mut binding = valid_signing_key_binding();
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["expires_at"] = json!("2026-08-05T00:00:00.000Z");
        binding.expires_at = Some(
            DateTime::parse_from_rfc3339("2026-08-05T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        event["payload"]["signing_key_binding_digest"] = json!(
            arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding).unwrap()
        );

        validate_controller_authorize_event(
            &authorize_event(event),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now(),
        )
        .expect("durable key authorization must outlive individual session grants");
    }

    #[test]
    fn authorize_event_rejects_non_positive_authorization_lifetime() {
        let mut binding = valid_signing_key_binding();
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["issued_at"] = json!("2026-07-06T00:06:00.000Z");
        event["payload"]["expires_at"] = json!("2026-07-06T00:06:00.000Z");
        binding.issued_at = DateTime::parse_from_rfc3339("2026-07-06T00:06:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        binding.expires_at = Some(binding.issued_at);
        event["payload"]["signing_key_binding_digest"] = json!(
            arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding).unwrap()
        );

        let err = validate_controller_authorize_event(
            &authorize_event(event),
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            &binding,
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
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &signing_key.verifying_key().to_bytes(),
        );
        let mut unsigned_event = valid_authorize_event(PAIRING_REQUEST_ID);
        unsigned_event["proofs"] = json!([]);
        let mut event: arkret_wire::Event = serde_json::from_value(unsigned_event).unwrap();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let mut proof = arkret_wire::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            proof_purpose: None,
            verification_method: arkret_wire::DidUrl::new(verification_method.clone()).unwrap(),
            event_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                &canonical_bytes,
            ))
            .unwrap(),
            created_at: "2026-07-06T00:01:00.000Z".parse().unwrap(),
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
            &event,
            AGENT,
            CONTROLLER,
            &[method],
        )
        .expect("authorized controller device signature accepts");
    }

    fn full_fake_signed_authorize_event() -> arkret_wire::Event {
        // The fixture already carries a spec-shaped proof; only its digest is a
        // placeholder. Rebind that one field rather than rebuilding the array,
        // so this helper cannot drift away from the fixture's proof shape.
        let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
        let parsed = authorize_event(envelope.clone());
        envelope["proofs"][0]["event_digest"] = json!(parsed.event_digest().unwrap());
        authorize_event(envelope)
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
