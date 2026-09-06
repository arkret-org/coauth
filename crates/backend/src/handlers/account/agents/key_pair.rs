//! AKP-0008 §4.5 runtime key pairing (`ak.gate.account.command.pair_agent_key.v1`).
//!
//! `POST /_arkret/gate/account/agent-key-pair`. The agent runtime generated a
//! key pair locally and submits the public key plus a proof-of-possession. The
//! controller supplies the signed `ak.agent.key.authorize` event; coauth only
//! validates the request binding, persists the pending local authorization for
//! `agent_key_proof`, and commits the unchanged signed request to the
//! authoritative Station before reporting the Event as durable. The
//! caller closes it into an accepted Agent-PCR frontier and retries the same
//! idempotent request before the runtime is reported active.

use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_data::RepositoryAccess;
use coauth_data::accountability::AccountabilityGrantFanoutState;
use coauth_data::agent_key::NewAgentKeyAuthorization;
use coauth_data::audit::AdminOperation;
use coauth_data::queue::{AgentKeyPairCommitJob, QueueJobRepositoryExt as _};
use coauth_principal::PrincipalAgentKeyPairCommitRequest;
use salvo::prelude::*;
#[cfg(test)]
use serde_json::Value;

use super::error_matrix::{AgentAuthRejection, enforce_verification_method_binding};
use super::proof::canonical_digest;
use crate::AppError;
use crate::handlers::account::{DepotExt, make_clock, make_rng};
use crate::handlers::admin::audit_helper::record_service_admin_operation_signed;
use crate::handlers::arkret::{
    ArkretRouteError, is_allowed_session_grant_audience, owning_station_did_for,
    owning_station_id_for,
};
use crate::services::did_binding_proof::normalize_did_for_binding;

/// Durable retry queue used when the authoritative Station cannot be
/// reached after the exact pairing request has been persisted locally.
const AGENT_KEY_PAIR_COMMIT_QUEUE: &str = "principal-agent-key-pair-commit";

/// `POST /_arkret/gate/account/agent-key-pair`
/// (`ak.gate.account.command.pair_agent_key.v1`).
///
/// Validates the runtime key pairing proof-of-possession and, on success,
/// records a pending local agent key authorization, commits the exact same
/// canonical operation to the authoritative Station, and returns only
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

    let body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    // The carried Event id is untrusted input. Verify its complete
    // suite-tagged digest binding before it is used for idempotency or any
    // repository lookup.
    verify_authorize_event_identity(&body.authorize_event.event)?;
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
    let public_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &body.public_key,
        &body.verification_method,
    )
    .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;

    let pop = &body.proof_of_possession;
    if pop.challenge != body.pairing_request_id {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }

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
        if existing.quarantined_at.is_some() {
            idempotency_repo.cancel().await?;
            return Err(AppError::conflict("witness_disagreement").into());
        }
        let stored_body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody =
            serde_json::from_value(existing.soland_fanout_payload.clone()).map_err(|error| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("stored Agent key-pair request is invalid: {error}"),
                )
            })?;
        verify_authorize_event_identity(&stored_body.authorize_event.event).map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored Agent authorization has an invalid Event identity",
            )
        })?;
        let stored_preimage = authorize_event_preimage_bytes(&stored_body.authorize_event.event)?;
        let incoming_preimage = authorize_event_preimage_bytes(&body.authorize_event.event)?;
        if stored_preimage != incoming_preimage {
            let variants = [
                coauth_data::agent_key::AgentEventCollisionVariant {
                    canonical_preimage: stored_preimage,
                    envelope: serde_json::to_value(&stored_body.authorize_event.event)
                        .map_err(|error| AppError::internal_box(Box::new(error)))?,
                },
                coauth_data::agent_key::AgentEventCollisionVariant {
                    canonical_preimage: incoming_preimage,
                    envelope: serde_json::to_value(&body.authorize_event.event)
                        .map_err(|error| AppError::internal_box(Box::new(error)))?,
                },
            ];
            let clock = make_clock();
            let mut rng = make_rng();
            let quarantined = idempotency_repo
                .agent_key_authorization()
                .quarantine_event_collision(&mut *rng, &*clock, &authorized_event_id, &variants)
                .await?;
            if !quarantined {
                idempotency_repo.cancel().await?;
                return Err(AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Event collision quarantine could not be persisted",
                )
                .into());
            }
            idempotency_repo.save().await?;
            return Err(AppError::conflict("witness_disagreement").into());
        }
        let same_request = existing.agent_id == agent_id
            && existing.verification_method == body.verification_method.as_str()
            && existing.public_key == public_key_value
            && existing.pairing_request_id == body.pairing_request_id.as_str()
            && existing.authorized_event_id == authorized_event_id
            && existing.raw_payload_digest == request_digest;
        if !same_request {
            idempotency_repo.cancel().await?;
            return Err(AppError::conflict(
                "authorize Event id is already bound to a different Agent authorization",
            )
            .into());
        }
        idempotency_repo.cancel().await?;
        let authorize_event_ref =
            arkret_identifiers::EventId::new(existing.authorized_event_id.clone())
                .map_err(|error| AppError::internal_box(Box::new(error)))?;
        let (authoritative_view, authoritative_server) =
            super::session_proof::fetch_authoritative_agent_view(
                &http_client,
                &arkret_config,
                &agent_id,
            )
            .await
            .map_err(AgentAuthRejection::into_app_error)?;
        if existing.soland_fanout_state == AccountabilityGrantFanoutState::Delivered {
            let activation_state = if authoritative_view.key_state.as_ref().is_some_and(
                |key_state| {
                    key_state.active_authorizations.iter().any(|authorization| {
                        authorization.authorized_event_ref.as_str() == authorize_event_ref.as_str()
                            && authorization.verification_method == stored_body.verification_method
                    })
                },
            ) {
                arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active
            } else {
                arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::AwaitingAcceptedFrontier
            };
            return Ok(Json(
                arkret_models_collaboration::agent_operations::AgentKeyPairOutcome {
                    activation_state,
                    authorize_event_ref,
                    signing_key_binding: stored_body.signing_key_binding,
                },
            ));
        }
        let signing_key_binding = stored_body.signing_key_binding.clone();
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
                activation_state: arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::AwaitingAcceptedFrontier,
                authorize_event_ref,
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
        agent_id.as_str(),
        &body.pairing_request_id,
        now,
    )
    .await
    .map_err(AgentAuthRejection::into_app_error)?;

    // Expiry: a stale pairing PoP is rejected as `pairing_request_expired`.
    // Audience MUST be this service (the coauth issuer audience or a configured
    // station audience).
    if !is_allowed_session_grant_audience(
        &url_builder,
        &arkret_config,
        crate::services::station_trust::shared(),
        pop.audience_id.as_str(),
    ) {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }

    let agent_id = arkret_identifiers::DidCoreId::new(agent_id.clone())
        .map_err(|error| AppError::bad_request(format!("agent_id invalid: {error}")))?;
    let expected_binding =
        arkret_models_collaboration::agent_operations::agent_runtime_key_binding_digest(
            &agent_id,
            &body.pairing_request_id,
            &body.verification_method,
            &body.public_key,
            body.runtime_attestation.as_ref(),
        )
        .map_err(|error| {
            AppError::bad_request(format!(
                "proof_of_possession runtime binding failed: {error}"
            ))
        })?;
    let authoritative_key_state = authoritative_view
        .key_state
        .as_ref()
        .ok_or_else(|| AppError::forbidden("authoritative Agent key state is missing"))?;
    let pairing_code = authoritative_key_state
        .pairing_code
        .as_deref()
        .ok_or_else(|| AppError::forbidden("authoritative pairing code is missing"))?;
    let pairing_expires_at = authoritative_key_state
        .pairing_expires_at
        .ok_or_else(|| AppError::forbidden("authoritative pairing expiry is missing"))?;
    let transcript = pop
        .validate_shape(
            &agent_id,
            &body.pairing_request_id,
            &body.verification_method,
            &body.public_key,
            &expected_binding,
            pairing_code,
            pairing_expires_at,
            now,
        )
        .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.raw_public_key)
        .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
    let signature = Base64UrlUnpadded::decode_vec(pop.signature.as_str())
        .ok()
        .and_then(|bytes| ed25519_dalek::Signature::from_slice(&bytes).ok())
        .ok_or_else(|| AgentAuthRejection::ProofInvalid.into_app_error())?;
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;

    let authorize_event = validate_controller_authorize_event(
        &body.authorize_event.event,
        agent_id.as_str(),
        &body.verification_method,
        &body.public_key,
        &body.signing_key_binding,
        &body.pairing_request_id,
        pop.audience_id.as_str(),
        authoritative_key_state,
        now,
    )?;
    // Everything above is a structural check over untrusted bytes. The two
    // controller-signed evidences are only believed after their signatures
    // verify against key material this service resolved for itself.
    let controller_keys =
        resolve_controller_signing_keys(depot, &authoritative_key_state.controller_account_id, now)
            .await?;
    verify_controller_pairing_evidence(
        &body.authorize_event.event,
        &body.signing_key_binding,
        &authorize_event.payload,
        &body.verification_method,
        authoritative_key_state,
        &controller_keys,
    )?;
    super::session_proof::validate_agent_runtime_key_scope_layers(
        &authoritative_key_state.requested_scope.actions,
        &authorize_event.payload.agent_key_scope.actions,
    )
    .map_err(AgentAuthRejection::into_app_error)?;
    let mut repo = depot.repo().await?;

    // `pair_agent_key` validates the current Station pairing handle
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
        .list_active_for_agent(agent_id.as_str())
        .await?;
    let service_id = owning_station_id_for(&arkret_config);
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
                agent_id: agent_id.to_string(),
                key_id: key_id.clone(),
                verification_method: body.verification_method.to_string(),
                public_key: public_key_value.clone(),
                accountable_principal_id: arkret_identifiers::DidCoreId::new(
                    authorize_event.controller_principal_id.clone(),
                )
                .map_err(|err| AppError::internal_box(Box::new(err)))?,
                agent_key_scope,
                audience: vec![pop.audience_id.to_string()],
                issued_at,
                expires_at,
                pairing_request_id: body.pairing_request_id.to_string(),
                request_canonical_digest: authorize_event
                    .payload
                    .approval_evidence
                    .request_canonical_digest
                    .as_ref()
                    .expect("validated pairing request approval digest")
                    .to_string(),
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
        "controller_principal_id": &authorize_event.controller_principal_id,
        "verification_method": &body.verification_method,
        "audience_id": &pop.audience_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "superseded_active_keys": superseded_keys,
        // Two orthogonal axes (key-management.md §3.6.1): the controller
        // lifecycle intent is preserved by pairing completion (an active agent
        // needs no resume), while the derived runtime_state advances to ready.
        "agent_lifecycle": authoritative_view.agent.lifecycle.as_wire_str(),
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
            "station": &authoritative_server.name,
            "next_retry_at": issued_at,
        }
    });
    let key_store = depot.key_store()?;
    let service_did = owning_station_did_for(&arkret_config);
    record_service_admin_operation_signed(
        &mut repo,
        &mut *rng,
        &*clock,
        &key_store,
        &service_did,
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
            activation_state: arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::AwaitingAcceptedFrontier,
            authorize_event_ref: outcome_event_id,
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
    controller_principal_id: String,
    payload: AgentKeyAuthorizePayload,
}

fn validate_controller_authorize_event(
    event: &arkret_wire::Event,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key: &arkret_models_collaboration::governance::agent_artifacts::PublicKey,
    signing_key_binding: &arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
    pairing_request_id: &str,
    audience: &str,
    authoritative_key_state: &arkret_models_collaboration::agent_operations::KeyState,
    now: DateTime<Utc>,
) -> Result<ValidatedAuthorizeEvent, AppError> {
    // Closes the payload once, here. Every business check below reads a typed
    // field; unknown payload fields are already rejected by the SDK type.
    let payload = AgentKeyAuthorizePayload::try_from(event)
        .map_err(|error| AppError::bad_request(format!("authorize_event.event {error}")))?;

    let expected_agent_id = parse_principal_id(agent_id, "agent_id")?;
    if event.actor_id != arkret_wire::ActorId::service(expected_agent_id.clone()) {
        return Err(AppError::forbidden(
            "authorize_event.event.actor_id must equal the Agent DID",
        ));
    }
    let controller_account_id = event
        .executed_by
        .as_ref()
        .and_then(arkret_wire::ActorId::as_account_id)
        .ok_or_else(|| {
            AppError::bad_request(
                "authorize_event.event.executed_by must be the controller account actor",
            )
        })?;
    let controller_principal_id = controller_account_id.principal_id.as_str();
    if authoritative_key_state.agent_id != expected_agent_id
        || &authoritative_key_state.controller_account_id != controller_account_id
    {
        return Err(AppError::forbidden(
            "authorize_event controller account does not match the authoritative Agent binding",
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
    ensure_authorize_event_has_controller_signature(event, controller_principal_id)?;

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
    if parse_principal_id(
        payload.accountable_principal_id.as_str(),
        "authorize_event.event.payload.accountable_principal_id",
    )?
    .as_str()
        != controller_principal_id
    {
        return Err(AppError::forbidden(
            "authorize_event.event.payload.accountable_principal_id must match executed_by",
        ));
    }
    let verification_method =
        arkret_wire::DidUrl::new(verification_method.to_owned()).map_err(AppError::bad_request)?;
    let validated_key_material =
        arkret_signatures::agent_evidence::validate_agent_pairing_key_material(
            runtime_public_key,
            &verification_method,
            signing_key_binding,
        )
        .map_err(|reason| AppError::bad_request(reason.as_str()))?;
    if payload.public_key_digest != validated_key_material.authorization_digest {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.public_key_digest must bind the raw signing key",
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
    if signing_key_binding.agent_id != expected_agent_id
        || signing_key_binding.verification_method != verification_method
        || signing_key_binding.agent_key_authorize_event_id.as_str() != event.event_id.as_str()
        || signing_key_binding.public_key_digest != validated_key_material.authorization_digest
        || signing_key_binding.controller_principal_id.as_str() != controller_principal_id
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
    let approved_by_matches_controller = approval
        .approved_by
        .as_ref()
        .is_some_and(|approved_by| approved_by.as_str() == controller_principal_id);
    if !approved_by_matches_controller {
        return Err(AppError::forbidden(
            "authorize_event.event.payload.approval_evidence.approved_by must match executed_by",
        ));
    }

    Ok(ValidatedAuthorizeEvent {
        controller_principal_id: payload.accountable_principal_id.to_string(),
        payload,
    })
}

fn verify_authorize_event_identity(event: &arkret_wire::Event) -> Result<(), AppError> {
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|_| AppError::bad_request("event_id_digest_mismatch"))
}

fn authorize_event_preimage_bytes(event: &arkret_wire::Event) -> Result<Vec<u8>, AppError> {
    let preimage = event.digest_payload().map_err(|error| {
        AppError::bad_request(format!(
            "authorize Event digest preimage is invalid: {error}"
        ))
    })?;
    arkret_canonical::canonical_json_bytes(&preimage).map_err(|error| {
        AppError::bad_request(format!(
            "authorize Event preimage is not canonical: {error}"
        ))
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

/// Pre-crypto principal binding for the controller Event proof.
///
/// This is the AUTH-1 edge check: it only proves the proof *names* a method
/// under the controller's DID, so a principal-binding bug cannot hide behind a
/// crypto bug. The signature itself is verified later, against key material
/// this service resolved, by [`verify_controller_authorize_event_proofs`].
fn ensure_authorize_event_has_controller_signature(
    event: &arkret_wire::Event,
    controller_principal_id: &str,
) -> Result<(), AppError> {
    if event.proofs.is_empty() {
        return Err(AppError::bad_request(
            "authorize_event must carry controller signature proofs",
        ));
    }
    let signed_by_controller = event
        .proofs
        .iter()
        .filter_map(|proof| proof.as_producer())
        .any(|proof| {
            verification_method_controller_principal_id(&proof.verification_method).is_some_and(
                |proof_controller| proof_controller.as_str() == controller_principal_id,
            )
        });
    if !signed_by_controller {
        return Err(AppError::bad_request(
            "authorize_event proof verification_method controller must match executed_by.account_id.principal_id",
        ));
    }
    Ok(())
}

/// Controller signing keys resolved by this service, never by the request.
///
/// `key-management.md` §3.6.1 makes the Account Authority verify the controller
/// Event proof and the `signing_key_binding` controller proof itself, and
/// `service-http-binding.md` forbids trusting an upstream "already verified"
/// boolean. Both requirements collapse to one rule: the request body may name
/// *which* published method signed, but it may never supply the key that
/// checks the signature.
struct ControllerSigningKeys {
    document: arkret_models_identity::DidDocument,
}

impl ControllerSigningKeys {
    /// Published key material for one controller verification method.
    ///
    /// A method the resolved document does not publish is a rejection, not a
    /// fallback to anything the caller sent.
    fn material(
        &self,
        verification_method: &str,
    ) -> Result<arkret_signatures::PublicKeyMaterial, AppError> {
        arkret_identity::resolve_verification_method_key_from_document(
            &self.document,
            verification_method,
        )
        .map(|resolved| resolved.public_key)
        .map_err(|error| {
            tracing::debug!(%verification_method, %error, "controller verification method is not published");
            AgentAuthRejection::ProofInvalid.into_app_error()
        })
    }
}

/// Resolve the authoritative controller's published DID document.
///
/// The DID is taken from this deployment's accepted principal binding for the
/// exact `AccountId` the authoritative Agent key state names, so a caller
/// cannot steer the resolution by writing a controller DID into the evidence
/// it wants accepted. The document itself comes from the same
/// freshness-bounded authority path the other controller gates use, so key
/// rotation and deactivation reach this endpoint the way they reach them.
async fn resolve_controller_signing_keys(
    depot: &Depot,
    controller_account_id: &arkret_wire::AccountId,
    now: DateTime<Utc>,
) -> Result<ControllerSigningKeys, AppError> {
    let mut repo = depot.repo().await?;
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(
            controller_account_id.principal_id.as_str(),
            controller_account_id.station_id.as_str(),
        )
        .await?
        .filter(|binding| &binding.account_id == controller_account_id)
        .ok_or_else(|| {
            tracing::debug!(
                controller = %controller_account_id.principal_id,
                "Agent pairing controller has no accepted principal DID binding"
            );
            AgentAuthRejection::ProofInvalid.into_app_error()
        })?;
    let authority = crate::services::did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &depot.arkret_config()?,
        &depot.key_store()?,
        &mut repo,
        depot.did_resolver_service()?.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        binding.verified_did.as_str(),
        arkret_identity::DidBindingPurpose::Controller,
        crate::services::did_binding::controller_freshness(),
        now,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "controller DID resolution for Agent key pairing failed");
        AgentAuthRejection::PolicyUnavailable.into_app_error()
    })?;
    let document = authority.accepted.document().clone();
    repo.save().await?;
    Ok(ControllerSigningKeys { document })
}

/// Verify both controller-signed pairing evidences.
///
/// Order matters: the Event proof runs first, so every `payload` value used
/// below as an expectation for the binding is already controller-authenticated
/// rather than merely well-shaped. Nothing is read back out of the binding —
/// the expectations come from the authoritative key state, the typed request
/// fields and the content-bound Event id.
fn verify_controller_pairing_evidence(
    event: &arkret_wire::Event,
    signing_key_binding: &arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
    payload: &AgentKeyAuthorizePayload,
    verification_method: &arkret_wire::DidUrl,
    authoritative_key_state: &arkret_models_collaboration::agent_operations::KeyState,
    controller_keys: &ControllerSigningKeys,
) -> Result<(), AppError> {
    verify_controller_authorize_event_proofs(event, controller_keys)?;
    arkret_signatures::agent_evidence::verify_agent_signing_key_binding(
        signing_key_binding,
        &authoritative_key_state.agent_id,
        &payload.key_id,
        &authoritative_key_state.controller_account_id.principal_id,
        verification_method,
        &event.event_id,
        &payload.public_key_digest,
        &payload.signing_key_binding_digest,
        &controller_keys.material(
            signing_key_binding
                .controller_proof
                .verification_method
                .as_str(),
        )?,
    )
    .map_err(|reason| {
        tracing::debug!(
            reason = reason.as_str(),
            "Agent signing key binding rejected"
        );
        AgentAuthRejection::ProofInvalid.into_app_error()
    })?;
    Ok(())
}

/// Verify every producer proof on the controller-signed authorize Event.
///
/// The signed transcript is the proof binding object, not the raw Event bytes;
/// the SDK verifier builds it from the proof plus `actor_id` and re-derives the
/// covered `event_digest` from the canonical preimage passed in here. Requiring
/// *every* producer proof to verify, rather than any one of them, keeps a
/// second unverifiable proof from riding along on a valid one.
fn verify_controller_authorize_event_proofs(
    event: &arkret_wire::Event,
    controller_keys: &ControllerSigningKeys,
) -> Result<(), AppError> {
    let canonical_bytes = authorize_event_preimage_bytes(event)?;
    let mut verified = 0usize;
    for proof in event
        .proofs
        .iter()
        .filter_map(arkret_wire::EventProof::as_producer)
    {
        let material = controller_keys.material(proof.verification_method.as_str())?;
        arkret_signatures::proof::verify_ed25519_detached_jws_proof(
            proof,
            &canonical_bytes,
            &event.actor_id,
            &material,
        )
        .map_err(|error| {
            tracing::debug!(%error, "controller authorize Event proof failed verification");
            AgentAuthRejection::ProofInvalid.into_app_error()
        })?;
        verified += 1;
    }
    if verified == 0 {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }
    Ok(())
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

fn parse_principal_id(
    principal_id: &str,
    field: &str,
) -> Result<arkret_identifiers::DidCoreId, AppError> {
    arkret_identifiers::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::bad_request(format!("{field} invalid: {error}")))
}

fn verification_method_controller_principal_id(
    verification_method: &str,
) -> Option<arkret_identifiers::DidCoreId> {
    let did = arkret_identifiers::Did::new(
        verification_method_controller(verification_method).to_owned(),
    )
    .ok()?;
    arkret_identifiers::project_did_to_core_id(&did).ok()
}

async fn commit_and_mark_agent_key_authorization(
    depot: &Depot,
    authorized_event_id: &str,
    idempotency_key: &str,
    request_digest: &str,
    station_name: &str,
    body: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
) -> Result<(), AppError> {
    let superseded_event_refs = pairing_superseded_event_refs(&body)?;
    let http_client = depot.http_client()?;
    let arkret_config = depot.arkret_config()?;
    let request = PrincipalAgentKeyPairCommitRequest::new(
        idempotency_key.to_owned(),
        request_digest.to_owned(),
        station_name.to_owned(),
        body,
    );
    crate::services::principal_facade::commit_agent_key_pair_to_station(
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
                "Agent key-pair request is durable but the authoritative Station has not accepted it: {error}"
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
            "Station accepted the Agent key, but local reconciliation is pending",
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
#[path = "key_pair/tests.rs"]
mod tests;
