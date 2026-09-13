//! AKP-0008 §4.5 runtime key pairing (`ak.gate.account.command.pair_agent_key.v1`).
//!
//! `POST /_arkret/gate/account/agent-key-pair`. The owning Station is the
//! single owner of the pairing raw material and of business admission
//! (`key-management.md` §3.6.1): it holds the frozen candidate and verifies the
//! runtime proof-of-possession against the current handle. Coauth checks only
//! the request / Event / Agent / controller / authorization-object bindings on
//! that authenticated result, persists the pending local authorization for
//! `agent_key_proof`, and commits the unchanged signed request to the
//! authoritative Station before reporting the Event as durable. The
//! Station activates the frozen candidate after its authorize Event enters an
//! accepted Agent-PCR frontier; polling only observes this transition.

use std::collections::BTreeMap;

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

/// Durable retry queue used when the authoritative Station cannot be
/// reached after the exact pairing request has been persisted locally.
const AGENT_KEY_PAIR_COMMIT_QUEUE: &str = "principal-agent-key-pair-commit";

/// `POST /_arkret/gate/account/agent-key-pair`
/// (`ak.gate.account.command.pair_agent_key.v1`).
///
/// Checks the pairing request against the Station's authenticated Agent key
/// state and the controller-authored authorize Event and, on success,
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
    let key_store = depot.key_store()?;

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

    // `agent_id` is already a closed `DidCoreId` on the wire model. Do not
    // feed it through the full-DID normalizer: that parser deliberately
    // rejects `ak:did_core:*` identifiers.
    let submitted_payload = AgentKeyAuthorizePayload::try_from(&body.authorize_event.event)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let agent_id = submitted_payload.agent_id.to_string();
    ensure_body_pairing_request_id_present(&body.pairing_request_id)?;

    enforce_verification_method_binding(&submitted_payload.verification_method, &agent_id)
        .map_err(AgentAuthRejection::into_app_error)?;

    let public_key_value = serde_json::to_value(&submitted_payload.public_key)
        .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;
    arkret_signatures::agent::validate_agent_runtime_public_key(
        &submitted_payload.public_key,
        &submitted_payload.verification_method,
    )
    .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;

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
            && existing.verification_method == submitted_payload.verification_method.as_str()
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
        let (_authoritative_view, authoritative_server) =
            super::session_proof::fetch_authoritative_agent_view(
                &http_client,
                &arkret_config,
                &key_store,
                &agent_id,
            )
            .await
            .map_err(AgentAuthRejection::into_app_error)?;
        let outcome = commit_and_mark_agent_key_authorization(
            depot,
            &existing.authorized_event_id,
            &existing.soland_fanout_idempotency_key,
            &existing.raw_payload_digest,
            &authoritative_server.name,
            stored_body,
        )
        .await?;
        return Ok(Json(outcome));
    }
    idempotency_repo.cancel().await?;

    let clock = make_clock();
    let now = clock.now();

    let (authoritative_view, authoritative_server) = super::enforce_authoritative_pairing_handle(
        &http_client,
        &arkret_config,
        &key_store,
        agent_id.as_str(),
        &body.pairing_request_id,
        now,
    )
    .await
    .map_err(AgentAuthRejection::into_app_error)?;

    // `key-management.md` §3.6.1: the owning Station is the single owner of the
    // pairing raw material and of business admission. It holds and verifies the
    // candidate proof-of-possession against the current handle; the Account
    // Authority consumes that authenticated result and only checks the
    // request / Event / Agent / controller / authorization-object bindings
    // below. It never re-obtains the candidate and PoP to rebuild the stable
    // binding and PoP transcript for a second signature check, and it never
    // infers completion from a caller-supplied "verified" flag.
    let authoritative_key_state = authoritative_view
        .key_state
        .as_ref()
        .ok_or_else(|| AppError::forbidden("authoritative Agent key state is missing"))?;
    let pairing_expires_at = authoritative_key_state
        .pairing_expires_at
        .ok_or_else(|| AppError::forbidden("authoritative pairing expiry is missing"))?;

    let agent_id = arkret_identifiers::DidCoreId::new(agent_id.clone())
        .map_err(|error| AppError::bad_request(format!("agent_id invalid: {error}")))?;
    // The controller-authored disclosure names the verifier this pairing is
    // requested for. Its signature is verified further down against controller
    // key material this service resolved, and the controller Event's approval
    // digest binds the same value, so it is the authorization object the
    // Authority checks - not a raw-material input it re-validates.
    let disclosure = &body.requested_scope_disclosure;
    disclosure
        .validate()
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let audience_id = disclosure.verifier_id.clone();
    if !is_allowed_session_grant_audience(
        &url_builder,
        &arkret_config,
        crate::services::station_trust::shared(),
        audience_id.as_str(),
    ) {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }
    // Derived from the fields the request already carries, so the
    // controller-signed approval digest can be checked. This is a binding
    // recomputation over an authenticated object, not a second verification of
    // the runtime's possession proof.
    let expected_binding =
        arkret_models_collaboration::agent_operations::agent_runtime_key_binding_digest(
            &agent_id,
            &body.pairing_request_id,
            &submitted_payload.verification_method,
            &submitted_payload.public_key,
            submitted_payload.runtime_attestation.as_ref(),
        )
        .map_err(|error| {
            AppError::bad_request(format!("runtime key binding digest failed: {error}"))
        })?;

    let authorize_event = validate_controller_authorize_event(
        &body.authorize_event.event,
        agent_id.as_str(),
        &submitted_payload.verification_method,
        &submitted_payload.public_key,
        &body.pairing_request_id,
        audience_id.as_str(),
        authoritative_key_state,
        now,
    )?;
    let expected_approval =
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            "ak.gate.account.command.pair_agent_key.v1",
            &authoritative_key_state.controller_account_id.principal_id,
            &agent_id,
            &body.pairing_request_id,
            &body.approval_request_id,
            pairing_expires_at,
            &audience_id,
            &expected_binding,
        )
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    if authorize_event
        .payload
        .approval_evidence
        .request_canonical_digest
        .as_ref()
        != Some(&expected_approval)
    {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }
    if disclosure.agent_id != agent_id
        || disclosure.controller_principal_id
            != authoritative_key_state.controller_account_id.principal_id
        || disclosure.requested_scope != authoritative_key_state.requested_scope
        || disclosure.audience.as_str() != "ak.gate.account.command.pair_agent_key.v1"
        || disclosure.request_id.as_str()
            != format!(
                "ak:request:{}",
                body.pairing_request_id
                    .as_str()
                    .strip_prefix("agent_pairing_request:")
                    .unwrap_or("")
            )
        || now < disclosure.issued_at
        || now > disclosure.expires_at
        || disclosure.challenge.as_str() != body.pairing_request_id.as_str()
    {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
    }
    // Everything above is a structural check over untrusted bytes. The
    // controller-authored Event is only believed after its signatures
    // verify against key material this service resolved for itself.
    let controller_verification_methods = body
        .authorize_event
        .event
        .proofs
        .iter()
        .map(|proof| proof.verification_method.as_str())
        .chain(
            disclosure
                .proofs
                .iter()
                .map(|proof| proof.verification_method.as_str()),
        )
        .collect::<Vec<_>>();
    let controller_keys = resolve_controller_signing_keys(
        depot,
        &authoritative_key_state.controller_account_id,
        &controller_verification_methods,
        now,
    )
    .await?;
    verify_controller_authorize_event_proofs(&body.authorize_event.event, &controller_keys)?;
    for proof in &disclosure.proofs {
        if proof.created_at < disclosure.issued_at || proof.created_at > disclosure.expires_at {
            return Err(AgentAuthRejection::ProofInvalid.into_app_error().into());
        }
        let transcript = disclosure
            .canonical_proof_binding_bytes(proof)
            .map_err(|error| AppError::bad_request(error.to_string()))?;
        let parts = arkret_signatures::proof::validate_ed25519_detached_jws_shape(&proof.jws)
            .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
        let signing_input = format!(
            "{}.{}",
            parts[0],
            Base64UrlUnpadded::encode_string(&transcript)
        );
        arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
            signing_input.as_bytes(),
            parts[2],
            &controller_keys.material(proof.verification_method.as_str())?,
        )
        .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
    }
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

    let raw_payload_digest = request_digest;
    let fanout_payload =
        serde_json::to_value(&body).map_err(|error| AppError::internal_box(Box::new(error)))?;
    let idempotency_key = authorized_event_id.clone();
    let agent_key_scope = serde_json::to_string(&authorize_event.payload.agent_key_scope)
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    // State-truth model (`key-management.md` §3.6.1): the Station holds the
    // single command/activation truth; this row is the Account Authority's
    // issuer-side projection plus the exact pending intent it owes a retry for.
    // It is written from the same frozen request the Station will accept, so it
    // can be rebuilt from that one durable outcome; it is read back only
    // together with the current authoritative Agent view
    // (`session_proof::validate_authoritative_agent_session_evidence`); and a
    // locally `active` row is never evidence that the Station activated the
    // key - `commit_and_mark_agent_key_authorization` advances it only after
    // the Station's own outcome says `Active`.
    repo.agent_key_authorization()
        .add(
            &mut *rng,
            &*clock,
            NewAgentKeyAuthorization {
                authorized_event_id: authorized_event_id.clone(),
                agent_id: agent_id.to_string(),
                key_id: key_id.clone(),
                verification_method: submitted_payload.verification_method.to_string(),
                public_key: public_key_value.clone(),
                accountable_principal_id: arkret_identifiers::DidCoreId::new(
                    authorize_event.controller_principal_id.clone(),
                )
                .map_err(|err| AppError::internal_box(Box::new(err)))?,
                agent_key_scope,
                audience: vec![audience_id.to_string()],
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
        "verification_method": &submitted_payload.verification_method,
        "audience_id": &audience_id,
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

    let outcome = commit_and_mark_agent_key_authorization(
        depot,
        &authorized_event_id,
        &idempotency_key,
        &raw_payload_digest,
        &authoritative_server.name,
        body,
    )
    .await?;

    Ok(Json(outcome))
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
    let expected_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        expected_agent_id.clone(),
        authoritative_key_state
            .controller_account_id
            .station_id
            .clone(),
    ));
    if event.actor_id != expected_actor_id {
        return Err(AppError::forbidden(
            "authorize_event.event.actor_id must equal the Agent account at the authoritative Station",
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
    validate_authorize_event_supersedes(&payload, authoritative_key_state)?;

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
    arkret_signatures::agent::validate_agent_runtime_public_key(
        runtime_public_key,
        &verification_method,
    )
    .map_err(|error| AppError::bad_request(error.to_string()))?;
    if payload.public_key != *runtime_public_key {
        return Err(AppError::bad_request(
            "authorize Event key differs from the submitted runtime key",
        ));
    }
    if !payload
        .audience
        .iter()
        .any(|candidate| candidate == audience)
    {
        return Err(AppError::bad_request(
            "authorize_event.event.payload.audience must include requested_scope_disclosure.verifier_id",
        ));
    }
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
    let signed_by_controller = event.proofs.iter().any(|proof| {
        verification_method_controller_principal_id(&proof.verification_method)
            .is_some_and(|proof_controller| proof_controller.as_str() == controller_principal_id)
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
/// Event proof independently, and
/// `service-http-binding.md` forbids trusting an upstream "already verified"
/// boolean. The request body may name
/// *which* published method signed, but it may never supply the key that
/// checks the signature.
struct ControllerSigningKeys {
    document: arkret_models_identity::DidDocument,
    accepted_device_material: BTreeMap<String, arkret_signatures::PublicKeyMaterial>,
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
        if let Some(material) = self.accepted_device_material.get(verification_method) {
            return Ok(material.clone());
        }
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
    verification_methods: &[&str],
    now: DateTime<Utc>,
) -> Result<ControllerSigningKeys, AppError> {
    let arkret_config = depot.arkret_config()?;
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
        &arkret_config,
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
    let controller_did = binding.verified_did.as_str();
    let mut method_devices = BTreeMap::new();
    for method in verification_methods {
        if verification_method_controller(method) != controller_did {
            return Err(AgentAuthRejection::ProofInvalid.into_app_error());
        }
        let device = method
            .rsplit_once('#')
            .map(|(_, fragment)| fragment)
            .ok_or_else(|| AgentAuthRejection::ProofInvalid.into_app_error())?;
        let device_id = arkret_identifiers::DeviceId::new(device.to_owned())
            .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
        method_devices.insert((*method).to_owned(), device_id);
    }

    let station = controller_station_for_pairing(
        &arkret_config,
        crate::services::station_trust::shared(),
        &controller_account_id.station_id,
    )?;
    let bearer = station
        .embedded_webvh_registration_bearer
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "controller Station device signing-key directory bearer is not configured",
            )
        })?;
    let mut directory_url = station.endpoint.clone();
    directory_url.set_path("/_soland/gate/account/device-signing-keys/query");
    directory_url.set_query(None);
    directory_url.set_fragment(None);
    let query = soland_contracts::admin::device_signing_directory::DeviceSigningKeyDirectoryQueryRequestBody {
        principal_id: controller_account_id.principal_id.clone(),
        device_ids: method_devices.values().cloned().collect(),
    };
    let query_bytes = arkret_canonical::canonical_json_bytes(&query)
        .map_err(|error| AppError::internal_box(Box::new(error)))?;
    let response = depot
        .http_client()?
        .post(directory_url)
        .bearer_auth(bearer)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(query_bytes)
        .send()
        .await
        .map_err(|error| AppError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "controller Station device signing-key directory rejected the request",
        ));
    }
    let directory: soland_contracts::admin::device_signing_directory::DeviceSigningKeyDirectoryOutcome =
        response
            .json()
            .await
            .map_err(|error| AppError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    if directory.principal_id != controller_account_id.principal_id {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }
    let mut accepted_device_material = BTreeMap::new();
    for (method, device_id) in method_devices {
        let device = directory
            .devices
            .iter()
            .find(|candidate| {
                candidate.device_id == device_id
                    && matches!(
                        candidate.device_status,
                        arkret_models_crypto::DeviceStatus::Active
                    )
            })
            .ok_or_else(|| AgentAuthRejection::ProofInvalid.into_app_error())?;
        let multibase = device
            .device_signing_key_did
            .strip_prefix("did:key:")
            .ok_or_else(|| AgentAuthRejection::ProofInvalid.into_app_error())?;
        let public_key = arkret_canonical::decode_ed25519_multibase(multibase)
            .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
        accepted_device_material.insert(
            method,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: public_key.to_vec(),
            },
        );
    }
    repo.save().await?;
    Ok(ControllerSigningKeys {
        document,
        accepted_device_material,
    })
}

fn controller_station_for_pairing<'a>(
    config: &'a coauth_config::ArkretConfig,
    resolver: &crate::services::station_trust::StationTrustResolver,
    station_id: &arkret_identifiers::DidCoreId,
) -> Result<&'a coauth_config::StationConfig, AppError> {
    config
        .stations
        .iter()
        .find(|station| {
            crate::services::station_trust::effective_audience(station, resolver).as_ref()
                == Some(station_id)
        })
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "controller Station is not configured or its trusted identity is unavailable",
            )
        })
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
    for proof in &event.proofs {
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
) -> Result<arkret_models_collaboration::agent_operations::AgentKeyPairOutcome, AppError> {
    let superseded_event_refs = pairing_superseded_event_refs(&body)?;
    let http_client = depot.http_client()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let request = PrincipalAgentKeyPairCommitRequest::new(
        idempotency_key.to_owned(),
        request_digest.to_owned(),
        station_name.to_owned(),
        body,
    );
    let outcome = crate::services::principal_facade::commit_agent_key_pair_to_station(
        &http_client,
        &arkret_config,
        &key_store,
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

    if outcome.activation_state
        != arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active
    {
        return Ok(outcome);
    }
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
    Ok(outcome)
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
