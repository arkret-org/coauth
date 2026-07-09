//! CKP-0008 §4.5 runtime key pairing (`ck.gate.account.command.pair_agent_key`).
//!
//! `POST /_arkret/gate/account/agent-key-pair`. The agent runtime generated a
//! key pair locally and submits the public key plus a proof-of-possession. The
//! controller supplies the signed `ck.agent.key.authorize` event; coauth only
//! validates the request binding, persists the accepted authorization for
//! `agent_key_proof`, and queues the signed event for soland projection.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::accountability::{AccountabilityGrantFanoutState, AccountabilitySubjectKind};
use coauth_data::agent_key::NewAgentKeyAuthorization;
use coauth_data::audit::AdminOperation;
use coauth_data::{BoxRepository, RepositoryAccess, UrlBuilder};
use coauth_keystore::Keystore;
use arkret_signatures::proof::{PublicKeyMaterial, verify_eddsa_detached_jws_proof};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::Value;

use super::error_matrix::{AgentAuthRejection, enforce_verification_method_binding};
use super::proof::{ProofSignedFields, canonical_digest, verify_proof_signature};
use crate::handlers::account::{DepotExt, make_clock, make_rng};
use crate::handlers::admin::CreatedJson;
use crate::handlers::admin::audit_helper::record_service_admin_operation_signed;
use crate::handlers::arkret::{
    VerificationMethod, is_allowed_session_grant_audience, service_did_for,
};
use crate::services::did_binding_proof::normalize_did_for_binding;
use crate::services::did_resolver::DidResolverService;
use crate::{AppError, CreatedJsonResult};

/// CKP-0008 §4.5 baseline runtime attestation kind. v1 only accepts
/// `self_asserted`; any other kind MUST fail closed.
const RUNTIME_ATTESTATION_SELF_ASSERTED: &str = "self_asserted";

const AGENT_KEY_AUTHORIZE_FANOUT_QUEUE: &str = "soland-agent-key-authorize-fanout";

/// Internal coauth→soland fan-out envelope kind wrapping the controller-signed
/// `ck.agent.key.authorize` event.
const AGENT_KEY_AUTHORIZE_FANOUT_KIND: &str = "org.arkret.coauth.agent_key_authorize.fanout.v1";

/// CKP-0008 agent runtime authorizations are short-lived; session grants minted
/// from them are capped at 15 minutes, so the root key authorization uses the
/// same hard ceiling rather than accepting effectively permanent keys.
const AGENT_KEY_AUTHORIZATION_MAX_TTL: chrono::Duration = chrono::Duration::minutes(15);

#[derive(Debug)]
struct ValidatedRuntimePublicKey {
    public_key: Value,
    verification_public_key: String,
}

/// Proof-of-possession over the pairing request (CKP-0008 §4.5
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

/// Optional runtime attestation (CKP-0008 §4.5 `runtime_attestation`). Only the
/// `kind` is interpreted at v1 baseline; an unknown kind fails closed.
#[derive(Debug, Clone, Deserialize)]
struct RuntimeAttestationInput {
    kind: String,
}

/// `POST /_arkret/gate/account/agent-key-pair`
/// (`ck.gate.account.command.pair_agent_key`).
///
/// Validates the runtime key pairing proof-of-possession and, on success,
/// records a durable agent key authorization and queues the
/// `ck.agent.key.authorize` soland fan-out. Returns the SDK
/// [`AgentKeyPairOutcome`] carrying the minted authorization event ref.
#[handler]
#[tracing::instrument(name = "handler.account.agents.agent_key_pair", skip_all)]
pub async fn post_agent_key_pair(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<arkret_core::AgentKeyPairOutcome> {
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let did_resolver = depot.did_resolver_service()?;

    let body: arkret_core::AgentKeyPairRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let agent_principal_id = normalize_did_for_binding(body.agent_principal_id.as_str())
        .map_err(|error| AppError::bad_request(format!("agent_principal_id invalid: {error}")))?;
    ensure_body_pairing_request_id_present(&body.pairing_request_id)?;

    enforce_verification_method_binding(&body.verification_method, &agent_principal_id)
        .map_err(AgentAuthRejection::into_app_error)?;

    let public_key = validate_runtime_public_key(&body.public_key, &body.verification_method)?;

    let pop: ProofOfPossessionInput = serde_json::from_value(body.proof_of_possession.clone())
        .map_err(|error| AppError::bad_request(format!("proof_of_possession invalid: {error}")))?;
    if pop.challenge != body.pairing_request_id {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    // runtime_attestation: v1 baseline accepts only `kind=self_asserted`. Any
    // present-but-unknown kind fails closed.
    if let Some(attestation_value) = body.runtime_attestation.clone() {
        let attestation: RuntimeAttestationInput = serde_json::from_value(attestation_value)
            .map_err(|error| {
                AppError::bad_request(format!("runtime_attestation invalid: {error}"))
            })?;
        if attestation.kind != RUNTIME_ATTESTATION_SELF_ASSERTED {
            return Err(AppError::bad_request(format!(
                "runtime_attestation.kind {:?} is not supported (v1 baseline is self_asserted)",
                attestation.kind
            )));
        }
    }

    let clock = make_clock();
    let now = clock.now();

    // Expiry: a stale pairing PoP is rejected as `pairing_request_expired`.
    if pop.expires_at <= now {
        return Err(AgentAuthRejection::PairingRequestExpired.into_app_error());
    }

    // Audience MUST be this service (the coauth issuer audience or a configured
    // principal-server audience).
    if !is_allowed_session_grant_audience(&url_builder, &arkret_config, &pop.audience) {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    // The PoP MUST bind the request canonical digest (CKP-0008 §4.5). It is an
    // opaque `sha256:<hex>` the client computed over the pairing request body;
    // we re-bind it into the signed-fields so the signature covers it.
    if !pop.request_canonical_digest.starts_with("sha256:") {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }
    let agent_id = arkret_core::Did::new(agent_principal_id.clone())
        .map_err(|error| AppError::bad_request(format!("agent_principal_id invalid: {error}")))?;
    let expected_pop_digest = arkret::agent::agent_key_pair_proof_request_binding_digest(
        &body.pairing_request_id,
        &agent_id,
        &body.verification_method,
        &body.public_key,
        body.runtime_attestation.as_ref(),
    )
    .map_err(|error| {
        AppError::bad_request(format!(
            "proof_of_possession request binding failed: {error}"
        ))
    })?;
    if pop.request_canonical_digest != expected_pop_digest.as_str() {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
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
        runtime_public_key_digest(&body.public_key, &body.verification_method)?;
    let authorize_event = validate_controller_authorize_event(
        &body.authorize_event,
        &agent_principal_id,
        &body.verification_method,
        &runtime_public_key_digest,
        &body.pairing_request_id,
        &pop.audience,
        now,
    )?;

    if let Err(error) = verify_authorize_event_controller_signature(
        &body.authorize_event,
        &authorize_event.controller_did,
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
        return Err(error);
    }

    let accountable_grants = repo
        .accountability_grant()
        .list_active_for_subject(
            AccountabilitySubjectKind::AgentPrincipalId,
            &agent_principal_id,
        )
        .await?;
    if !accountable_grants
        .iter()
        .any(|grant| grant.controller_did == authorize_event.controller_did)
    {
        repo.cancel().await.ok();
        return Err(AgentAuthRejection::AccountabilityGrantMissing.into_app_error());
    };

    let mut rng = make_rng();
    let key_id = authorize_event.key_id.clone();
    let authorized_event_id = authorize_event.event_id.clone();
    let issued_at = authorize_event.issued_at;
    let expires_at = authorize_event.expires_at;

    let service_did = service_did_for(&arkret_config);
    let outcome_event_id = arkret_core::EventId::new(authorized_event_id.clone())
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    let fanout_payload = build_agent_key_authorize_fanout_payload(
        &authorized_event_id,
        &body.pairing_request_id,
        &body.authorize_event,
        &service_did,
        &arkret_config,
    );
    let raw_payload_digest = canonical_digest(&fanout_payload)?;
    let idempotency_key = format!("coauth:agent_key_authorize:{authorized_event_id}");
    let agent_key_scope = serde_json::to_string(authorize_event.agent_key_scope)
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    repo.agent_key_authorization()
        .add(
            &mut *rng,
            &*clock,
            NewAgentKeyAuthorization {
                authorized_event_id: authorized_event_id.clone(),
                agent_principal_id: agent_principal_id.clone(),
                key_id: key_id.clone(),
                verification_method: body.verification_method.clone(),
                public_key: public_key.public_key.clone(),
                accountable_principal_id: authorize_event.controller_did.clone(),
                agent_key_scope,
                audience: vec![pop.audience.clone()],
                issued_at,
                expires_at,
                pairing_request_id: body.pairing_request_id.clone(),
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

    let audit_details = serde_json::json!({
        "actor": { "kind": "service", "service_did": &service_did },
        "operation": "agent_key_authorize_issued",
        "authorized_event_id": &authorized_event_id,
        "agent_principal_id": &agent_principal_id,
        "controller_did": &authorize_event.controller_did,
        "verification_method": &body.verification_method,
        "audience": &pop.audience,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "raw_payload_digest": &raw_payload_digest,
        "soland_fanout": {
            "state": AccountabilityGrantFanoutState::Queued,
            "idempotency_key": &idempotency_key,
            "queue": AGENT_KEY_AUTHORIZE_FANOUT_QUEUE,
            "next_retry_at": issued_at,
        }
    });
    let key_store = depot.key_store()?;
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
        .schedule(
            &mut *rng,
            &*clock,
            AGENT_KEY_AUTHORIZE_FANOUT_QUEUE,
            fanout_payload,
            serde_json::json!({
                "idempotency_key": idempotency_key,
                "authorized_event_id": authorized_event_id,
                "raw_payload_digest": raw_payload_digest,
                "next_retry_at": issued_at,
                "attempt": 0,
            }),
        )
        .await?;
    repo.save().await?;

    Ok(CreatedJson(arkret_core::AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref: outcome_event_id,
    }))
}

#[derive(Debug)]
struct ValidatedAuthorizeEvent<'a> {
    event_id: String,
    controller_did: String,
    key_id: String,
    agent_key_scope: &'a Value,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

fn validate_runtime_public_key(
    public_key: &Value,
    verification_method: &str,
) -> Result<ValidatedRuntimePublicKey, AppError> {
    let key: arkret_core::PublicKey = serde_json::from_value(public_key.clone())
        .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;
    if key.kty != "OKP" {
        return Err(AppError::bad_request("public_key.kty must be OKP"));
    }
    if key.kid != verification_method {
        return Err(AppError::bad_request(
            "public_key.kid must match verification_method",
        ));
    }
    if key.alg != "Ed25519" && key.alg != "EdDSA" {
        return Err(AppError::bad_request(
            "public_key.alg must be Ed25519 or EdDSA",
        ));
    }
    let raw = Base64UrlUnpadded::decode_vec(&key.key)
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
    arkret::agent::agent_runtime_public_key_digest(public_key)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|error| AppError::bad_request(format!("public_key is invalid: {error}")))
}

fn validate_controller_authorize_event<'a>(
    envelope: &'a Value,
    agent_principal_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    pairing_request_id: &str,
    audience: &str,
    now: DateTime<Utc>,
) -> Result<ValidatedAuthorizeEvent<'a>, AppError> {
    if !envelope.is_object() {
        return Err(AppError::bad_request(
            "authorize_event must be a controller-signed event object",
        ));
    }
    if envelope.get("kind").and_then(Value::as_str) != Some("ck.agent.key.authorize") {
        return Err(AppError::bad_request(
            "authorize_event.kind must be ck.agent.key.authorize",
        ));
    }

    let event_id = envelope
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("authorize_event.event_id is required"))?;
    arkret_core::EventId::new(event_id.to_owned())
        .map_err(|err| AppError::bad_request(format!("authorize_event.event_id invalid: {err}")))?;
    let controller_did = envelope
        .get("actor_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("authorize_event.actor_id is required"))?;
    arkret_core::Did::new(controller_did.to_owned())
        .map_err(|err| AppError::bad_request(format!("authorize_event.actor_id invalid: {err}")))?;
    ensure_authorize_event_has_controller_signature(envelope, controller_did)?;

    let payload = envelope
        .get("payload")
        .ok_or_else(|| AppError::bad_request("authorize_event.payload is required"))?;
    if payload.get("agent_principal_id").and_then(Value::as_str) != Some(agent_principal_id) {
        return Err(AppError::bad_request(
            "authorize_event.payload.agent_principal_id must match the request",
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
        != Some(controller_did)
    {
        return Err(AppError::forbidden(
            "authorize_event.payload.accountable_principal_id must match actor_id",
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
    let expires_at = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .ok_or_else(|| {
            AppError::bad_request("authorize_event.payload.expires_at must be rfc3339")
        })?;
    if expires_at <= now {
        return Err(AgentAuthRejection::PairingRequestExpired.into_app_error());
    }
    let authorization_lifetime = expires_at.signed_duration_since(issued_at);
    if authorization_lifetime <= chrono::Duration::zero()
        || authorization_lifetime > AGENT_KEY_AUTHORIZATION_MAX_TTL
    {
        return Err(AppError::bad_request(format!(
            "authorize_event.payload.expires_at must be after issued_at and within {} seconds",
            AGENT_KEY_AUTHORIZATION_MAX_TTL.num_seconds()
        )));
    }
    let approval = payload.get("approval_evidence").ok_or_else(|| {
        AppError::bad_request("authorize_event.payload.approval_evidence is required")
    })?;
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
    if let Some(approved_by) = approval.get("approved_by").and_then(Value::as_str)
        && approved_by != controller_did
    {
        return Err(AppError::forbidden(
            "authorize_event.payload.approval_evidence.approved_by must match actor_id",
        ));
    }

    Ok(ValidatedAuthorizeEvent {
        event_id: event_id.to_owned(),
        controller_did: controller_did.to_owned(),
        key_id: key_id.to_owned(),
        agent_key_scope,
        issued_at,
        expires_at,
    })
}

fn ensure_body_pairing_request_id_present(pairing_request_id: &str) -> Result<(), AppError> {
    if pairing_request_id.trim().is_empty() {
        return Err(AppError::bad_request("pairing_request_id is required"));
    }
    Ok(())
}

fn ensure_authorize_event_has_controller_signature(
    envelope: &Value,
    controller_did: &str,
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
                verification_method_controller(verification_method) == controller_did
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
    controller_did: &str,
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &CokretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
) -> Result<(), AppError> {
    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            arkret_config,
            key_store,
            repo,
            controller_did,
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
        controller_did,
        &resolution.document.verification_method,
    )
}

fn verify_authorize_event_controller_signature_with_methods(
    envelope: &Value,
    controller_did: &str,
    verification_methods: &[VerificationMethod],
) -> Result<(), AppError> {
    let event: arkret_core::Event = serde_json::from_value(envelope.clone()).map_err(|error| {
        AppError::bad_request(format!(
            "authorize_event must be a complete signed Event envelope: {error}"
        ))
    })?;
    if event.actor_id.as_str() != controller_did {
        return Err(AppError::bad_request(
            "authorize_event.actor_id must match the resolved controller DID",
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

    let mut saw_controller_proof = false;
    for proof in &event.proofs {
        if verification_method_controller(&proof.verification_method) != controller_did {
            continue;
        }
        saw_controller_proof = true;
        let Some(method) = verification_methods
            .iter()
            .find(|method| method.id == proof.verification_method)
        else {
            continue;
        };
        let jwk_value = serde_json::to_value(&method.public_key_jwk).map_err(|error| {
            AppError::bad_request(format!("authorize_event controller JWK invalid: {error}"))
        })?;
        let public_key = PublicKeyMaterial::Jwk { value: jwk_value };
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

fn verification_method_controller(verification_method: &str) -> &str {
    verification_method
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
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

/// Build the canonical `ck.agent.key.authorize` fan-out payload for soland.
/// The wrapping envelope is coauth-internal queue metadata.
fn build_agent_key_authorize_fanout_payload(
    authorized_event_id: &str,
    pairing_request_id: &str,
    authorize_event: &Value,
    service_did: &str,
    arkret_config: &CokretConfig,
) -> serde_json::Value {
    let principal_servers: Vec<_> = arkret_config
        .principal_servers
        .iter()
        .map(|server| {
            serde_json::json!({
                "name": server.name.as_str(),
                "audience": server.audience.as_str(),
                "endpoint": server.endpoint.as_str(),
                "did": server.did.as_deref(),
            })
        })
        .collect();

    serde_json::json!({
        "kind": AGENT_KEY_AUTHORIZE_FANOUT_KIND,
        "issuer_service_did": service_did,
        "authorized_event_id": authorized_event_id,
        "pairing_request_id": pairing_request_id,
        "authorize_event": authorize_event,
        "principal_servers": principal_servers,
    })
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

    fn valid_authorize_event(pairing_request_id: &str) -> Value {
        json!({
            "event_id": "ak:event:01999999-0000-7000-8000-000000000001",
            "kind": "ck.agent.key.authorize",
            "realm_id": "ak:realm:01999999-0000-7000-8000-000000000010",
            "actor_id": CONTROLLER,
            "actor_seq": 1,
            "created_at": "2026-07-06T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "agent_principal_id": AGENT,
                "key_id": "runtime-key-1",
                "verification_method": VM,
                "public_key_digest": PUBLIC_KEY_DIGEST,
                "accountable_principal_id": CONTROLLER,
                "agent_key_scope": {
                    "actions": [
                        "ck.self.events.stream.subscribe",
                        "ck.event.read"
                    ],
                    "resources": []
                },
                "audience": [AUDIENCE],
                "issued_at": "2026-07-06T00:00:00Z",
                "expires_at": "2026-07-06T00:10:00Z",
                "approval_evidence": {
                    "kind": "approval_event",
                    "ref": "ak:event:01999999-0000-7000-8000-000000000099",
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
            test_now(),
        )
        .expect_err("authorize_event pairing id mismatch must reject");

        assert!(err.message().contains("pairing_request_id"));
    }

    #[test]
    fn authorize_event_rejects_unbounded_authorization_lifetime() {
        let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
        event["payload"]["expires_at"] = json!("2026-07-06T00:16:00Z");

        let err = validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            PUBLIC_KEY_DIGEST,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            test_now(),
        )
        .expect_err("agent key authorization lifetime must be bounded");

        assert!(err.message().contains("within 900 seconds"));
    }

    #[test]
    fn authorize_event_rejects_fake_controller_jws() {
        let event = full_fake_signed_authorize_event();
        let method = controller_verification_method();

        let err = verify_authorize_event_controller_signature_with_methods(
            &event,
            CONTROLLER,
            std::slice::from_ref(&method),
        )
        .expect_err("fake detached JWS must fail closed");

        assert_eq!(err.status(), http::StatusCode::UNAUTHORIZED);
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
            public_key_jwk: serde_json::from_value(json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
            }))
            .unwrap(),
        }
    }
}
