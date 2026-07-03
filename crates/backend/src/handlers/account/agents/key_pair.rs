//! CKP-0008 §4.5 runtime key pairing (`ck.gate.account.command.pair_agent_key`).
//!
//! `POST /_cokret/gate/account/agent-key-pair`. The agent runtime generated a
//! key pair locally and submits the public key plus a proof-of-possession. This
//! endpoint validates the DID binding + PoP, then writes a durable
//! `agent_key_authorization` row and fans the `ck.agent.key.authorize` event out
//! to soland (the reducer authority) over the same retryable queue mechanism the
//! accountability-grant path uses. coauth is the local PoP / session-issuance
//! authority; soland projects the durable event and clears
//! `effective_after_first_authorized_key` flags.

use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::RepositoryAccess;
use coauth_data::accountability::{AccountabilityGrantFanoutState, AccountabilitySubjectKind};
use coauth_data::agent_key::NewAgentKeyAuthorization;
use coauth_data::audit::AdminOperation;
use cokret_core::identifiers::new_prefixed_uuid7;
use salvo::prelude::*;
use serde::Deserialize;

use sha2::Digest as _;

use super::error_matrix::{AgentAuthRejection, enforce_verification_method_binding};
use super::proof::{ProofSignedFields, canonical_digest, verify_proof_signature};
use super::session_proof::{AGENT_KEY_SCOPE_LIMITED, LIMITED_AGENT_SCOPE_ACTIONS};
use crate::handlers::account::{DepotExt, make_clock, make_rng};
use crate::handlers::admin::CreatedJson;
use crate::handlers::admin::audit_helper::record_service_admin_operation_signed;
use crate::handlers::cokret::{is_allowed_session_grant_audience, service_did_for};
use crate::services::did_binding_proof::normalize_did_for_binding;
use crate::{AppError, CreatedJsonResult};

/// CKP-0008 §4.5 baseline runtime attestation kind. v1 only accepts
/// `self_asserted`; any other kind MUST fail closed.
const RUNTIME_ATTESTATION_SELF_ASSERTED: &str = "self_asserted";

const AGENT_KEY_AUTHORIZE_FANOUT_QUEUE: &str = "soland-agent-key-authorize-fanout";

/// Internal coauth→soland fan-out envelope kind wrapping the spec-typed
/// `ck.agent.key.authorize` payload.
const AGENT_KEY_AUTHORIZE_FANOUT_KIND: &str = "org.cokret.coauth.agent_key_authorize.fanout.v1";

/// Ed25519 public key submitted at pairing (CKP-0008 §4.5 `public_key`).
#[derive(Debug, Clone, Deserialize)]
struct AgentPublicKeyInput {
    key_type: String,
    public_key_multibase: String,
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

/// Strip DID URL `#fragment` and `?query`, returning the bare DID.
fn did_without_fragment_query(did_url: &str) -> &str {
    did_url
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

/// `POST /_cokret/gate/account/agent-key-pair`
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
) -> CreatedJsonResult<cokret_core::AgentKeyPairOutcome> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;

    let body: cokret_core::AgentKeyPairRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let agent_principal_id = normalize_did_for_binding(body.agent_principal_id.as_str())
        .map_err(|error| AppError::bad_request(format!("agent_principal_id invalid: {error}")))?;

    // AUTH-1: fail-closed DID binding BEFORE any crypto runs. The
    // verification_method DID part (fragment/query stripped) MUST be
    // bit-identical to the agent principal.
    let vm_did = did_without_fragment_query(&body.verification_method);
    enforce_verification_method_binding(&body.verification_method, &agent_principal_id)
        .map_err(AgentAuthRejection::into_app_error)?;
    let _ = vm_did;

    let public_key: AgentPublicKeyInput = serde_json::from_value(body.public_key.clone())
        .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;
    if !public_key.key_type.eq_ignore_ascii_case("Ed25519") {
        // v1 pairing accepts Ed25519 runtime keys only; unknown key types fail
        // closed rather than being silently treated as Ed25519.
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    let pop: ProofOfPossessionInput = serde_json::from_value(body.proof_of_possession.clone())
        .map_err(|error| AppError::bad_request(format!("proof_of_possession invalid: {error}")))?;

    // runtime_attestation: v1 baseline accepts only `kind=self_asserted`. Any
    // present-but-unknown kind fails closed (CKP-0008 §4.5 / Non-Goals).
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
    if !is_allowed_session_grant_audience(&url_builder, &cokret_config, &pop.audience) {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    // The PoP MUST bind the request canonical digest (CKP-0008 §4.5). It is an
    // opaque `sha256:<hex>` the client computed over the pairing request body;
    // we re-bind it into the signed-fields so the signature covers it.
    if !pop.request_canonical_digest.starts_with("sha256:") {
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
        &public_key.public_key_multibase,
        &signed_fields,
        &pop.signature,
    )
    .map_err(AgentAuthRejection::into_app_error)?;

    // The accountable controller for this agent: derive from the active
    // accountability grant coauth issued at provisioning. Without one, the key
    // authorization has nothing to be accountable to — fail closed.
    let pairing_request_id = req
        .query::<String>("pairing_request_id")
        .unwrap_or_default();

    let mut rng = make_rng();
    let mut repo = depot.repo().await?;

    let accountable_grants = repo
        .accountability_grant()
        .list_active_for_subject(
            AccountabilitySubjectKind::AgentPrincipalId,
            &agent_principal_id,
        )
        .await?;
    let Some(accountability) = accountable_grants.into_iter().next() else {
        repo.cancel().await.ok();
        return Err(AgentAuthRejection::AccountabilityGrantMissing.into_app_error());
    };
    let controller_did = accountability.controller_did.clone();

    // Mint the durable authorization event id coauth returns and binds the
    // session branch's `agent_key_authorization_ref` against. The `key_id` is
    // the verification method DID URL.
    let authorized_event_id = new_prefixed_uuid7("ck:event:");
    let key_id = body.verification_method.clone();
    let issued_at = now;
    let expires_at = now + chrono::Duration::days(30);

    let service_did = service_did_for(&cokret_config);
    let outcome_event_id = cokret_core::EventId::new(authorized_event_id.clone())
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    // §4.5: the authorized key inherits the controller-approved scope; coauth
    // stores the broadest tier the accountability grant covers and soland's
    // evaluator intersects it down per-resource. v1 baseline tier is `limited`;
    // the fan-out carries the spec-typed object form of that tier.
    let agent_key_scope = limited_agent_key_scope(&pop.audience, &service_did, &cokret_config)?;

    let fanout_payload = build_agent_key_authorize_fanout_payload(
        &authorized_event_id,
        &agent_principal_id,
        &key_id,
        &body.verification_method,
        &public_key.public_key_multibase,
        &controller_did,
        agent_key_scope,
        &pop.audience,
        issued_at,
        expires_at,
        &accountability.accountability_grant_id,
        &pairing_request_id,
        &pop.request_canonical_digest,
        &service_did,
        &cokret_config,
    )?;
    let raw_payload_digest = canonical_digest(&fanout_payload)?;
    let idempotency_key = format!("coauth:agent_key_authorize:{authorized_event_id}");

    repo.agent_key_authorization()
        .add(
            &mut *rng,
            &*clock,
            NewAgentKeyAuthorization {
                authorized_event_id: authorized_event_id.clone(),
                agent_principal_id: agent_principal_id.clone(),
                key_id: key_id.clone(),
                verification_method: body.verification_method.clone(),
                public_key_multibase: public_key.public_key_multibase.clone(),
                accountable_principal_id: controller_did.clone(),
                agent_key_scope: AGENT_KEY_SCOPE_LIMITED.to_owned(),
                audience: vec![pop.audience.clone()],
                issued_at,
                expires_at,
                pairing_request_id: pairing_request_id.clone(),
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
        "controller_did": &controller_did,
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
        cokret_config.audit_signature_fail_closed,
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

    Ok(CreatedJson(cokret_core::AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref: outcome_event_id,
    }))
}

/// Spec-typed `agent_key_scope` object for the v1 `limited` baseline tier:
/// the closed limited action set (shared with the session-proof tier
/// evaluator), scoped to the principal service the pairing audience resolves
/// to (falling back to this coauth deployment's own service DID).
fn limited_agent_key_scope(
    audience: &str,
    service_did: &str,
    cokret_config: &CokretConfig,
) -> Result<cokret_core::AgentKeyScope, AppError> {
    let scoped_service_did = cokret_config
        .principal_servers
        .iter()
        .find(|server| server.audience == audience)
        .and_then(|server| server.did.clone())
        .unwrap_or_else(|| service_did.to_owned());
    let scoped_service_did = cokret_core::Did::new(scoped_service_did)
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    Ok(cokret_core::AgentKeyScope {
        actions: LIMITED_AGENT_SCOPE_ACTIONS
            .iter()
            .map(|action| (*action).to_owned())
            .collect(),
        resources: vec![cokret_core::AgentKeyScopeResource {
            kind: cokret_core::AgentKeyScopeResourceKind::Service,
            realm_id: None,
            r#ref: None,
            operation: None,
            service_did: Some(scoped_service_did),
        }],
        constraints: Vec::new(),
    })
}

/// Build the canonical `ck.agent.key.authorize` fan-out payload for soland.
/// The inner `payload` is the SDK [`cokret_core::AgentKeyAuthorizePayload`]
/// (truth source `event-payload.schema.json#/$defs/agent_key_authorize_payload`);
/// the wrapping envelope is coauth-internal queue metadata.
#[allow(clippy::too_many_arguments)]
fn build_agent_key_authorize_fanout_payload(
    authorized_event_id: &str,
    agent_principal_id: &str,
    key_id: &str,
    verification_method: &str,
    public_key_multibase: &str,
    accountable_principal_id: &str,
    agent_key_scope: cokret_core::AgentKeyScope,
    audience: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accountability_grant_id: &str,
    pairing_request_id: &str,
    request_canonical_digest: &str,
    service_did: &str,
    cokret_config: &CokretConfig,
) -> Result<serde_json::Value, AppError> {
    let principal_servers: Vec<_> = cokret_config
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

    // sha256 digest of the raw Ed25519 public key bytes behind
    // `verification_method` (spec `public_key_digest` hash form).
    let public_key_bytes = cokret_core::multibase::decode_ed25519_multibase(public_key_multibase)
        .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;
    let public_key_digest = cokret_core::Hash::new(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(public_key_bytes))
    ))
    .map_err(|err| AppError::internal_box(Box::new(err)))?;

    // The client-supplied pairing digest was prefix-checked earlier; the SDK
    // `Hash` constructor enforces the full `sha256:<64 hex>` shape fail-closed.
    let request_canonical_digest = cokret_core::Hash::new(request_canonical_digest.to_owned())
        .map_err(|_| AgentAuthRejection::ProofInvalid.into_app_error())?;

    // SDK drift: `AgentKeyAuthorizePayload.verification_method` is typed `Did`,
    // but the spec `$defs/verification_method` REQUIRES a `#fragment` DID URL,
    // which `Did` rejects. Until the SDK grows a DID-URL type we construct the
    // typed payload with the bare agent DID and patch the serialized field to
    // the real verification-method DID URL below.
    let payload = cokret_core::AgentKeyAuthorizePayload {
        agent_principal_id: cokret_core::Did::new(agent_principal_id.to_owned())
            .map_err(|err| AppError::internal_box(Box::new(err)))?,
        key_id: key_id.to_owned(),
        verification_method: cokret_core::Did::new(agent_principal_id.to_owned())
            .map_err(|err| AppError::internal_box(Box::new(err)))?,
        public_key_digest: Some(public_key_digest),
        accountable_principal_id: cokret_core::Did::new(accountable_principal_id.to_owned())
            .map_err(|err| AppError::internal_box(Box::new(err)))?,
        agent_key_scope,
        audience: vec![audience.to_owned()],
        issued_at,
        expires_at,
        // The controller-accepted accountability grant (`ck:grant:<uuid7>`) is
        // the durable evidence that authorized this key; the raw pairing
        // request id travels on the envelope for traceability only.
        approval_evidence: cokret_core::AgentKeyApprovalEvidence {
            kind: cokret_core::AgentKeyApprovalEvidenceKind::CapabilityGrant,
            r#ref: accountability_grant_id.to_owned(),
            request_canonical_digest: Some(request_canonical_digest),
            approved_by: Some(
                cokret_core::Did::new(accountable_principal_id.to_owned())
                    .map_err(|err| AppError::internal_box(Box::new(err)))?,
            ),
        },
        revocation_check_ref: None,
        runtime_attestation: Some(cokret_core::AgentKeyAuthorizePayloadRuntimeAttestation {
            kind: cokret_core::AgentKeyRuntimeAttestationKind::SelfAsserted,
            software: None,
            version: None,
            attestation_digest: None,
            evidence_ref: None,
        }),
    };
    let mut payload =
        serde_json::to_value(&payload).map_err(|err| AppError::internal_box(Box::new(err)))?;
    // See the SDK-drift note above: restore the spec-required DID URL form.
    payload["verification_method"] = serde_json::Value::String(verification_method.to_owned());

    Ok(serde_json::json!({
        "kind": AGENT_KEY_AUTHORIZE_FANOUT_KIND,
        "issuer_service_did": service_did,
        "authorized_event_id": authorized_event_id,
        "pairing_request_id": pairing_request_id,
        "payload": payload,
        "principal_servers": principal_servers,
    }))
}
