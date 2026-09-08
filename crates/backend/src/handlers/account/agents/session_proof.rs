//! AKP-0008 §4.6 agent runtime authentication (`agent_key_proof` branch of
//! `ak.gate.account.command.issue_session_grant.v1`).
//!
//! This is the independent validator the session-grant endpoint calls; it MUST
//! NOT fall back to the password / OIDC / passkey validators.

use std::collections::BTreeSet;

use arkret_identifiers::{DidCoreId, new_prefixed_uuid7};
use coauth_config::ArkretConfig;
use coauth_data::RepositoryAccess;
use coauth_data::agent_key::NewAgentSessionProofReplay;
use serde::Deserialize;
use serde_json::Value;

use super::error_matrix::{AgentAuthRejection, enforce_verification_method_binding};
use super::proof::{runtime_public_key_material_from_spec, verify_proof_signature_bytes};
use crate::handlers::arkret::is_allowed_session_grant_audience;

/// Replay grace window appended to the proof `expires_at` (AKP-0008 §4.6:
/// "at least covers the proof expiry plus a replay grace window"). A consumed
/// challenge stays in the replay table until `proof.expires_at + this` so a
/// replay landing right after expiry is still rejected.
const AGENT_PROOF_REPLAY_GRACE: chrono::Duration = chrono::Duration::minutes(5);
const AGENT_REFRESH_PROOF_MAX_WINDOW: chrono::Duration = chrono::Duration::minutes(5);
/// Rebuild the SDK refresh-intent digest from already-typed coordinates.
///
/// The inputs stay in their protocol types the whole way: the SDK signature is
/// `(&DidCoreId, &DeviceId, &DidCoreId, &DidUrl)`, so a caller that hands over a
/// DID URL where a `did_core_id` belongs is a compile error rather than a
/// runtime `ProofInvalid`.
fn agent_session_refresh_request_digest(
    prior_grant_jwt: &str,
    principal_id: &DidCoreId,
    device_id: &arkret_identifiers::DeviceId,
    audience: &DidCoreId,
    verification_method: &arkret_wire::DidUrl,
) -> Result<arkret_identifiers::Hash, AgentAuthRejection> {
    arkret_models_collaboration::session_grant_bodies::agent_session_refresh_request_digest(
        prior_grant_jwt,
        principal_id,
        device_id,
        audience,
        verification_method,
    )
    .map_err(|_| AgentAuthRejection::ProofInvalid)
}

/// Spec ceiling on the default agent session TTL (AKP-0008 §4.6 / key-management
/// §3.6.1: default SHOULD be ≤ 15 minutes). coauth caps the agent branch to
/// this regardless of the (human-oriented) `arkret.session_grant_ttl`.
pub const AGENT_SESSION_MAX_TTL: chrono::Duration = chrono::Duration::minutes(15);

/// Outcome of validating an `agent_key_proof` session-grant request.
pub struct AgentSessionAuthorization {
    /// Agent principal DID the proof authenticated.
    pub agent_id: arkret_identifiers::DidCoreId,
    /// Controller principal DID accountable for the agent. Lifecycle payloads
    /// derive controller authority from the containing Event instead of
    /// carrying a duplicate controller field.
    pub controller_principal_id: arkret_identifiers::DidCoreId,
    /// Effective granted scope. Service-surface tokens are intersected with the
    /// authorized key scope and policy/resource constraints; content capability
    /// tokens are additionally intersected with active capability grants.
    pub granted_scope: Vec<String>,
    /// Materialized `scope_details` overlay baked into the session-grant JWT
    /// payload (canonical resource constraints + optional participation
    /// entries). This is the JWT-internal shape soland enforces against; it is
    /// not an unsigned field in the `SessionGrantOutcome` wire DTO.
    pub scope_details: serde_json::Map<String, serde_json::Value>,
    /// Capped agent session TTL (≤ 15 min).
    pub ttl: chrono::Duration,
}

/// Validate the runtime-key proof used to rotate an existing Agent session.
/// Unlike initial issuance, refresh preserves the already-materialized scope
/// and therefore authenticates the current authorization rather than accepting
/// a new scope request.
pub async fn validate_agent_session_refresh_proof<R>(
    repo: &mut R,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    authoritative_agent: &arkret_models_collaboration::agent_operations::AgentView,
    prior_claims: &arkret_models_identity::SignedSessionGrantClaims,
    prior_grant_jwt: &str,
    device_id: &arkret_identifiers::DeviceId,
    proof: &arkret_models_collaboration::session_grant_bodies::AgentSessionRefreshProof,
) -> Result<coauth_data::agent_key::AgentKeyAuthorization, AgentSessionProofError>
where
    R: RepositoryAccess + ?Sized,
{
    use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};

    let request_digest = &proof.request_canonical_digest;
    let proof_audience = &proof.audience_id;
    let issued_at = proof.issued_at;
    let expires_at = proof.expires_at;
    let signature = Some(proof.signature.trim())
        .filter(|value| !value.is_empty())
        .ok_or(AgentAuthRejection::ProofInvalid)?;
    let verification_method = &proof.verification_method;
    let now = clock.now();
    if expires_at <= issued_at
        || expires_at - issued_at > AGENT_REFRESH_PROOF_MAX_WINDOW
        || issued_at > now + chrono::Duration::seconds(30)
        || now >= expires_at
    {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if proof_audience.as_str() != prior_claims.audience_id.as_str()
        || prior_claims.proof_kind
            != Some(arkret_models_identity::SessionGrantProofKind::AgentKeyProof)
    {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    let authorization_ref = prior_claims
        .scope_details
        .as_ref()
        .and_then(|details| details.get("agent_key_authorization_ref"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(AgentAuthRejection::ProofInvalid)?;
    let authorization = repo
        .agent_key_authorization()
        .lookup_by_event_id(authorization_ref)
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?
        .ok_or(AgentAuthRejection::ProofInvalid)?;
    validate_agent_key_authorization_binding(
        &authorization,
        now,
        prior_claims.account_id.principal_id.as_str(),
        verification_method.as_str(),
        proof_audience.as_str(),
    )?;
    validate_authoritative_agent_session_evidence(
        &authorization,
        authoritative_agent,
        &prior_claims.scopes,
    )?;

    let expected_digest = agent_session_refresh_request_digest(
        prior_grant_jwt,
        &prior_claims.account_id.principal_id,
        device_id,
        proof_audience,
        verification_method,
    )?;
    if *request_digest != expected_digest {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    let message = proof
        .canonical_signing_bytes()
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let public_key = runtime_public_key_material_from_spec(
        &authorization.public_key,
        verification_method.as_str(),
    )?;
    if !verify_detached_ed25519_signature(
        &PublicKeyMaterial::Ed25519Multibase { value: public_key },
        &message,
        signature,
    ) {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    let won = repo
        .agent_key_authorization()
        .consume_proof_challenge(
            rng,
            clock,
            NewAgentSessionProofReplay {
                agent_id: prior_claims.account_id.principal_id.to_string(),
                verification_method: verification_method.to_string(),
                challenge: request_digest.to_string(),
                nonce: request_digest.to_string(),
                request_canonical_digest: request_digest.to_string(),
                audience_id: proof_audience.to_string(),
                proof_expires_at: expires_at,
                prune_after: expires_at + AGENT_PROOF_REPLAY_GRACE,
            },
        )
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    if !won {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    Ok(authorization)
}

/// Either a fail-closed wire rejection or a structured human-approval request.
pub enum AgentSessionProofError {
    /// Canonical fail-closed rejection (proof_invalid / agent_paused / …).
    Rejection(AgentAuthRejection),
    /// `claim_required` / `human_approval_required` structured error.
    HumanApprovalRequired(arkret_wire::AgentHumanApprovalProblem),
}

impl From<AgentAuthRejection> for AgentSessionProofError {
    fn from(value: AgentAuthRejection) -> Self {
        Self::Rejection(value)
    }
}

/// `agent_scope_request` overlay (AKP-0008 §4.6). `participation[]` is the
/// participation-aware extension; an `act_on_behalf` selection routes to the
/// human-approval path (act-on-behalf is default-disabled and requires fresh
/// controller approval, §4.10).
#[derive(Debug, Clone, Default, Deserialize)]
struct AgentScopeRequestInput {
    #[serde(default)]
    realm_ids: Vec<String>,
    #[serde(default)]
    strand_ids: Vec<String>,
    #[serde(default)]
    track_names: Vec<String>,
    #[serde(default)]
    participation:
        Vec<arkret_models_collaboration::governance::agent_participation::AgentParticipationEntry>,
}

/// Validate an `agent_key_proof` session-grant request. On success returns the
/// resolved scope material the caller mints the session from.
///
/// `repo` is borrowed for the active-key lookup + replay consumption;
/// `controller_status` reports whether the accountable controller is
/// deactivated/suspended (resolved by the caller from the local user record or
/// soland introspection) so a deactivated controller fails closed.
pub async fn validate_agent_session_proof(
    repo: &mut coauth_data::BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    url_builder: &coauth_data::UrlBuilder,
    arkret_config: &ArkretConfig,
    authoritative_agent: &arkret_models_collaboration::agent_operations::AgentView,
    body: &arkret_models_collaboration::session_grant_bodies::AgentSessionGrantRequest,
) -> Result<AgentSessionAuthorization, AgentSessionProofError> {
    let now = clock.now();
    let proof = &body.proof;

    let agent_id = body.principal_id.as_str();

    // `proof.verification_method` MUST be present and its DID part MUST equal
    // the agent principal (AUTH-1, fail closed before crypto).
    let verification_method = proof.verification_method.as_str();
    if let Err(error) = enforce_verification_method_binding(verification_method, agent_id) {
        tracing::warn!(
            agent_id,
            verification_method,
            "agent_key_proof rejected: verification method principal mismatch"
        );
        return Err(error.into());
    }
    // expiry / audience.
    let expires_at = proof.expires_at;
    if expires_at <= now {
        tracing::warn!(agent_id, verification_method, %expires_at, %now, "agent_key_proof rejected: proof expired");
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !is_allowed_session_grant_audience(
        url_builder,
        arkret_config,
        crate::services::station_trust::shared(),
        proof.audience_id.as_str(),
    ) {
        tracing::warn!(agent_id, verification_method, audience_id = %proof.audience_id, "agent_key_proof rejected: audience is not configured");
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !proof
        .request_canonical_digest
        .as_str()
        .starts_with("sha256:")
    {
        tracing::warn!(agent_id, verification_method, request_canonical_digest = %proof.request_canonical_digest, "agent_key_proof rejected: malformed request digest");
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    let request_digest = canonical_session_grant_request_digest_without_signature(body)?;
    if request_digest != proof.request_canonical_digest.as_str() {
        tracing::warn!(
            agent_id,
            verification_method,
            expected_request_digest = %request_digest,
            presented_request_digest = %proof.request_canonical_digest,
            "agent_key_proof rejected: request canonical digest mismatch"
        );
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    let nonce = proof.nonce.trim();
    if nonce.is_empty() {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    // The key MUST be authorized by an accepted, unrevoked (and unexpired,
    // when it declares an `expires_at`)
    // `ak.agent.key.authorize`. Resolve it by the request's
    // `agent_key_authorization_ref` (the content-bound authorize Event id).
    let authorization_ref = body.agent_key_authorization_ref.as_str();
    let authorization = repo
        .agent_key_authorization()
        .lookup_by_event_id(authorization_ref)
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?
        .ok_or_else(|| {
            tracing::warn!(
                agent_id,
                verification_method,
                authorization_ref,
                "agent_key_proof rejected: authorization event is absent from account authority"
            );
            AgentAuthRejection::ProofInvalid
        })?;

    if let Err(error) = validate_agent_key_authorization_binding(
        &authorization,
        now,
        agent_id,
        verification_method,
        proof.audience_id.as_str(),
    ) {
        tracing::warn!(agent_id, verification_method, authorization_ref, audience_id = %proof.audience_id, "agent_key_proof rejected: authorization binding mismatch");
        return Err(error.into());
    }
    validate_authoritative_agent_session_evidence(
        &authorization,
        authoritative_agent,
        &body.requested_scope,
    )?;
    // Verify the SDK-owned closed proof transcript directly. Reconstructing a
    // parallel shape here previously omitted `proof_kind`, so conforming
    // clients and this verifier signed different canonical bytes.
    let signed_bytes = proof
        .canonical_signing_bytes()
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let verification_public_key =
        runtime_public_key_material_from_spec(&authorization.public_key, verification_method)?;
    if let Err(error) =
        verify_proof_signature_bytes(&verification_public_key, &signed_bytes, &proof.signature)
    {
        tracing::warn!(
            agent_id,
            verification_method,
            authorization_ref,
            request_canonical_digest = %proof.request_canonical_digest,
            "agent_key_proof rejected: detached runtime signature mismatch"
        );
        return Err(error.into());
    }
    tracing::debug!(
        agent_id,
        verification_method,
        authorization_ref,
        "agent_key_proof debug: detached runtime signature accepted"
    );

    // Replay defense: consume the challenge exactly once. A replayed challenge
    // (or one already consumed within the grace window) fails closed.
    let prune_after = expires_at + AGENT_PROOF_REPLAY_GRACE;
    let won = repo
        .agent_key_authorization()
        .consume_proof_challenge(
            rng,
            clock,
            NewAgentSessionProofReplay {
                agent_id: agent_id.to_owned(),
                verification_method: verification_method.to_owned(),
                challenge: proof.challenge.clone(),
                nonce: nonce.to_owned(),
                request_canonical_digest: proof.request_canonical_digest.as_str().to_owned(),
                audience_id: proof.audience_id.to_string(),
                proof_expires_at: expires_at,
                prune_after,
            },
        )
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    if !won {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    // Parse the `agent_scope_request` overlay. An `act_on_behalf` participation
    // selection routes to the human-approval path (§4.10).
    let scope_request = AgentScopeRequestInput {
        realm_ids: body
            .agent_scope_request
            .realm_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
        strand_ids: body
            .agent_scope_request
            .strand_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
        track_names: body
            .agent_scope_request
            .track_names
            .iter()
            .map(ToString::to_string)
            .collect(),
        participation: Vec::new(),
    };

    let requests_act_on_behalf = scope_request
        .participation
        .iter()
        .any(|entry| entry.selection.act_on_behalf);
    if requests_act_on_behalf {
        // Opaque UUIDv7 artifact id (AKP-0008 §4.6); the controller resolves it
        // out-of-band, the agent runtime never renders a UI for it.
        let approval_request_id = new_prefixed_uuid7("");
        let details = arkret_wire::AgentHumanApprovalProblem::new(approval_request_id)
            .map_err(|_| AgentAuthRejection::ProofInvalid)?;
        return Err(AgentSessionProofError::HumanApprovalRequired(details));
    }

    let controller_principal_id = authorization.accountable_principal_id.clone();
    // The controller-authored accountability Event is validated by the
    // authoritative Agent projection. It is not a Realm capability grant and
    // therefore contributes no content actions or resource selectors here.
    let capability_scope = AgentSessionCapabilityScope::default();

    let policy_snapshot = repo
        .policy_data()
        .get()
        .await
        .map_err(|_| AgentAuthRejection::PolicyUnavailable)?;
    let mut realm_policy = policy_snapshot
        .as_ref()
        .and_then(|snapshot| AgentSessionRealmPolicy::from_policy_data(snapshot.data.as_json()));
    if let (Some(snapshot), Some(policy)) = (policy_snapshot.as_ref(), realm_policy.as_mut()) {
        policy.policy_refs.insert(snapshot.id.to_string());
    }
    let policy_data = policy_snapshot
        .as_ref()
        .map(|snapshot| snapshot.data.as_json());

    let effective_scope = intersect_agent_session_scope(
        authorization.agent_key_scope.as_str(),
        &body.requested_scope,
        &scope_request,
        &capability_scope,
        realm_policy.as_ref(),
        policy_data,
        agent_id,
    )
    .inspect_err(|error| {
        tracing::warn!(
            agent_id,
            rejection_reason_code = error.code(),
            requested_scope = ?body.requested_scope,
            agent_key_scope = %authorization.agent_key_scope,
            "agent_key_proof rejected: effective scope intersection failed"
        );
    })?;

    let mut constraints = serde_json::json!({
        "allowed_tracks": effective_scope.allowed_tracks,
        "allowed_data_classes": effective_scope.allowed_data_classes,
        "allowed_endpoints": effective_scope.allowed_endpoints,
    });
    if !effective_scope.strand_ids.is_empty() {
        constraints["allowed_strand_ids"] = serde_json::to_value(&effective_scope.strand_ids)
            .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    }

    let mut scope_details = serde_json::Map::from_iter([
        (
            "controller_principal_id".to_owned(),
            serde_json::json!(&controller_principal_id),
        ),
        // Issuing key authorization, retained so introspection can fail the
        // grant closed at use time once the key is revoked (pause /
        // deactivate / superseded_by_repairing) instead of letting the token
        // live out its natural TTL (key-management §3.6.1).
        (
            "agent_key_authorization_ref".to_owned(),
            serde_json::json!(authorization_ref),
        ),
        (
            "realm_ids".to_owned(),
            serde_json::json!(&effective_scope.realm_ids),
        ),
        (
            "strand_ids".to_owned(),
            serde_json::json!(&effective_scope.strand_ids),
        ),
        (
            "resources".to_owned(),
            serde_json::json!({
                "realm_refs": &effective_scope.realm_ids,
                "strand_refs": &effective_scope.strand_ids,
            }),
        ),
        ("constraints".to_owned(), constraints),
        (
            "capability_grant_refs".to_owned(),
            serde_json::json!(&effective_scope.capability_grant_refs),
        ),
        (
            "policy_refs".to_owned(),
            serde_json::json!(&effective_scope.policy_refs),
        ),
    ]);
    if !scope_request.participation.is_empty() {
        scope_details.insert(
            "participation".to_owned(),
            serde_json::to_value(&scope_request.participation)
                .map_err(|_| AgentAuthRejection::ProofInvalid)?,
        );
    }

    // TTL: cap to the spec ceiling (≤ 15 min), never wider than the
    // (human-oriented) configured grant TTL.
    let configured = arkret_config.session_grant_ttl;
    let ttl = if configured < AGENT_SESSION_MAX_TTL {
        configured
    } else {
        AGENT_SESSION_MAX_TTL
    };

    Ok(AgentSessionAuthorization {
        agent_id: body.principal_id.clone(),
        controller_principal_id,
        granted_scope: effective_scope.granted_scope,
        scope_details,
        ttl,
    })
}

fn canonical_session_grant_request_digest_without_signature(
    body: &arkret_models_collaboration::session_grant_bodies::AgentSessionGrantRequest,
) -> Result<String, AgentAuthRejection> {
    body.canonical_request_digest()
        .map(|digest| digest.to_string())
        .map_err(|_| AgentAuthRejection::ProofInvalid)
}

fn validate_agent_key_authorization_binding(
    authorization: &coauth_data::agent_key::AgentKeyAuthorization,
    now: chrono::DateTime<chrono::Utc>,
    agent_id: &str,
    verification_method: &str,
    audience: &str,
) -> Result<(), AgentAuthRejection> {
    if authorization.quarantined_at.is_some() {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    if authorization.soland_fanout_state
        != coauth_data::accountability::AccountabilityGrantFanoutState::Delivered
    {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    if authorization.revoked_at.is_some() {
        return Err(AgentAuthRejection::AgentDeactivated);
    }
    // `expires_at` is optional: absent means the authorization never expires
    // by time and stays valid until revoked (key-management §3.6.1). An
    // elapsed declared expiry is a dedicated rejection so the runtime can
    // tell "prompt the controller to re-authorize" apart from a proof
    // construction failure (`proof_invalid`).
    if let Some(expires_at) = authorization.expires_at
        && expires_at <= now
    {
        return Err(AgentAuthRejection::AgentKeyAuthorizationExpired);
    }
    if !authorization
        .audience
        .iter()
        .any(|authorized| authorized == audience)
    {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    if authorization.agent_id != agent_id
        || authorization.verification_method != verification_method
    {
        return Err(AgentAuthRejection::VerificationMethodPrincipalMismatch);
    }
    Ok(())
}

fn validate_authoritative_agent_session_evidence(
    authorization: &coauth_data::agent_key::AgentKeyAuthorization,
    view: &arkret_models_collaboration::agent_operations::AgentView,
    session_scope: &[String],
) -> Result<(), AgentAuthRejection> {
    let key_state = view
        .key_state
        .as_ref()
        .ok_or(AgentAuthRejection::PolicyUnavailable)?;

    // A delivered pair request is verifier-private evidence that the
    // Station validated the controller-signed disclosure against the
    // accepted-at Agent DID commitment. Re-bind that cached evidence to the
    // current authoritative projection before every session issuance.
    let paired_request: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody =
        serde_json::from_value(authorization.soland_fanout_payload.clone())
            .map_err(|_| AgentAuthRejection::AgentRequestedScopeCommitmentInvalid)?;
    let controller_account_id = paired_request
        .authorize_event
        .event
        .executed_by
        .as_ref()
        .and_then(arkret_wire::ActorId::as_account_id)
        .ok_or(AgentAuthRejection::AgentRequestedScopeCommitmentInvalid)?;
    if view.agent.agent_id.as_str() != authorization.agent_id
        || key_state.agent_id.as_str() != authorization.agent_id
        || &key_state.controller_account_id != controller_account_id
        || controller_account_id.principal_id.as_str()
            != authorization.accountable_principal_id.as_str()
        || !key_state.active_authorizations.iter().any(|active| {
            active.authorized_event_ref.as_str() == authorization.authorized_event_id
                && active.verification_method.as_str() == authorization.verification_method
        })
    {
        return Err(AgentAuthRejection::ProofInvalid);
    }

    let disclosure = &paired_request.requested_scope_disclosure;
    disclosure
        .validate()
        .map_err(|_| AgentAuthRejection::AgentRequestedScopeCommitmentInvalid)?;
    if paired_request.agent_id.as_str() != authorization.agent_id
        || paired_request.verification_method.as_str() != authorization.verification_method
        || paired_request.authorize_event.event.event_id.as_str()
            != authorization.authorized_event_id
        || disclosure.agent_id.as_str() != authorization.agent_id
        || disclosure.controller_principal_id.as_str()
            != authorization.accountable_principal_id.as_str()
        || disclosure.requested_scope != key_state.requested_scope
    {
        return Err(AgentAuthRejection::AgentRequestedScopeCommitmentInvalid);
    }

    let key_actions = parse_agent_key_scope_actions(&authorization.agent_key_scope)?
        .into_iter()
        .collect::<Vec<_>>();
    validate_agent_runtime_session_scope_layers(
        &key_state.requested_scope.actions,
        &key_actions,
        session_scope,
    )
}

fn validate_registered_agent_scope_actions(
    actions: &[String],
    layer: arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer,
) -> Result<(), AgentAuthRejection> {
    if actions.iter().any(|action| {
        arkret_wire::ServiceOperationId::from_wire(action).is_none()
            && arkret_schema::capability_action(action).is_none()
    }) {
        return Err(super::error_matrix::agent_runtime_scope_rejection(layer));
    }
    Ok(())
}

pub(super) fn validate_agent_runtime_key_scope_layers(
    provision_scope: &[String],
    key_scope: &[String],
) -> Result<(), AgentAuthRejection> {
    use arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer;

    validate_registered_agent_scope_actions(provision_scope, AgentRuntimeScopeLayer::Provision)?;
    let provision_deficiency =
        arkret_schema::agent_runtime_scope::assess_agent_runtime_provision_scope(provision_scope)
            .map_err(|_| AgentAuthRejection::AgentProvisionScopeMigrationRequired)?;
    if let Some(value) = provision_deficiency {
        return Err(super::error_matrix::agent_runtime_scope_rejection(
            value.layer,
        ));
    }
    validate_registered_agent_scope_actions(key_scope, AgentRuntimeScopeLayer::KeyAuthorization)?;
    let deficiency = arkret_schema::agent_runtime_scope::assess_agent_runtime_key_scopes(
        provision_scope,
        key_scope,
    )
    .map_err(|_| AgentAuthRejection::AgentProvisionScopeMigrationRequired)?;
    deficiency.map_or(Ok(()), |value| {
        Err(super::error_matrix::agent_runtime_scope_rejection(
            value.layer,
        ))
    })
}

fn validate_agent_runtime_session_scope_layers(
    provision_scope: &[String],
    key_scope: &[String],
    session_scope: &[String],
) -> Result<(), AgentAuthRejection> {
    use arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer;

    validate_agent_runtime_key_scope_layers(provision_scope, key_scope)?;
    validate_registered_agent_scope_actions(session_scope, AgentRuntimeScopeLayer::Session)?;
    let deficiency = arkret_schema::agent_runtime_scope::assess_agent_runtime_scopes(
        provision_scope,
        key_scope,
        session_scope,
    )
    .map_err(|_| AgentAuthRejection::AgentProvisionScopeMigrationRequired)?;
    deficiency.map_or(Ok(()), |value| {
        Err(super::error_matrix::agent_runtime_scope_rejection(
            value.layer,
        ))
    })
}

#[derive(Debug, Clone, Default)]
struct AgentSessionCapabilityScope {
    actions: BTreeSet<String>,
    realm_ids: Option<BTreeSet<String>>,
    strand_ids: Option<BTreeSet<String>>,
    allowed_tracks: Option<BTreeSet<String>>,
    allowed_data_classes: Option<BTreeSet<String>>,
    allowed_endpoints: Option<BTreeSet<String>>,
    grant_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct AgentSessionRealmPolicy {
    actions: Option<BTreeSet<String>>,
    realm_ids: Option<BTreeSet<String>>,
    strand_ids: Option<BTreeSet<String>>,
    allowed_tracks: Option<BTreeSet<String>>,
    allowed_data_classes: Option<BTreeSet<String>>,
    allowed_endpoints: Option<BTreeSet<String>>,
    policy_refs: BTreeSet<String>,
}

impl AgentSessionRealmPolicy {
    fn from_policy_data(data: &Value) -> Option<Self> {
        let mut policy = Self::default();
        let mut found_projection = false;
        visit_agent_scope_projection_objects(data, &mut |projection| {
            if merge_policy_projection(projection, &mut policy) {
                found_projection = true;
            }
        });
        if found_projection { Some(policy) } else { None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveAgentSessionScope {
    granted_scope: Vec<String>,
    realm_ids: Vec<String>,
    strand_ids: Vec<String>,
    allowed_tracks: Vec<String>,
    allowed_data_classes: Vec<String>,
    allowed_endpoints: Vec<String>,
    capability_grant_refs: Vec<String>,
    policy_refs: Vec<String>,
}

fn intersect_agent_session_scope(
    agent_key_scope: &str,
    requested_scope: &[String],
    scope_request: &AgentScopeRequestInput,
    capability_scope: &AgentSessionCapabilityScope,
    realm_policy: Option<&AgentSessionRealmPolicy>,
    policy_data: Option<&Value>,
    agent_id: &str,
) -> Result<EffectiveAgentSessionScope, AgentAuthRejection> {
    let key_scope =
        intersect_requested_scope_with_agent_key_scope(agent_key_scope, requested_scope)?;
    let mut denied_content_scope = false;
    let mut granted_scope = Vec::new();
    for token in key_scope {
        if service_surface_scope_token(&token) {
            granted_scope.push(token);
        } else if content_capability_scope_token(&token)? {
            if capability_scope.actions.contains(&token) {
                granted_scope.push(token);
            } else {
                denied_content_scope = true;
            }
        } else {
            return Err(AgentAuthRejection::ProofInvalid);
        }
    }
    if granted_scope.is_empty() {
        return if denied_content_scope {
            Err(AgentAuthRejection::CapabilityDenied)
        } else {
            Err(AgentAuthRejection::ProofInvalid)
        };
    }

    if let Some(policy) = realm_policy
        && let Some(policy_actions) = policy.actions.as_ref()
    {
        granted_scope.retain(|token| policy_actions.contains(token));
        if granted_scope.is_empty() {
            return Err(AgentAuthRejection::PolicyViolation);
        }
    }

    let content_resource_scoped = granted_scope
        .iter()
        .any(|token| !service_surface_scope_token(token) && realm_resource_scope_token(token));
    // Account-global agent service endpoints (for example the self event
    // stream) do not become Realm-scoped merely because their operation name
    // contains `events`. Content actions and explicit resource selectors must
    // still fail closed through the Realm capability/policy intersection.
    let resource_scoped =
        content_resource_scoped || scope_request_has_resource_selectors(scope_request);

    let (
        realm_ids,
        strand_ids,
        allowed_tracks,
        allowed_data_classes,
        allowed_endpoints,
        policy_refs,
    ) = if resource_scoped {
        let policy = realm_policy.ok_or(AgentAuthRejection::PolicyUnavailable)?;
        let (realm_ids, strand_ids, allowed_tracks, allowed_data_classes, allowed_endpoints) =
            if content_resource_scoped {
                let realm_ids = materialize_optional_selector(
                    &scope_request.realm_ids,
                    capability_scope.realm_ids.as_ref(),
                    policy.realm_ids.as_ref(),
                )?;
                let strand_ids = materialize_optional_selector(
                    &scope_request.strand_ids,
                    capability_scope.strand_ids.as_ref(),
                    policy.strand_ids.as_ref(),
                )?;
                if realm_ids.is_empty() && strand_ids.is_empty() {
                    return Err(missing_resource_selector_rejection(
                        capability_scope,
                        policy,
                    ));
                }
                (
                    realm_ids,
                    strand_ids,
                    materialize_optional_selector(
                        &scope_request.track_names,
                        capability_scope.allowed_tracks.as_ref(),
                        policy.allowed_tracks.as_ref(),
                    )?,
                    materialize_optional_constraint(
                        capability_scope.allowed_data_classes.as_ref(),
                        policy.allowed_data_classes.as_ref(),
                    )?,
                    materialize_optional_constraint(
                        capability_scope.allowed_endpoints.as_ref(),
                        policy.allowed_endpoints.as_ref(),
                    )?,
                )
            } else {
                (
                    materialize_service_selector(
                        &scope_request.realm_ids,
                        policy.realm_ids.as_ref(),
                    )?,
                    materialize_service_selector(
                        &scope_request.strand_ids,
                        policy.strand_ids.as_ref(),
                    )?,
                    materialize_service_selector(
                        &scope_request.track_names,
                        policy.allowed_tracks.as_ref(),
                    )?,
                    policy
                        .allowed_data_classes
                        .as_ref()
                        .map(|values| values.iter().cloned().collect())
                        .unwrap_or_default(),
                    policy
                        .allowed_endpoints
                        .as_ref()
                        .map(|values| values.iter().cloned().collect())
                        .unwrap_or_default(),
                )
            };

        let policy_data = policy_data.ok_or(AgentAuthRejection::PolicyUnavailable)?;
        granted_scope.retain(|token| {
            realm_policy_allows_session_scope(policy_data, agent_id, token, &realm_ids)
        });
        if granted_scope.is_empty() {
            return Err(AgentAuthRejection::PolicyViolation);
        }

        (
            realm_ids,
            strand_ids,
            allowed_tracks,
            allowed_data_classes,
            allowed_endpoints,
            policy.policy_refs.iter().cloned().collect(),
        )
    } else {
        if let Some(policy_data) = policy_data {
            granted_scope.retain(|token| {
                realm_policy_allows_session_scope(policy_data, agent_id, token, &[])
            });
            if granted_scope.is_empty() {
                return Err(AgentAuthRejection::PolicyViolation);
            }
        }
        (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            realm_policy
                .map(|policy| policy.policy_refs.iter().cloned().collect())
                .unwrap_or_default(),
        )
    };

    Ok(EffectiveAgentSessionScope {
        granted_scope,
        realm_ids,
        strand_ids,
        allowed_tracks,
        allowed_data_classes,
        allowed_endpoints,
        capability_grant_refs: capability_scope.grant_refs.iter().cloned().collect(),
        policy_refs,
    })
}

fn intersect_requested_scope_with_agent_key_scope(
    agent_key_scope: &str,
    requested_scope: &[String],
) -> Result<Vec<String>, AgentAuthRejection> {
    let normalized = normalize_requested_scope(requested_scope);
    if normalized.is_empty() {
        return Err(AgentAuthRejection::ProofInvalid);
    }

    let authorized_actions = parse_agent_key_scope_actions(agent_key_scope)?;
    for token in &normalized {
        if !authorized_actions.contains(token) || !registered_agent_session_scope_token(token)? {
            return Err(AgentAuthRejection::ProofInvalid);
        }
    }

    Ok(normalized)
}

fn parse_agent_key_scope_actions(
    agent_key_scope: &str,
) -> Result<BTreeSet<String>, AgentAuthRejection> {
    let scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope =
        serde_json::from_str(agent_key_scope.trim())
            .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    if scope.actions.is_empty() {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    let mut normalized = BTreeSet::new();
    for action in scope.actions {
        let action = action.trim();
        if action.is_empty() {
            return Err(AgentAuthRejection::ProofInvalid);
        }
        normalized.insert(action.to_owned());
    }
    Ok(normalized)
}

fn registered_agent_session_scope_token(token: &str) -> Result<bool, AgentAuthRejection> {
    Ok(arkret_wire::ServiceOperationId::from_wire(token).is_some()
        || arkret_schema::capability_action(token).is_some())
}

fn normalize_requested_scope(scope: &[String]) -> Vec<String> {
    scope
        .iter()
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn normalize_string_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn service_surface_scope_token(token: &str) -> bool {
    arkret_wire::ServiceOperationId::from_wire(token).is_some()
        || arkret_schema::capability_action(token)
            .is_some_and(|descriptor| descriptor.category == "service")
}

fn content_capability_scope_token(token: &str) -> Result<bool, AgentAuthRejection> {
    Ok(arkret_schema::capability_action(token)
        .is_some_and(|descriptor| descriptor.category != "service"))
}

fn realm_resource_scope_token(token: &str) -> bool {
    arkret_schema::capability_action(token)
        .is_some_and(|descriptor| descriptor.event_mapping_kind != "non_event_surface")
}

fn scope_request_has_resource_selectors(scope_request: &AgentScopeRequestInput) -> bool {
    !scope_request.realm_ids.is_empty()
        || !scope_request.strand_ids.is_empty()
        || !scope_request.track_names.is_empty()
}

fn materialize_optional_selector(
    requested: &[String],
    capability_values: Option<&BTreeSet<String>>,
    policy_values: Option<&BTreeSet<String>>,
) -> Result<Vec<String>, AgentAuthRejection> {
    let requested = normalize_string_set(requested);
    if requested.is_empty() && capability_values.is_none() && policy_values.is_none() {
        return Ok(Vec::new());
    }

    let capability_values = capability_values.ok_or(AgentAuthRejection::CapabilityDenied)?;
    let policy_values = policy_values.ok_or(AgentAuthRejection::PolicyUnavailable)?;

    let capability_intersection = if requested.is_empty() {
        capability_values.clone()
    } else {
        requested
            .intersection(capability_values)
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    if capability_intersection.is_empty() {
        return Err(AgentAuthRejection::CapabilityDenied);
    }

    let policy_intersection = capability_intersection
        .intersection(policy_values)
        .cloned()
        .collect::<BTreeSet<_>>();
    if policy_intersection.is_empty() {
        return Err(AgentAuthRejection::PolicyViolation);
    }

    Ok(policy_intersection.into_iter().collect())
}

fn materialize_service_selector(
    requested: &[String],
    policy: Option<&BTreeSet<String>>,
) -> Result<Vec<String>, AgentAuthRejection> {
    let requested = normalize_string_set(requested);
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let Some(policy) = policy else {
        return Err(AgentAuthRejection::PolicyUnavailable);
    };
    let selected = requested.intersection(policy).cloned().collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(AgentAuthRejection::PolicyViolation);
    }
    Ok(selected)
}

fn materialize_optional_constraint(
    capability_values: Option<&BTreeSet<String>>,
    policy_values: Option<&BTreeSet<String>>,
) -> Result<Vec<String>, AgentAuthRejection> {
    match (capability_values, policy_values) {
        (Some(capability_values), Some(policy_values)) => {
            let intersection = capability_values
                .intersection(policy_values)
                .cloned()
                .collect::<BTreeSet<_>>();
            if intersection.is_empty() {
                return Err(AgentAuthRejection::PolicyViolation);
            }
            Ok(intersection.into_iter().collect())
        }
        (Some(_), None) => Err(AgentAuthRejection::PolicyUnavailable),
        (None, Some(_)) => Err(AgentAuthRejection::CapabilityDenied),
        (None, None) => Ok(Vec::new()),
    }
}

fn missing_resource_selector_rejection(
    capability_scope: &AgentSessionCapabilityScope,
    policy: &AgentSessionRealmPolicy,
) -> AgentAuthRejection {
    let capability_has_selector = capability_scope
        .realm_ids
        .as_ref()
        .is_some_and(|values| !values.is_empty())
        || capability_scope
            .strand_ids
            .as_ref()
            .is_some_and(|values| !values.is_empty());
    let policy_has_selector = policy
        .realm_ids
        .as_ref()
        .is_some_and(|values| !values.is_empty())
        || policy
            .strand_ids
            .as_ref()
            .is_some_and(|values| !values.is_empty());

    if !capability_has_selector {
        AgentAuthRejection::CapabilityDenied
    } else if !policy_has_selector {
        AgentAuthRejection::PolicyUnavailable
    } else {
        AgentAuthRejection::PolicyViolation
    }
}

fn realm_policy_allows_session_scope(
    policy_data: &Value,
    agent_id: &str,
    action: &str,
    realm_ids: &[String],
) -> bool {
    if policy_scope_rejects_session_scope(policy_data, agent_id, action) {
        return false;
    }

    if let Some(default_scope) = policy_data
        .get("realms")
        .and_then(|realms| realms.get("default"))
        && policy_scope_rejects_session_scope(default_scope, agent_id, action)
    {
        return false;
    }

    for realm_id in realm_ids {
        if let Some(realm_scope) = policy_data
            .get("realms")
            .and_then(|realms| realms.get(realm_id.as_str()))
            && policy_scope_rejects_session_scope(realm_scope, agent_id, action)
        {
            return false;
        }
    }

    true
}

fn policy_scope_rejects_session_scope(scope: &Value, agent_id: &str, action: &str) -> bool {
    value_contains_str(scope.get("deny_actors"), agent_id)
        || value_contains_str(scope.get("deny_actions"), action)
        || value_contains_str(scope.get("require_review_actions"), action)
}

fn value_contains_str(value: Option<&Value>, needle: &str) -> bool {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .any(|item| item.as_str().is_some_and(|value| value == needle)),
        Some(Value::String(value)) => value == needle,
        _ => false,
    }
}

fn merge_policy_projection(projection: &Value, policy: &mut AgentSessionRealmPolicy) -> bool {
    let mut found = false;
    found |= merge_optional_set(
        &mut policy.actions,
        read_string_set(
            projection,
            &["allowed_actions", "actions", "granted_scope", "scope"],
        ),
    );
    found |= merge_optional_set(
        &mut policy.realm_ids,
        read_string_set(projection, &["allowed_realm_ids", "realm_ids"]),
    );
    found |= merge_optional_set(
        &mut policy.strand_ids,
        read_string_set(projection, &["allowed_strand_ids", "strand_ids"]),
    );
    found |= merge_optional_set(
        &mut policy.allowed_tracks,
        read_string_set(projection, &["allowed_tracks"]),
    );
    found |= merge_optional_set(
        &mut policy.allowed_data_classes,
        read_string_set(projection, &["allowed_data_classes"]),
    );
    found |= merge_optional_set(
        &mut policy.allowed_endpoints,
        read_string_set(projection, &["allowed_endpoints"]),
    );
    if let Some(constraints) = projection.get("constraints") {
        found |= merge_optional_set(
            &mut policy.strand_ids,
            read_string_set(constraints, &["allowed_strand_ids", "strand_ids"]),
        );
        found |= merge_optional_set(
            &mut policy.allowed_tracks,
            read_string_set(constraints, &["allowed_tracks"]),
        );
        found |= merge_optional_set(
            &mut policy.allowed_data_classes,
            read_string_set(constraints, &["allowed_data_classes"]),
        );
        found |= merge_optional_set(
            &mut policy.allowed_endpoints,
            read_string_set(constraints, &["allowed_endpoints"]),
        );
    }
    if let Some(refs) = read_string_set(projection, &["policy_refs", "policy_versions"]) {
        policy.policy_refs.extend(refs);
        found = true;
    }
    found
}

fn merge_optional_set(
    target: &mut Option<BTreeSet<String>>,
    values: Option<BTreeSet<String>>,
) -> bool {
    if let Some(values) = values {
        target.get_or_insert_with(BTreeSet::new).extend(values);
        true
    } else {
        false
    }
}

fn read_string_set(value: &Value, keys: &[&str]) -> Option<BTreeSet<String>> {
    let mut found = false;
    let mut values = BTreeSet::new();
    for key in keys {
        if let Some(raw_value) = value.get(*key) {
            found = true;
            values.extend(value_as_string_set(raw_value));
        }
    }
    found.then_some(values)
}

fn value_as_string_set(value: &Value) -> BTreeSet<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        Value::String(value) => {
            let value = value.trim();
            if value.is_empty() {
                BTreeSet::new()
            } else {
                BTreeSet::from([value.to_owned()])
            }
        }
        _ => BTreeSet::new(),
    }
}

fn visit_agent_scope_projection_objects<F>(value: &Value, visit: &mut F)
where
    F: FnMut(&Value),
{
    match value {
        Value::Object(object) => {
            visit(value);
            for key in [
                "agent_session_scope",
                "agent_session_policy",
                "agent_runtime",
                "session_scope",
                "scope",
                "grant",
                "capability_grant",
                "capability_grants",
            ] {
                if let Some(child) = object.get(key) {
                    visit_agent_scope_projection_objects(child, visit);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                visit_agent_scope_projection_objects(item, visit);
            }
        }
        _ => {}
    }
}

/// Resolve the current reducer-stamped agent lifecycle state from a configured
/// Station. Missing or unreachable authority fails closed.
pub(super) async fn fetch_authoritative_agent_view(
    http_client: &reqwest::Client,
    arkret_config: &ArkretConfig,
    agent_id: &str,
) -> Result<
    (
        arkret_models_collaboration::agent_operations::AgentView,
        coauth_config::StationConfig,
    ),
    AgentAuthRejection,
> {
    let mut queried = false;
    let mut saw_not_found = false;

    for server in &arkret_config.stations {
        let Some(bearer) = server
            .session_grant_introspection_bearer
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        queried = true;
        let mut endpoint = server.endpoint.clone();
        endpoint.set_path("/");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
            .path_segments_mut()
            .map_err(|_| AgentAuthRejection::PolicyUnavailable)?
            .extend(["_arkret", "self", "agents", agent_id]);

        let response = http_client
            .get(endpoint)
            .header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::SELF_AGENT_RESOURCE_GET_V1,
            )
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|_| AgentAuthRejection::PolicyUnavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            saw_not_found = true;
            continue;
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::PRECONDITION_FAILED
                && body.contains(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)
            {
                return Err(AgentAuthRejection::AccountabilityGrantMissing);
            }
            return Err(AgentAuthRejection::PolicyUnavailable);
        }
        let view = response
            .json::<arkret_models_collaboration::agent_operations::AgentView>()
            .await
            .map_err(|_| AgentAuthRejection::PolicyUnavailable)?;
        return Ok((view, server.clone()));
    }

    if queried && saw_not_found {
        Err(AgentAuthRejection::ProofInvalid)
    } else {
        Err(AgentAuthRejection::PolicyUnavailable)
    }
}

pub async fn enforce_authoritative_agent_lifecycle(
    http_client: &reqwest::Client,
    arkret_config: &ArkretConfig,
    agent_id: &str,
) -> Result<arkret_models_collaboration::agent_operations::AgentView, AgentAuthRejection> {
    let (view, _) = fetch_authoritative_agent_view(http_client, arkret_config, agent_id).await?;
    // Session issuance is governed only by the controller lifecycle intent axis
    // (key-management.md §3.6.1). The orthogonal runtime_state readiness axis is
    // never a session gate; an agent that holds no active key simply cannot
    // produce a valid agent_key_proof.
    match view.agent.lifecycle {
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active => Ok(view),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused => {
            Err(AgentAuthRejection::AgentPaused)
        }
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated => {
            Err(AgentAuthRejection::AgentDeactivated)
        }
    }
}

pub async fn enforce_authoritative_pairing_handle(
    http_client: &reqwest::Client,
    arkret_config: &ArkretConfig,
    agent_id: &str,
    pairing_request_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<
    (
        arkret_models_collaboration::agent_operations::AgentView,
        coauth_config::StationConfig,
    ),
    AgentAuthRejection,
> {
    let (view, server) =
        fetch_authoritative_agent_view(http_client, arkret_config, agent_id).await?;
    // Only the terminal lifecycle intent forbids pairing. Both active and
    // paused agents may complete a (bootstrap or replacement) pairing handle
    // (key-management.md §3.6.1); handle open/expiry is enforced below via the
    // authoritative key_state rather than the lifecycle axis.
    match view.agent.lifecycle {
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
        | arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused => {}
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated => {
            return Err(AgentAuthRejection::AgentDeactivated);
        }
    }
    let key_state = view
        .key_state
        .as_ref()
        .ok_or(AgentAuthRejection::PolicyUnavailable)?;
    if key_state.pairing_request_id.as_deref() != Some(pairing_request_id) {
        return Err(AgentAuthRejection::PairingRequestExpired);
    }
    let expires_at = key_state
        .pairing_expires_at
        .ok_or(AgentAuthRejection::PolicyUnavailable)?;
    if expires_at <= now {
        return Err(AgentAuthRejection::PairingRequestExpired);
    }
    Ok((view, server))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    async fn lifecycle_config(
        status: &str,
        pairing_request_id: &str,
    ) -> (MockServer, ArkretConfig) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("authorization", "Bearer lifecycle-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "agent": {
                    "agent_id": "ak:did_core:web:agent.example",
                    "slug": "agent",
                    "lifecycle": status,
                    "readiness": {
                        "state": "not_ready",
                        "blockers": ["runtime_key_missing", "pairing_open"]
                    },
                    "presence": {
                        "state": "unknown",
                        "expires_at": "2099-01-01T00:00:00.000Z",
                        "refresh_after": "2098-12-31T23:59:00.000Z"
                    }
                },
                "key_state": {
                    "agent_id": "ak:did_core:web:agent.example",
                    "controller_account_id": {
                        "principal_id": "ak:did_core:web:controller.example",
                        "station_id": "ak:did_core:web:station.example"
                    },
                    "principal_control_realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG",
                    "controller_authorization_ref": "did:web:agent.example#managed-controller",
                    "requested_scope": {
                        "actions": ["ak.message.create"],
                        "resources": []
                    },
                    "pairing_request_id": pairing_request_id,
                    "pairing_mode": "bootstrap",
                    "pairing_expires_at": "2099-01-01T00:00:00.000Z",
                    "active_authorizations": []
                }
            })))
            .mount(&server)
            .await;
        let mut config = ArkretConfig::default();
        config.stations.push(coauth_config::StationConfig {
            name: "soland-test".to_owned(),
            endpoint: server.uri().parse().unwrap(),
            service_id: Some(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:soland.test").unwrap(),
            ),
            session_grant_introspection_bearer: Some("lifecycle-secret".to_owned()),
            embedded_webvh_registration_bearer: None,
        });
        crate::services::station_trust::shared()
            .insert_for_test(&config.stations[0].endpoint, "ak:did_core:web:soland.test");
        (server, config)
    }

    #[tokio::test]
    async fn authoritative_lifecycle_and_pairing_fail_closed() {
        let client = reqwest::Client::new();
        let (_active_server, active) = lifecycle_config("active", "pair-current").await;
        enforce_authoritative_agent_lifecycle(&client, &active, "ak:did_core:web:agent.example")
            .await
            .expect("active agent accepts");
        enforce_authoritative_pairing_handle(
            &client,
            &active,
            "ak:did_core:web:agent.example",
            "pair-current",
            chrono::Utc::now(),
        )
        .await
        .expect("current pairing handle accepts");
        assert_eq!(
            enforce_authoritative_pairing_handle(
                &client,
                &active,
                "ak:did_core:web:agent.example",
                "pair-old",
                chrono::Utc::now(),
            )
            .await
            .expect_err("old pairing handle rejects"),
            AgentAuthRejection::PairingRequestExpired
        );

        let (_paused_server, paused) = lifecycle_config("paused", "pair-paused").await;
        assert_eq!(
            enforce_authoritative_agent_lifecycle(
                &client,
                &paused,
                "ak:did_core:web:agent.example",
            )
            .await
            .expect_err("paused agent rejects"),
            AgentAuthRejection::AgentPaused
        );
        assert_eq!(
            enforce_authoritative_agent_lifecycle(
                &client,
                &ArkretConfig::default(),
                "ak:did_core:web:agent.example",
            )
            .await
            .expect_err("missing lifecycle authority rejects"),
            AgentAuthRejection::PolicyUnavailable
        );
    }

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn canonical_agent_key_scope() -> String {
        let actions = [
            "ak.event.read",
            "ak.message.create",
            "ak.reaction.add",
            "ak.self.authorization_leases.command.issue.v1",
            "ak.self.device_messages.command.ack.v1",
            "ak.self.device_messages.read.list.v1",
            "ak.self.events.command.submit.v1",
            "ak.self.events.read.describe.v1",
            "ak.self.events.read.frontier.v1",
            "ak.self.events.read.resolve.v1",
            "ak.self.events.read.scan.v1",
            "ak.self.events.resource.get.v1",
            "ak.self.events.stream.subscribe.v1",
            "ak.self.keys.keypackages.command.consume.v1",
            "ak.self.keys.keypackages.command.revoke.v1",
            "ak.self.keys.keypackages.upload.create.v1",
            "ak.self.seals.read.frontier.v1",
            "ak.self.signal.command.send.v1",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        serde_json::json!({"actions": actions, "resources": []}).to_string()
    }

    fn capability_scope(actions: &[&str]) -> AgentSessionCapabilityScope {
        AgentSessionCapabilityScope {
            actions: set(actions),
            grant_refs: set(&["ak:grant:capability"]),
            ..AgentSessionCapabilityScope::default()
        }
    }

    fn policy_scope(actions: Option<&[&str]>) -> AgentSessionRealmPolicy {
        AgentSessionRealmPolicy {
            actions: actions.map(set),
            policy_refs: set(&["policy:2026-06-19"]),
            ..AgentSessionRealmPolicy::default()
        }
    }

    fn agent_key_authorization(
        now: chrono::DateTime<chrono::Utc>,
    ) -> coauth_data::agent_key::AgentKeyAuthorization {
        coauth_data::agent_key::AgentKeyAuthorization {
            id: coauth_data::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
            authorized_event_id: "ak:event:AQoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoK".to_owned(),
            agent_id: "ak:did_core:web:agent.example".to_owned(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: "did:web:agent.example#runtime-key-1".to_owned(),
            public_key: serde_json::json!({
                "id": "did:web:agent.example#runtime-key-1",
                "type": "Multikey",
                "controller": "did:web:agent.example",
                "publicKeyMultibase": "z6MksG8zH7ZkUVGqdnqQWUV7s6jVMrptHToH6aQahJ2HWaW1",
            }),
            accountable_principal_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:controller.example",
            )
            .unwrap(),
            agent_key_scope: canonical_agent_key_scope(),
            audience: vec!["https://arkret.example/_arkret".to_owned()],
            issued_at: now,
            expires_at: Some(now + chrono::Duration::minutes(15)),
            pairing_request_id: "pairing_request:01970000-0000-7000-8000-000000000020".to_owned(),
            request_canonical_digest: format!("sha256:{}", "1".repeat(64)),
            revoked_at: None,
            revoked_reason: None,
            quarantined_at: None,
            quarantine_reason: None,
            raw_payload_digest: format!("sha256:{}", "2".repeat(64)),
            soland_fanout_state:
                coauth_data::accountability::AccountabilityGrantFanoutState::Delivered,
            soland_fanout_idempotency_key: "coauth:agent_key_authorize:test".to_owned(),
            soland_fanout_payload: serde_json::json!({}),
            soland_fanout_attempt: 0,
            soland_fanout_next_retry_at: None,
            soland_fanout_dead_letter_reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn authorization_binding_accepts_active_matching_key() {
        let now = chrono::Utc::now();
        let authorization = agent_key_authorization(now);

        validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect("active matching authorization should pass");
    }

    #[test]
    fn authorization_binding_rejects_revoked_key() {
        let now = chrono::Utc::now();
        let mut authorization = agent_key_authorization(now);
        authorization.revoked_at = Some(now);

        let err = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect_err("revoked runtime keys must fail closed");

        assert_eq!(err, AgentAuthRejection::AgentDeactivated);
    }

    #[test]
    fn authorization_binding_rejects_collision_quarantine() {
        let now = chrono::Utc::now();
        let mut authorization = agent_key_authorization(now);
        authorization.quarantined_at = Some(now);
        authorization.quarantine_reason = Some("event_hash_collision".to_owned());

        let error = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect_err("a quarantined Event cannot authorize sessions");
        assert_eq!(error, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn authorization_binding_rejects_key_before_soland_acceptance() {
        let now = chrono::Utc::now();
        let mut authorization = agent_key_authorization(now);
        authorization.soland_fanout_state =
            coauth_data::accountability::AccountabilityGrantFanoutState::Queued;

        let err = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect_err("queued Agent key authorization must not issue sessions");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn authorization_binding_rejects_expired_authorization() {
        let now = chrono::Utc::now();
        let mut authorization = agent_key_authorization(now);
        authorization.expires_at = Some(now);

        let err = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect_err("expired agent key authorization must fail closed");

        assert_eq!(err, AgentAuthRejection::AgentKeyAuthorizationExpired);
    }

    #[test]
    fn authorization_binding_accepts_non_expiring_authorization() {
        let now = chrono::Utc::now();
        let mut authorization = agent_key_authorization(now - chrono::Duration::days(365));
        authorization.expires_at = None;

        validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect("absent expires_at means the authorization never expires by time");
    }

    #[test]
    fn authorization_binding_rejects_revoked_key_before_expiry_check() {
        let now = chrono::Utc::now();
        let mut authorization = agent_key_authorization(now);
        authorization.expires_at = Some(now);
        authorization.revoked_at = Some(now);
        authorization.revoked_reason =
            Some(arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING.to_owned());

        let err = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://arkret.example/_arkret",
        )
        .expect_err("revoked authorizations must fail closed regardless of expiry");

        assert_eq!(err, AgentAuthRejection::AgentDeactivated);
    }

    #[test]
    fn authorization_binding_rejects_wrong_audience() {
        let now = chrono::Utc::now();
        let authorization = agent_key_authorization(now);

        let err = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#runtime-key-1",
            "https://evil.example/_arkret",
        )
        .expect_err("authorization audience must bind the target service");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn authorization_binding_rejects_mismatched_verification_method() {
        let now = chrono::Utc::now();
        let authorization = agent_key_authorization(now);

        let err = validate_agent_key_authorization_binding(
            &authorization,
            now,
            "ak:did_core:web:agent.example",
            "did:web:agent.example#other-key",
            "https://arkret.example/_arkret",
        )
        .expect_err("authorization must bind the exact runtime verification method");

        assert_eq!(err, AgentAuthRejection::VerificationMethodPrincipalMismatch);
    }

    #[test]
    fn canonical_agent_key_scope_dedupes_and_allows_runtime_scope() {
        let scope = intersect_requested_scope_with_agent_key_scope(
            &canonical_agent_key_scope(),
            &[
                " ak.self.events.command.submit.v1 ".to_owned(),
                "ak.message.create".to_owned(),
                "ak.self.events.command.submit.v1".to_owned(),
                "ak.self.events.read.frontier.v1".to_owned(),
                "ak.self.authorization_leases.command.issue.v1".to_owned(),
                "ak.self.signal.command.send.v1".to_owned(),
                "ak.reaction.add".to_owned(),
                "ak.self.keys.keypackages.upload.create.v1".to_owned(),
                "ak.self.keys.keypackages.command.consume.v1".to_owned(),
                "ak.self.device_messages.read.list.v1".to_owned(),
                "ak.self.device_messages.command.ack.v1".to_owned(),
            ],
        )
        .expect("canonical runtime scope should be accepted");

        assert_eq!(
            scope,
            vec![
                "ak.message.create".to_owned(),
                "ak.reaction.add".to_owned(),
                "ak.self.authorization_leases.command.issue.v1".to_owned(),
                "ak.self.device_messages.command.ack.v1".to_owned(),
                "ak.self.device_messages.read.list.v1".to_owned(),
                "ak.self.events.command.submit.v1".to_owned(),
                "ak.self.events.read.frontier.v1".to_owned(),
                "ak.self.keys.keypackages.command.consume.v1".to_owned(),
                "ak.self.keys.keypackages.upload.create.v1".to_owned(),
                "ak.self.signal.command.send.v1".to_owned(),
            ]
        );
    }

    #[test]
    fn secure_messaging_service_scope_needs_no_realm_content_grant() {
        let requested_scope = [
            "ak.self.device_messages.command.ack.v1",
            "ak.self.device_messages.read.list.v1",
            "ak.self.keys.keypackages.command.consume.v1",
            "ak.self.keys.keypackages.upload.create.v1",
        ]
        .map(str::to_owned);

        let effective_scope = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &requested_scope,
            &AgentScopeRequestInput::default(),
            &AgentSessionCapabilityScope::default(),
            None,
            None,
            "did:example:agent",
        )
        .expect("MLS and to-device operations are service-surface scope");

        assert_eq!(effective_scope.granted_scope, requested_scope);
        assert!(effective_scope.capability_grant_refs.is_empty());
    }

    #[test]
    fn spec_agent_key_scope_object_limits_requested_actions() {
        let agent_key_scope = serde_json::json!({
            "actions": [
                "ak.self.events.stream.subscribe.v1",
                "ak.event.read"
            ],
            "resources": []
        })
        .to_string();

        let scope = intersect_requested_scope_with_agent_key_scope(
            &agent_key_scope,
            &[
                "ak.self.events.stream.subscribe.v1".to_owned(),
                "ak.event.read".to_owned(),
            ],
        )
        .expect("spec agent_key_scope object should act as the runtime ceiling");
        assert_eq!(
            scope,
            vec![
                "ak.event.read".to_owned(),
                "ak.self.events.stream.subscribe.v1".to_owned(),
            ]
        );

        let err = intersect_requested_scope_with_agent_key_scope(
            &agent_key_scope,
            &["ak.self.events.command.submit.v1".to_owned()],
        )
        .expect_err("actions outside the signed agent_key_scope must reject");
        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn canonical_agent_key_scope_rejects_unlisted_admin_surface() {
        let err = intersect_requested_scope_with_agent_key_scope(
            &canonical_agent_key_scope(),
            &["ak.self.agent.command.deactivate.v1".to_owned()],
        )
        .expect_err("key scope must not mint an unlisted control-plane action");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn canonical_agent_key_scope_rejects_unlisted_account_surface() {
        let err = intersect_requested_scope_with_agent_key_scope(
            &canonical_agent_key_scope(),
            &["ak.self.account.read.describe.v1".to_owned()],
        )
        .expect_err("key scope must not mint an unlisted account-surface action");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn canonical_agent_key_scope_rejects_unknown_content_action() {
        let err = intersect_requested_scope_with_agent_key_scope(
            &canonical_agent_key_scope(),
            &["ak.message.not_registered".to_owned()],
        )
        .expect_err("unknown content actions must fail closed");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn unregistered_events_subscribe_scope_rejects_fail_closed() {
        // The registered stream action is `ak.self.events.stream.subscribe.v1`
        // (capabilities.md §5.5). `ak.self.events.subscribe` is not in the
        // closed set, and §5.0 requires verbatim `actions[]` matching with no
        // subsumption, so the canonical key scope must fail closed on it.
        let unregistered_scope = format!("ak.self.events.{}", "subscribe");
        let err = intersect_requested_scope_with_agent_key_scope(
            &canonical_agent_key_scope(),
            std::slice::from_ref(&unregistered_scope),
        )
        .expect_err("an unregistered service token must fail closed");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn schema_external_agent_key_scope_rejects_fail_closed() {
        let err = intersect_requested_scope_with_agent_key_scope(
            "delegated-root",
            &["ak.self.events.read.scan.v1".to_owned()],
        )
        .expect_err("schema-external key scope must fail closed");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn empty_requested_scope_rejects_after_normalization() {
        let err = intersect_requested_scope_with_agent_key_scope(
            &canonical_agent_key_scope(),
            &[" ".to_owned(), String::new()],
        )
        .expect_err("empty scope must fail closed");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn session_scope_is_requested_key_grant_policy_intersection() {
        let mut capability_scope = capability_scope(&["ak.message.create", "ak.reaction.add"]);
        capability_scope.realm_ids = Some(set(&["realm-a", "realm-b"]));
        capability_scope.allowed_tracks = Some(set(&["main", "ops"]));

        let mut policy_scope = policy_scope(Some(&["ak.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-b", "realm-c"]));
        policy_scope.allowed_tracks = Some(set(&["main"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned(), "realm-b".to_owned()],
            track_names: vec!["main".to_owned(), "ops".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let effective_scope = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &["ak.message.create".to_owned(), "ak.reaction.add".to_owned()],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect("session scope should be narrowed to the four-way intersection");

        assert_eq!(effective_scope.granted_scope, vec!["ak.message.create"]);
        assert_eq!(effective_scope.realm_ids, vec!["realm-b"]);
        assert_eq!(effective_scope.allowed_tracks, vec!["main"]);
        assert_eq!(
            effective_scope.capability_grant_refs,
            vec!["ak:grant:capability"]
        );
        assert_eq!(effective_scope.policy_refs, vec!["policy:2026-06-19"]);
    }

    #[test]
    fn stream_service_scope_is_not_filtered_by_content_grants() {
        let mut capability_scope = capability_scope(&["ak.event.read"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));

        let mut policy_scope = policy_scope(None);
        policy_scope.realm_ids = Some(set(&["realm-a"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let effective_scope = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &[
                "ak.self.events.stream.subscribe.v1".to_owned(),
                "ak.event.read".to_owned(),
            ],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect("stream service scope and read content grant should both survive");

        assert_eq!(
            effective_scope.granted_scope,
            vec![
                "ak.event.read".to_owned(),
                "ak.self.events.stream.subscribe.v1".to_owned()
            ]
        );
    }

    #[test]
    fn stream_service_scope_survives_without_read_content_grant() {
        let mut capability_scope = capability_scope(&["ak.reaction.add"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));

        let mut policy_scope = policy_scope(None);
        policy_scope.realm_ids = Some(set(&["realm-a"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let effective_scope = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &[
                "ak.self.events.stream.subscribe.v1".to_owned(),
                "ak.event.read".to_owned(),
            ],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect("service-surface access must not depend on content read grants");

        assert_eq!(
            effective_scope.granted_scope,
            vec!["ak.self.events.stream.subscribe.v1"]
        );
    }

    #[test]
    fn submit_service_scope_survives_without_message_create_content_grant() {
        let mut capability_scope = capability_scope(&["ak.event.read"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));

        let mut policy_scope = policy_scope(None);
        policy_scope.realm_ids = Some(set(&["realm-a"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let effective_scope = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &[
                "ak.self.events.command.submit.v1".to_owned(),
                "ak.message.create".to_owned(),
            ],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect("submit service scope should survive without message.create content grant");

        assert_eq!(
            effective_scope.granted_scope,
            vec!["ak.self.events.command.submit.v1"]
        );
    }

    #[test]
    fn account_global_service_scope_does_not_require_realm_policy() {
        let effective_scope = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &[
                "ak.self.events.stream.subscribe.v1".to_owned(),
                "ak.event.read".to_owned(),
            ],
            &AgentScopeRequestInput::default(),
            &AgentSessionCapabilityScope::default(),
            None,
            None,
            "did:example:agent",
        )
        .expect("account-global service access must precede Realm content grants");

        assert_eq!(
            effective_scope.granted_scope,
            vec!["ak.self.events.stream.subscribe.v1"]
        );
        assert!(effective_scope.realm_ids.is_empty());
        assert!(effective_scope.policy_refs.is_empty());
    }

    #[test]
    fn content_only_scope_without_capability_grant_rejects_fail_closed() {
        let capability_scope = capability_scope(&["ak.event.read"]);
        let scope_request = AgentScopeRequestInput::default();
        let policy_data = serde_json::json!({});

        let err = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &["ak.message.create".to_owned()],
            &scope_request,
            &capability_scope,
            None,
            Some(&policy_data),
            "did:example:agent",
        )
        .expect_err("content action without matching capability grant must fail closed");

        assert_eq!(err, AgentAuthRejection::CapabilityDenied);
    }

    #[test]
    fn resource_scope_without_capability_selector_rejects_fail_closed() {
        let capability_scope = capability_scope(&["ak.message.create"]);
        let mut policy_scope = policy_scope(Some(&["ak.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-a"]));
        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let err = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &["ak.message.create".to_owned()],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect_err("resource-level grant selectors must be enforced in coauth");

        assert_eq!(err, AgentAuthRejection::CapabilityDenied);
    }

    #[test]
    fn resource_scope_without_realm_policy_rejects_fail_closed() {
        let mut capability_scope = capability_scope(&["ak.message.create"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));
        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };

        let err = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &["ak.message.create".to_owned()],
            &scope_request,
            &capability_scope,
            None,
            None,
            "did:example:agent",
        )
        .expect_err("Realm policy must be present for resource-scoped sessions");

        assert_eq!(err, AgentAuthRejection::PolicyUnavailable);
    }

    #[test]
    fn realm_policy_deny_action_rejects_effective_scope() {
        let mut capability_scope = capability_scope(&["ak.message.create"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));

        let mut policy_scope = policy_scope(Some(&["ak.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-a"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({
            "realms": {
                "realm-a": {
                    "deny_actions": ["ak.message.create"]
                }
            }
        });

        let err = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &["ak.message.create".to_owned()],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect_err("Realm policy denial must remove the action fail-closed");

        assert_eq!(err, AgentAuthRejection::PolicyViolation);
    }

    #[test]
    fn requested_track_without_policy_coverage_rejects_fail_closed() {
        let mut capability_scope = capability_scope(&["ak.message.create"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));
        capability_scope.allowed_tracks = Some(set(&["main"]));

        let mut policy_scope = policy_scope(Some(&["ak.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-a"]));
        policy_scope.allowed_tracks = Some(set(&["ops"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            track_names: vec!["main".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let err = intersect_agent_session_scope(
            &canonical_agent_key_scope(),
            &["ak.message.create".to_owned()],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect_err("requested track must survive grant and policy intersection");

        assert_eq!(err, AgentAuthRejection::PolicyViolation);
    }

    #[test]
    fn session_request_digest_ignores_signature_but_binds_scope() {
        let mut body = arkret_models_collaboration::session_grant_bodies::AgentSessionGrantRequest {
            principal_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:agent.example")
                .unwrap(),
            device_id: arkret_identifiers::DeviceId::new(
                "ak:device:01964137-0000-7000-8000-000000000001",
            )
            .unwrap(),
            requested_scope: vec!["ak.message.create".to_owned()],
            requested_scope_disclosure: None,
            agent_key_authorization_ref:
                "ak:event:AQoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoK".to_owned(),
            agent_scope_request:
                arkret_models_collaboration::session_grant_bodies::SessionGrantAgentScopeRequest {
                    realm_ids: vec![
                        arkret_identifiers::RealmId::new(
                            "ak:realm:AR5_BcY29XYrMbX0Y8Qiz4KDnt-NvwrXmij2C3-4UD2c",
                        )
                        .unwrap(),
                    ],
                    strand_ids: Vec::new(),
                    track_names: Vec::new(),
                },
            dpop_binding_proof:
                arkret_models_collaboration::session_grant_bodies::SessionGrantDpopBindingProof {
                    proof_jwt: "dpop.jwt".to_owned(),
                },
            applet_authority: None,
            proof: arkret_models_collaboration::session_grant_bodies::AgentSessionGrantProof {
                proof_kind: arkret_models_collaboration::session_grant_bodies::AgentSessionGrantProofKind::AgentKeyProof,
                challenge: "challenge-abc".to_owned(),
                request_canonical_digest: arkret_identifiers::Hash::new(format!(
                    "sha256:{}",
                    "0".repeat(64)
                ))
                .unwrap(),
                audience_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:soland.example")
                    .unwrap(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                signature: "sig-a".to_owned(),
                verification_method:
                    arkret_wire::DidUrl::new("did:web:agent.example#runtime-key-1").unwrap(),
                nonce: "nonce-abc".to_owned(),
            },
        };
        let digest = canonical_session_grant_request_digest_without_signature(&body)
            .expect("request digest should compute");
        body.proof.request_canonical_digest =
            arkret_identifiers::Hash::new(digest.clone()).unwrap();

        let mut signature_changed = body.clone();
        signature_changed.proof.signature = "sig-b".to_owned();
        assert_eq!(
            canonical_session_grant_request_digest_without_signature(&signature_changed).unwrap(),
            digest
        );

        let mut scope_changed = body.clone();
        scope_changed
            .requested_scope
            .push("ak.reaction.add".to_owned());
        assert_ne!(
            canonical_session_grant_request_digest_without_signature(&scope_changed).unwrap(),
            digest
        );
    }

    #[test]
    fn agent_refresh_digest_binds_prior_grant_device_audience_and_runtime_key() {
        fn digest(
            prior_grant_jwt: &str,
            principal_id: &str,
            device_id: &str,
            audience: &str,
            verification_method: &str,
        ) -> arkret_identifiers::Hash {
            agent_session_refresh_request_digest(
                prior_grant_jwt,
                &DidCoreId::new(principal_id.to_owned()).unwrap(),
                &arkret_identifiers::DeviceId::new(device_id.to_owned()).unwrap(),
                &DidCoreId::new(audience.to_owned()).unwrap(),
                &arkret_wire::DidUrl::new(verification_method.to_owned()).unwrap(),
            )
            .unwrap()
        }

        let base = digest(
            "grant.jwt.one",
            "ak:did_core:web:agent.example",
            "ak:device:01970000-0000-7000-8000-000000000001",
            "ak:did_core:web:service.example",
            "did:web:agent.example#runtime-key-1",
        );
        assert!(base.as_str().starts_with("sha256:"));

        for changed in [
            digest(
                "grant.jwt.two",
                "ak:did_core:web:agent.example",
                "ak:device:01970000-0000-7000-8000-000000000001",
                "ak:did_core:web:service.example",
                "did:web:agent.example#runtime-key-1",
            ),
            digest(
                "grant.jwt.one",
                "ak:did_core:web:other-agent.example",
                "ak:device:01970000-0000-7000-8000-000000000001",
                "ak:did_core:web:service.example",
                "did:web:agent.example#runtime-key-1",
            ),
            digest(
                "grant.jwt.one",
                "ak:did_core:web:agent.example",
                "ak:device:01970000-0000-7000-8000-000000000002",
                "ak:did_core:web:service.example",
                "did:web:agent.example#runtime-key-1",
            ),
            digest(
                "grant.jwt.one",
                "ak:did_core:web:agent.example",
                "ak:device:01970000-0000-7000-8000-000000000001",
                "ak:did_core:web:other-service.example",
                "did:web:agent.example#runtime-key-1",
            ),
            digest(
                "grant.jwt.one",
                "ak:did_core:web:agent.example",
                "ak:device:01970000-0000-7000-8000-000000000001",
                "ak:did_core:web:service.example",
                "did:web:agent.example#runtime-key-2",
            ),
        ] {
            assert_ne!(changed, base);
        }
    }
}
