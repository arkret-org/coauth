//! CKP-0008 §4.6 agent runtime authentication (`agent_key_proof` branch of
//! `ck.gate.account.command.issue_session_grant`).
//!
//! This is the independent validator the session-grant endpoint calls; it MUST
//! NOT fall back to the password / OIDC / passkey validators.

use std::collections::BTreeSet;

use coauth_config::CokretConfig;
use coauth_data::RepositoryAccess;
use coauth_data::accountability::{AccountabilityGrant, AccountabilitySubjectKind};
use coauth_data::agent_key::NewAgentSessionProofReplay;
use cokret_core::canonical::canonical_sha256;
use cokret_core::identifiers::new_prefixed_uuid7;
use serde::Deserialize;
use serde_json::Value;

use super::error_matrix::{AgentAuthRejection, enforce_verification_method_binding};
use super::proof::{ProofSignedFields, verify_proof_signature};
use crate::handlers::cokret::is_allowed_session_grant_audience;

/// Replay grace window appended to the proof `expires_at` (CKP-0008 §4.6:
/// "at least covers the proof expiry plus a replay grace window"). A consumed
/// challenge stays in the replay table until `proof.expires_at + this` so a
/// replay landing right after expiry is still rejected.
const AGENT_PROOF_REPLAY_GRACE: chrono::Duration = chrono::Duration::minutes(5);

/// Spec ceiling on the default agent session TTL (CKP-0008 §4.6 / key-management
/// §3.6.1: default SHOULD be ≤ 15 minutes). coauth caps the agent branch to
/// this regardless of the (human-oriented) `cokret.session_grant_ttl`.
pub const AGENT_SESSION_MAX_TTL: chrono::Duration = chrono::Duration::minutes(15);

const AGENT_KEY_SCOPE_ACCOUNT: &str = "account";
const AGENT_KEY_SCOPE_REALM: &str = "realm";
const AGENT_KEY_SCOPE_APPLET: &str = "applet";
const AGENT_KEY_SCOPE_LIMITED: &str = "limited";

/// Outcome of validating an `agent_key_proof` session-grant request.
pub struct AgentSessionAuthorization {
    /// Agent principal DID the proof authenticated.
    pub agent_principal_id: String,
    /// Controller DID accountable for the agent.
    pub controller_did: String,
    /// Effective granted scope (intersection of requested scope, the authorized
    /// key scope, active capability grants, and Realm policy).
    pub granted_scope: Vec<String>,
    /// Materialized `scope_details` overlay (canonical resource constraints +
    /// optional participation entries).
    pub scope_details: serde_json::Value,
    /// Capped agent session TTL (≤ 15 min).
    pub ttl: chrono::Duration,
}

/// Structured `claim_required` rejection (CKP-0008 §4.6): the agent runtime
/// MUST NOT be shown a CAPTCHA / OTP. The session endpoint renders this as
/// `{ok:false, error:{code, reason_code, approval_request_id}}`.
pub struct AgentHumanApprovalRequired {
    pub approval_request_id: String,
}

/// Either a fail-closed wire rejection or a structured human-approval request.
pub enum AgentSessionProofError {
    /// Canonical fail-closed rejection (proof_invalid / agent_paused / …).
    Rejection(AgentAuthRejection),
    /// `claim_required` / `human_approval_required` structured error.
    HumanApprovalRequired(AgentHumanApprovalRequired),
}

impl From<AgentAuthRejection> for AgentSessionProofError {
    fn from(value: AgentAuthRejection) -> Self {
        Self::Rejection(value)
    }
}

/// `agent_scope_request` overlay (CKP-0008 §4.6). `participation[]` is the
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
    participation: Vec<cokret_core::AgentParticipationEntry>,
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
    cokret_config: &CokretConfig,
    body: &cokret_core::SessionGrantRequestBody,
) -> Result<AgentSessionAuthorization, AgentSessionProofError> {
    let now = clock.now();
    let proof = &body.proof;

    // The agent principal MUST be present for this branch.
    let agent_principal_id = body
        .principal_id
        .as_ref()
        .map(|did| did.as_str().to_owned())
        .ok_or(AgentAuthRejection::ProofInvalid)?;

    // `proof.verification_method` MUST be present and its DID part MUST equal
    // the agent principal (AUTH-1, fail closed before crypto).
    let verification_method = proof
        .verification_method
        .as_deref()
        .ok_or(AgentAuthRejection::VerificationMethodPrincipalMismatch)?;
    enforce_verification_method_binding(verification_method, &agent_principal_id)?;

    // expiry / audience.
    let expires_at = proof.expires_at.ok_or(AgentAuthRejection::ProofInvalid)?;
    if expires_at <= now {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !is_allowed_session_grant_audience(url_builder, cokret_config, &proof.audience) {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !proof
        .request_canonical_digest
        .as_str()
        .starts_with("sha256:")
    {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    let request_digest = canonical_session_grant_request_digest_without_signature(body)?;
    if request_digest != proof.request_canonical_digest.as_str() {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    let nonce = proof
        .nonce
        .as_deref()
        .filter(|nonce| !nonce.trim().is_empty())
        .ok_or(AgentAuthRejection::ProofInvalid)?;

    // The key MUST be authorized by an accepted, unexpired, unrevoked
    // `ck.agent.key.authorize`. Resolve it by the request's
    // `agent_key_authorization_ref` (the minted authorize event id).
    let authorization_ref = body
        .agent_key_authorization_ref
        .as_deref()
        .ok_or(AgentAuthRejection::ProofInvalid)?;
    let authorization = repo
        .agent_key_authorization()
        .lookup_by_event_id(authorization_ref)
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?
        .ok_or(AgentAuthRejection::ProofInvalid)?;

    if authorization.revoked_at.is_some() {
        return Err(AgentAuthRejection::AgentDeactivated.into());
    }
    if authorization.expires_at <= now {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !authorization
        .audience
        .iter()
        .any(|audience| audience == &proof.audience)
    {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    // The authorization MUST belong to this agent + verification method.
    if authorization.agent_principal_id != agent_principal_id
        || authorization.verification_method != verification_method
    {
        return Err(AgentAuthRejection::VerificationMethodPrincipalMismatch.into());
    }
    // Verify the proof signature over the same canonical signed-fields shape
    // the pairing PoP used, against the authorized public key.
    let signed_fields = ProofSignedFields {
        audience: &proof.audience,
        challenge: &proof.challenge,
        nonce: Some(nonce),
        expires_at,
        request_canonical_digest: proof.request_canonical_digest.as_str(),
        verification_method,
    };
    verify_proof_signature(
        &authorization.public_key_multibase,
        &signed_fields,
        &proof.signature,
    )?;

    // Replay defense: consume the challenge exactly once. A replayed challenge
    // (or one already consumed within the grace window) fails closed.
    let prune_after = expires_at + AGENT_PROOF_REPLAY_GRACE;
    let won = repo
        .agent_key_authorization()
        .consume_proof_challenge(
            rng,
            clock,
            NewAgentSessionProofReplay {
                agent_principal_id: agent_principal_id.clone(),
                verification_method: verification_method.to_owned(),
                challenge: proof.challenge.clone(),
                nonce: nonce.to_owned(),
                request_canonical_digest: proof.request_canonical_digest.as_str().to_owned(),
                audience: proof.audience.clone(),
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
    let scope_request: AgentScopeRequestInput = if body.agent_scope_request.is_null() {
        AgentScopeRequestInput::default()
    } else {
        serde_json::from_value(body.agent_scope_request.clone())
            .map_err(|_| AgentAuthRejection::ProofInvalid)?
    };

    let requests_act_on_behalf = scope_request
        .participation
        .iter()
        .any(|entry| entry.effective.act_on_behalf);
    if requests_act_on_behalf {
        // Opaque UUIDv7 artifact id (CKP-0008 §4.6); the controller resolves it
        // out-of-band, the agent runtime never renders a UI for it.
        let approval_request_id = new_prefixed_uuid7("");
        return Err(AgentSessionProofError::HumanApprovalRequired(
            AgentHumanApprovalRequired {
                approval_request_id,
            },
        ));
    }

    let controller_did = authorization.accountable_principal_id.clone();
    let active_grants = repo
        .accountability_grant()
        .list_active_for_subject(
            AccountabilitySubjectKind::AgentPrincipalId,
            &agent_principal_id,
        )
        .await
        .map_err(|_| AgentAuthRejection::AccountabilityGrantMissing)?
        .into_iter()
        .filter(|grant| {
            grant.controller_did == controller_did
                && grant.agent_principal_id == agent_principal_id
                && grant.revoked_at.is_none()
        })
        .collect::<Vec<_>>();
    if active_grants.is_empty() {
        return Err(AgentAuthRejection::AccountabilityGrantMissing.into());
    }
    let capability_scope = AgentSessionCapabilityScope::from_active_grants(&active_grants);

    let policy_snapshot = repo
        .policy_data()
        .get()
        .await
        .map_err(|_| AgentAuthRejection::PolicyUnavailable)?;
    let mut realm_policy = policy_snapshot
        .as_ref()
        .and_then(|snapshot| AgentSessionRealmPolicy::from_policy_data(&snapshot.data));
    if let (Some(snapshot), Some(policy)) = (policy_snapshot.as_ref(), realm_policy.as_mut()) {
        policy.policy_refs.insert(snapshot.id.to_string());
    }
    let policy_data = policy_snapshot.as_ref().map(|snapshot| &snapshot.data);

    let effective_scope = intersect_agent_session_scope(
        authorization.agent_key_scope.as_str(),
        &body.requested_scope,
        &scope_request,
        &capability_scope,
        realm_policy.as_ref(),
        policy_data,
        &agent_principal_id,
    )?;

    let mut constraints = serde_json::json!({
        "allowed_tracks": effective_scope.allowed_tracks,
        "allowed_data_classes": effective_scope.allowed_data_classes,
        "allowed_endpoints": effective_scope.allowed_endpoints,
    });
    if !effective_scope.strand_ids.is_empty() {
        constraints["allowed_strand_ids"] = serde_json::to_value(&effective_scope.strand_ids)
            .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    }

    let mut scope_details = serde_json::json!({
        "realm_ids": effective_scope.realm_ids,
        "strand_ids": effective_scope.strand_ids,
        "constraints": constraints,
        "capability_grant_refs": effective_scope.capability_grant_refs,
        "policy_refs": effective_scope.policy_refs,
    });
    if !scope_request.participation.is_empty() {
        scope_details["participation"] = serde_json::to_value(&scope_request.participation)
            .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    }
    // TTL: cap to the spec ceiling (≤ 15 min), never wider than the
    // (human-oriented) configured grant TTL.
    let configured = cokret_config.session_grant_ttl;
    let ttl = if configured < AGENT_SESSION_MAX_TTL {
        configured
    } else {
        AGENT_SESSION_MAX_TTL
    };

    Ok(AgentSessionAuthorization {
        agent_principal_id,
        controller_did,
        granted_scope: effective_scope.granted_scope,
        scope_details,
        ttl,
    })
}

fn canonical_session_grant_request_digest_without_signature(
    body: &cokret_core::SessionGrantRequestBody,
) -> Result<String, AgentAuthRejection> {
    let mut value = serde_json::to_value(body).map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let proof = value
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or(AgentAuthRejection::ProofInvalid)?;
    proof.remove("signature");
    proof.remove("request_canonical_digest");
    canonical_sha256(&value).map_err(|_| AgentAuthRejection::ProofInvalid)
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

impl AgentSessionCapabilityScope {
    fn from_active_grants(grants: &[AccountabilityGrant]) -> Self {
        let mut scope = Self::default();
        for grant in grants {
            scope.actions.extend(
                grant
                    .capabilities
                    .iter()
                    .map(|action| action.trim().to_owned()),
            );
            scope
                .grant_refs
                .insert(grant.accountability_grant_id.clone());
            merge_capability_projection(&grant.soland_fanout_payload, &mut scope);
        }
        scope.actions.retain(|action| !action.is_empty());
        scope
    }
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
    agent_principal_id: &str,
) -> Result<EffectiveAgentSessionScope, AgentAuthRejection> {
    let key_scope =
        intersect_requested_scope_with_agent_key_scope(agent_key_scope, requested_scope)?;
    let mut granted_scope = key_scope
        .into_iter()
        .filter(|token| capability_scope.actions.contains(token))
        .collect::<Vec<_>>();
    if granted_scope.is_empty() {
        return Err(AgentAuthRejection::CapabilityDenied);
    }

    if let Some(policy) = realm_policy
        && let Some(policy_actions) = policy.actions.as_ref()
    {
        granted_scope.retain(|token| policy_actions.contains(token));
        if granted_scope.is_empty() {
            return Err(AgentAuthRejection::PolicyViolation);
        }
    }

    let resource_scoped = granted_scope
        .iter()
        .any(|token| realm_resource_scope_token(token))
        || scope_request_has_resource_selectors(scope_request);

    let (
        realm_ids,
        strand_ids,
        allowed_tracks,
        allowed_data_classes,
        allowed_endpoints,
        policy_refs,
    ) = if resource_scoped {
        let policy = realm_policy.ok_or(AgentAuthRejection::PolicyUnavailable)?;
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
        let allowed_tracks = materialize_optional_selector(
            &scope_request.track_names,
            capability_scope.allowed_tracks.as_ref(),
            policy.allowed_tracks.as_ref(),
        )?;
        let allowed_data_classes = materialize_optional_constraint(
            capability_scope.allowed_data_classes.as_ref(),
            policy.allowed_data_classes.as_ref(),
        )?;
        let allowed_endpoints = materialize_optional_constraint(
            capability_scope.allowed_endpoints.as_ref(),
            policy.allowed_endpoints.as_ref(),
        )?;

        let policy_data = policy_data.ok_or(AgentAuthRejection::PolicyUnavailable)?;
        granted_scope.retain(|token| {
            realm_policy_allows_session_scope(policy_data, agent_principal_id, token, &realm_ids)
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
                realm_policy_allows_session_scope(policy_data, agent_principal_id, token, &[])
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

    if normalized
        .iter()
        .any(|token| !scope_token_allowed_by_agent_key_scope(agent_key_scope, token))
    {
        return Err(AgentAuthRejection::ProofInvalid);
    }

    Ok(normalized)
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

fn realm_resource_scope_token(token: &str) -> bool {
    token.starts_with("ck.self.events.")
        || token.starts_with("ck.applet.")
        || token.starts_with("ck.message.")
        || token.starts_with("ck.reaction.")
        || token.starts_with("ck.strand.")
        || token.starts_with("ck.space.")
        || token.starts_with("ck.blob.")
        || token.starts_with("ck.call.")
        || token.starts_with("ck.morph.")
        || token.starts_with("ck.relation.")
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
    agent_principal_id: &str,
    action: &str,
    realm_ids: &[String],
) -> bool {
    if policy_scope_rejects_session_scope(policy_data, agent_principal_id, action) {
        return false;
    }

    if let Some(default_scope) = policy_data
        .get("realms")
        .and_then(|realms| realms.get("default"))
        && policy_scope_rejects_session_scope(default_scope, agent_principal_id, action)
    {
        return false;
    }

    for realm_id in realm_ids {
        if let Some(realm_scope) = policy_data
            .get("realms")
            .and_then(|realms| realms.get(realm_id.as_str()))
            && policy_scope_rejects_session_scope(realm_scope, agent_principal_id, action)
        {
            return false;
        }
    }

    true
}

fn policy_scope_rejects_session_scope(
    scope: &Value,
    agent_principal_id: &str,
    action: &str,
) -> bool {
    value_contains_str(scope.get("deny_actors"), agent_principal_id)
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

fn merge_capability_projection(value: &Value, scope: &mut AgentSessionCapabilityScope) {
    visit_agent_scope_projection_objects(value, &mut |projection| {
        if let Some(actions) = read_string_set(
            projection,
            &["actions", "capabilities", "granted_scope", "scope"],
        ) {
            scope.actions.extend(actions);
        }
        merge_optional_set(
            &mut scope.realm_ids,
            read_string_set(projection, &["realm_ids", "allowed_realm_ids"]),
        );
        merge_optional_set(
            &mut scope.strand_ids,
            read_string_set(projection, &["strand_ids", "allowed_strand_ids"]),
        );
        merge_optional_set(
            &mut scope.allowed_tracks,
            read_string_set(projection, &["allowed_tracks"]),
        );
        merge_optional_set(
            &mut scope.allowed_data_classes,
            read_string_set(projection, &["allowed_data_classes"]),
        );
        merge_optional_set(
            &mut scope.allowed_endpoints,
            read_string_set(projection, &["allowed_endpoints"]),
        );
        if let Some(constraints) = projection.get("constraints") {
            merge_optional_set(
                &mut scope.strand_ids,
                read_string_set(constraints, &["allowed_strand_ids", "strand_ids"]),
            );
            merge_optional_set(
                &mut scope.allowed_tracks,
                read_string_set(constraints, &["allowed_tracks"]),
            );
            merge_optional_set(
                &mut scope.allowed_data_classes,
                read_string_set(constraints, &["allowed_data_classes"]),
            );
            merge_optional_set(
                &mut scope.allowed_endpoints,
                read_string_set(constraints, &["allowed_endpoints"]),
            );
        }
        if let Some(refs) = read_string_set(
            projection,
            &[
                "capability_grant_refs",
                "accountability_grant_refs",
                "grant_refs",
            ],
        ) {
            scope.grant_refs.extend(refs);
        }
    });
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

fn scope_token_allowed_by_agent_key_scope(agent_key_scope: &str, token: &str) -> bool {
    match agent_key_scope {
        AGENT_KEY_SCOPE_LIMITED => limited_agent_scope_token_allowed(token),
        AGENT_KEY_SCOPE_APPLET => applet_agent_scope_token_allowed(token),
        AGENT_KEY_SCOPE_REALM => realm_agent_scope_token_allowed(token),
        AGENT_KEY_SCOPE_ACCOUNT => account_agent_scope_token_allowed(token),
        _ => false,
    }
}

fn limited_agent_scope_token_allowed(token: &str) -> bool {
    matches!(
        token,
        "ck.self.events.query.describe"
            | "ck.self.events.command.submit"
            | "ck.self.events.resource.get"
            | "ck.self.events.query.resolve"
            | "ck.self.events.query.scan"
            | "ck.self.events.stream.subscribe"
            | "ck.self.events.query.frontier"
            | "ck.message.create"
            | "ck.reaction.add"
    )
}

fn applet_agent_scope_token_allowed(token: &str) -> bool {
    limited_agent_scope_token_allowed(token)
        || matches!(
            token,
            "ck.applet.query.describe"
                | "ck.applet.resource.get"
                | "ck.applet.command.invoke"
                | "ck.applet.action.request"
        )
}

fn realm_agent_scope_token_allowed(token: &str) -> bool {
    if token.starts_with("ck.account.")
        || token.starts_with("ck.admin.")
        || token.starts_with("ck.self.agent.")
        || token.starts_with("ck.gate.")
    {
        return false;
    }

    limited_agent_scope_token_allowed(token)
        || token.starts_with("ck.message.")
        || token.starts_with("ck.reaction.")
        || token.starts_with("ck.strand.")
        || token.starts_with("ck.space.")
        || token.starts_with("ck.blob.")
        || token.starts_with("ck.call.")
        || token.starts_with("ck.morph.")
        || token.starts_with("ck.relation.")
}

fn account_agent_scope_token_allowed(token: &str) -> bool {
    if token.starts_with("ck.admin.")
        || token.starts_with("ck.gate.")
        || token.starts_with("ck.self.agent.")
    {
        return false;
    }

    token.starts_with("ck.self.events.")
        || token.starts_with("ck.self.account.")
        || token.starts_with("ck.account.")
        || realm_agent_scope_token_allowed(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn capability_scope(actions: &[&str]) -> AgentSessionCapabilityScope {
        AgentSessionCapabilityScope {
            actions: set(actions),
            grant_refs: set(&["ck:grant:capability"]),
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

    #[test]
    fn limited_agent_key_scope_dedupes_and_allows_runtime_scope() {
        let scope = intersect_requested_scope_with_agent_key_scope(
            AGENT_KEY_SCOPE_LIMITED,
            &[
                " ck.self.events.command.submit ".to_owned(),
                "ck.message.create".to_owned(),
                "ck.self.events.command.submit".to_owned(),
                "ck.reaction.add".to_owned(),
            ],
        )
        .expect("limited runtime scope should be accepted");

        assert_eq!(
            scope,
            vec![
                "ck.message.create".to_owned(),
                "ck.reaction.add".to_owned(),
                "ck.self.events.command.submit".to_owned(),
            ]
        );
    }

    #[test]
    fn limited_agent_key_scope_rejects_admin_or_control_surface() {
        let err = intersect_requested_scope_with_agent_key_scope(
            AGENT_KEY_SCOPE_LIMITED,
            &["ck.self.agent.command.deactivate".to_owned()],
        )
        .expect_err("limited key must not mint control-plane scope");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn realm_agent_key_scope_rejects_account_surface() {
        let err = intersect_requested_scope_with_agent_key_scope(
            AGENT_KEY_SCOPE_REALM,
            &["ck.account.status".to_owned()],
        )
        .expect_err("realm key must not mint account-surface scope");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn unknown_agent_key_scope_rejects_fail_closed() {
        let err = intersect_requested_scope_with_agent_key_scope(
            "delegated-root",
            &["ck.self.events.query.scan".to_owned()],
        )
        .expect_err("unknown key tiers must fail closed");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn empty_requested_scope_rejects_after_normalization() {
        let err = intersect_requested_scope_with_agent_key_scope(
            AGENT_KEY_SCOPE_LIMITED,
            &[" ".to_owned(), String::new()],
        )
        .expect_err("empty scope must fail closed");

        assert_eq!(err, AgentAuthRejection::ProofInvalid);
    }

    #[test]
    fn session_scope_is_requested_key_grant_policy_intersection() {
        let mut capability_scope = capability_scope(&["ck.message.create", "ck.reaction.add"]);
        capability_scope.realm_ids = Some(set(&["realm-a", "realm-b"]));
        capability_scope.allowed_tracks = Some(set(&["main", "ops"]));

        let mut policy_scope = policy_scope(Some(&["ck.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-b", "realm-c"]));
        policy_scope.allowed_tracks = Some(set(&["main"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned(), "realm-b".to_owned()],
            track_names: vec!["main".to_owned(), "ops".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let effective_scope = intersect_agent_session_scope(
            AGENT_KEY_SCOPE_REALM,
            &["ck.message.create".to_owned(), "ck.reaction.add".to_owned()],
            &scope_request,
            &capability_scope,
            Some(&policy_scope),
            Some(&policy_data),
            "did:example:agent",
        )
        .expect("session scope should be narrowed to the four-way intersection");

        assert_eq!(effective_scope.granted_scope, vec!["ck.message.create"]);
        assert_eq!(effective_scope.realm_ids, vec!["realm-b"]);
        assert_eq!(effective_scope.allowed_tracks, vec!["main"]);
        assert_eq!(
            effective_scope.capability_grant_refs,
            vec!["ck:grant:capability"]
        );
        assert_eq!(effective_scope.policy_refs, vec!["policy:2026-06-19"]);
    }

    #[test]
    fn resource_scope_without_capability_selector_rejects_fail_closed() {
        let capability_scope = capability_scope(&["ck.message.create"]);
        let mut policy_scope = policy_scope(Some(&["ck.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-a"]));
        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let err = intersect_agent_session_scope(
            AGENT_KEY_SCOPE_REALM,
            &["ck.message.create".to_owned()],
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
        let mut capability_scope = capability_scope(&["ck.message.create"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));
        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };

        let err = intersect_agent_session_scope(
            AGENT_KEY_SCOPE_REALM,
            &["ck.message.create".to_owned()],
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
        let mut capability_scope = capability_scope(&["ck.message.create"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));

        let mut policy_scope = policy_scope(Some(&["ck.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-a"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({
            "realms": {
                "realm-a": {
                    "deny_actions": ["ck.message.create"]
                }
            }
        });

        let err = intersect_agent_session_scope(
            AGENT_KEY_SCOPE_REALM,
            &["ck.message.create".to_owned()],
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
        let mut capability_scope = capability_scope(&["ck.message.create"]);
        capability_scope.realm_ids = Some(set(&["realm-a"]));
        capability_scope.allowed_tracks = Some(set(&["main"]));

        let mut policy_scope = policy_scope(Some(&["ck.message.create"]));
        policy_scope.realm_ids = Some(set(&["realm-a"]));
        policy_scope.allowed_tracks = Some(set(&["ops"]));

        let scope_request = AgentScopeRequestInput {
            realm_ids: vec!["realm-a".to_owned()],
            track_names: vec!["main".to_owned()],
            ..AgentScopeRequestInput::default()
        };
        let policy_data = serde_json::json!({});

        let err = intersect_agent_session_scope(
            AGENT_KEY_SCOPE_REALM,
            &["ck.message.create".to_owned()],
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
        let mut body = cokret_core::SessionGrantRequestBody {
            principal_id: Some(cokret_core::Did::new("did:web:agent.example").unwrap()),
            device_id: None,
            requested_scope: vec!["ck.message.create".to_owned()],
            agent_key_authorization_ref: Some(
                "ck:event:01970000-0000-7000-8000-000000000021".to_owned(),
            ),
            agent_scope_request: serde_json::json!({
                "realm_ids": ["ck:realm:01970000-0000-7000-8000-000000000000"]
            }),
            proof: cokret_core::SessionGrantRequestProof {
                proof_kind: cokret_core::SessionGrantProofKind::AgentKeyProof,
                challenge: "challenge-abc".to_owned(),
                request_canonical_digest: cokret_core::Hash::new(format!(
                    "sha256:{}",
                    "0".repeat(64)
                ))
                .unwrap(),
                audience: "https://cokret.example/_cokret".to_owned(),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(5)),
                signature: "sig-a".to_owned(),
                verification_method: Some("did:web:agent.example#runtime-key-1".to_owned()),
                issuer: None,
                client_id: None,
                redirect_uri: None,
                state: None,
                nonce: Some("nonce-abc".to_owned()),
                authorization_code: None,
                code_verifier: None,
            },
        };
        let digest = canonical_session_grant_request_digest_without_signature(&body)
            .expect("request digest should compute");
        body.proof.request_canonical_digest = cokret_core::Hash::new(digest.clone()).unwrap();

        let mut signature_changed = body.clone();
        signature_changed.proof.signature = "sig-b".to_owned();
        assert_eq!(
            canonical_session_grant_request_digest_without_signature(&signature_changed).unwrap(),
            digest
        );

        let mut scope_changed = body.clone();
        scope_changed
            .requested_scope
            .push("ck.reaction.add".to_owned());
        assert_ne!(
            canonical_session_grant_request_digest_without_signature(&scope_changed).unwrap(),
            digest
        );
    }
}
