//! CKP-0008 §4.6 agent runtime authentication (`agent_key_proof` branch of
//! `ck.gate.account.command.issue_session_grant`).
//!
//! This is the independent validator the session-grant endpoint calls; it MUST
//! NOT fall back to the password / OIDC / passkey validators.

use std::collections::BTreeSet;

use coauth_config::CokretConfig;
use coauth_data::RepositoryAccess;
use coauth_data::agent_key::NewAgentSessionProofReplay;
use cokret_core::identifiers::new_prefixed_uuid7;
use serde::Deserialize;

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
    /// Effective granted scope (intersection of requested scope and the
    /// authorized key scope).
    pub granted_scope: Vec<String>,
    /// `scope_details` overlay (realm_ids / strand_ids / track_names +
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

    // coauth enforces the key-tier ceiling here. soland's resource-edge
    // capability evaluator still narrows per-resource by capability grant and
    // Realm policy before accepting reads or writes.
    let granted_scope = intersect_requested_scope_with_agent_key_scope(
        authorization.agent_key_scope.as_str(),
        &body.requested_scope,
    )?;

    // scope_details overlay: echo the requested narrowing + resolved
    // participation entries (the controller-approved effective participation).
    let mut scope_details = serde_json::json!({
        "realm_ids": scope_request.realm_ids,
        "strand_ids": scope_request.strand_ids,
        "track_names": scope_request.track_names,
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
        controller_did: authorization.accountable_principal_id,
        granted_scope,
        scope_details,
        ttl,
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
}
