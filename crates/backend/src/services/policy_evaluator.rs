// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 — pluggable evaluator for `ak.self.policy.read.check`.
//!
//! The spec [`policy-server.md` §4] defines the decision lattice as
//! `allow | soft_deny | hard_deny | quarantine | require_review`; the
//! Wire type [`arkret_wire::AuthzDecision`] exposes these as
//! `Allow | Deny | Quarantine | RequireReview | SoftFail`. This module
//! is responsible for picking one of those values, plus the
//! `reason_code` and the optional `obligations` array, for every
//! incoming `PolicyCheckRequestBody`.
//!
//! ## Why a separate trait
//!
//! The pre-round-4 `coauth_policy::PolicyFactory` evaluator only understands
//! `register` / `email` / `client_registration` / `authorization_grant`
//! shapes — it predates the round-4 `ak.self.policy.read.check` request and does
//! not know about realm scoping or frontier digests. Bolting a new
//! method onto it would force every existing handler to re-test. We
//! ship a dedicated [`PolicyEvaluator`] trait here and leave the
//! pre-round-4 evaluator alone.
//!
//! ## Default implementation
//!
//! [`RuleEvaluator`] loads the realm-scoped rules from the existing
//! `policy_data` table (`PolicyDataRepository::get`) and matches the
//! request against three lists kept in the loose JSON:
//!
//! - `deny_actors[]` — DIDs that are unconditionally denied (`hard_deny`).
//! - `deny_actions[]` — action tokens that are unconditionally denied.
//! - `throttle_actions` — actions that are rate limited (`soft_deny` with a signed
//!   `next_retry_at`); either a bare action list or an object keyed by action carrying
//!   `retry_after_ms`.
//! - `require_review_actions[]` — actions that route to manual review.
//!
//! When the loose policy data is absent or empty we default to `allow`
//! with `reason_code = "ok"` while still threading the rest of the binding
//! (frontier, signature, audit) through the real path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arkret_models_collaboration::governance::policy_check::PolicyCheckRequestBody;
use arkret_wire::{AuthzDecision, CapabilityActionId, FreshnessState, ProfileId, ReasonCode};
use chrono::{DateTime, Utc};
use coauth_data::collaboration_capability::{
    CollaborationCapabilityGrant, is_collaboration_capability_action,
};
use coauth_data::{BoxRepositoryFactory, RepositoryAccess as _};
use serde_json::Value;
use thiserror::Error;

use crate::services::policy_frontier::Frontier;

/// Local (non-registry) reason codes. `"ok"` and `"policy_review_required"`
/// are evaluator-internal `reason_code` values that are NOT part of the
/// canonical `arkret_wire::error_codes::ERROR_CODE_*` wire-error registry, so
/// they are kept as local constants rather than aliased to SDK symbols.
/// Retry window applied when a `throttle_actions` rule names an action but
/// declares no `retry_after_ms` of its own.
const DEFAULT_THROTTLE_RETRY_AFTER_MS: u64 = 30_000;

/// CAP-2: returns true when the candidate resource selector wire string
/// is a complete event-derived `ak:circle:<44-char token>` typed id. The evaluator accepts `circle`
/// selectors verbatim as `deny_actors` / `deny_actions` / target lists
/// per `resource-selector-grammar.md` §6 (R3).
#[must_use]
pub fn is_circle_selector(selector: &str) -> bool {
    arkret_identifiers::CircleId::new(selector.to_owned()).is_ok()
}

#[derive(Debug, Error)]
pub enum EvaluatorError {
    #[error("evaluator deadline exceeded")]
    Timeout,
    #[error("evaluator backend failed: {0}")]
    Backend(String),
}

/// One slot in a [`PolicyDecision::obligations`] array. Mirrors the
/// loose `{kind, expires_at, payload}` shape the spec [`policy-server.md`
/// §4] documents under "obligations". We keep `payload` as
/// `serde_json::Value` so different obligation kinds (`rate_limit`,
/// `challenge`, `mask_field`, …) can carry their own typed payload
/// without forcing a sum type here.
#[derive(Debug, Clone)]
pub struct PolicyObligation {
    pub kind: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub payload: Value,
}

impl PolicyObligation {
    /// Render to the wire form embedded in
    /// [`arkret_models_collaboration::governance::policy_check::PolicyCheckOutcome::obligations`].
    pub fn to_wire(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("kind".to_owned(), Value::String(self.kind.clone()));
        if let Some(expires_at) = self.expires_at {
            obj.insert(
                "expires_at".to_owned(),
                Value::String(arkret_canonical::format_timestamp_canonical(expires_at)),
            );
        }
        if !self.payload.is_null() {
            obj.insert("payload".to_owned(), self.payload.clone());
        }
        Value::Object(obj)
    }
}

/// What the evaluator produces. The handler turns this into the wire
/// [`arkret_models_collaboration::governance::policy_check::PolicyCheckOutcome`].
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: AuthzDecision,
    /// Stable reason code per [`policy-server.md` §4]. MUST be set.
    pub reason_code: ReasonCode,
    /// Obligations the calling service MUST execute before / after
    /// applying the decision. Empty for plain `allow` paths.
    pub obligations: Vec<PolicyObligation>,
    /// Earliest time the caller may retry. [`policy-server.md` §4] keeps
    /// this to throttle / backoff paths, so every other decision leaves it
    /// `None` and the signed transcript omits the key entirely.
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Policy-source revision this decision was computed against. Empty
    /// string when the evaluator runs against the default (no
    /// `policy_data` row yet).
    pub policy_version: String,
}

impl PolicyDecision {
    /// Convenience: a permissive default for the absence of any
    /// configured rule. `policy_version` is the version string the
    /// caller is responsible for filling in (typically the
    /// `PolicyData::id` ulid or `"v1"`).
    #[must_use]
    pub fn allow(policy_version: String) -> Self {
        Self {
            decision: AuthzDecision::Allow,
            reason_code: ReasonCode::from_wire("ok"),
            obligations: Vec::new(),
            next_retry_at: None,
            policy_version,
        }
    }

    /// Convenience: hard deny with a stable reason code. Used by the
    /// fail-closed timeout path in the handler.
    #[must_use]
    pub fn hard_deny(reason_code: ReasonCode, policy_version: String) -> Self {
        Self {
            decision: AuthzDecision::HardDeny,
            reason_code,
            obligations: Vec::new(),
            next_retry_at: None,
            policy_version,
        }
    }

    /// Throttle path: the actor may retry the same action once
    /// `next_retry_at` has passed. This is the only decision shape that
    /// carries a retry time, and the `rate_limit` obligation and the retry
    /// time are produced together so a caller cannot honour one without the
    /// other.
    #[must_use]
    pub fn throttled(next_retry_at: DateTime<Utc>, bucket: String, policy_version: String) -> Self {
        Self {
            decision: AuthzDecision::SoftDeny,
            reason_code: ReasonCode::from_wire("spam_flood"),
            obligations: vec![PolicyObligation {
                kind: "rate_limit".to_owned(),
                expires_at: Some(next_retry_at),
                payload: serde_json::json!({"bucket": bucket}),
            }],
            next_retry_at: Some(next_retry_at),
            policy_version,
        }
    }
}

/// Evaluate a `ak.self.policy.read.check` request against the configured rules.
/// Object-safe: handlers carry an `Arc<dyn PolicyEvaluator>`.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate<'a>(
        &'a self,
        request: &'a PolicyCheckRequestBody,
        frontier: &'a Frontier,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, EvaluatorError>> + Send + 'a>>;
}

/// Default implementation backed by the postgres `policy_data` table.
/// Reads the latest row via [`PolicyDataRepository::get`] and matches
/// the request actor + action against the three rule lists.
pub struct RuleEvaluator {
    repository_factory: BoxRepositoryFactory,
    /// Maximum time the evaluator is allowed to spend reading rules
    /// before returning [`EvaluatorError::Timeout`]. Caller (the
    /// handler) layers an outer 2-second budget on top per the
    /// fail-closed contract; this inner budget is a safety net against
    /// pathological database stalls.
    inner_timeout: Duration,
}

impl RuleEvaluator {
    #[must_use]
    pub fn new(repository_factory: BoxRepositoryFactory) -> Self {
        Self {
            repository_factory,
            inner_timeout: Duration::from_millis(1_500),
        }
    }
}

impl PolicyEvaluator for RuleEvaluator {
    fn evaluate<'a>(
        &'a self,
        request: &'a PolicyCheckRequestBody,
        frontier: &'a Frontier,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, EvaluatorError>> + Send + 'a>> {
        Box::pin(async move {
            let work = async {
                let mut repo = self
                    .repository_factory
                    .create()
                    .await
                    .map_err(|e| EvaluatorError::Backend(e.to_string()))?;
                let rules = repo
                    .policy_data()
                    .get()
                    .await
                    .map_err(|e| EvaluatorError::Backend(e.to_string()))?;
                let collaboration_grants = if let Some(action) =
                    CapabilityActionId::from_wire(request.action.as_str())
                        .filter(|action| is_collaboration_capability_action(*action))
                {
                    repo.collaboration_capability_grant()
                        .list_active_for_subject_action(
                            request.actor_id.as_str(),
                            request.realm_id.as_str(),
                            action,
                        )
                        .await
                        .map_err(|e| EvaluatorError::Backend(e.to_string()))?
                } else {
                    Vec::new()
                };
                Ok::<_, EvaluatorError>((rules, collaboration_grants))
            };

            let (rules, collaboration_grants) =
                match tokio::time::timeout(self.inner_timeout, work).await {
                    Ok(Ok(rules)) => rules,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(EvaluatorError::Timeout),
                };

            let Some(rules) = rules else {
                // No policy_data row yet → default-allow path. We still
                // tag `policy_version = "default"` so the audit trail
                // distinguishes "matched default policy" from "matched
                // configured allow rule".
                return Ok(match_rules_with_grants(
                    &Value::Null,
                    request,
                    frontier,
                    "default",
                    &collaboration_grants,
                ));
            };

            let policy_version = rules.id.to_string();
            let decision = match_rules_with_grants(
                rules.data.as_json(),
                request,
                frontier,
                &policy_version,
                &collaboration_grants,
            );
            Ok(decision)
        })
    }
}

/// Pure rule-matcher; pulled out so unit tests can exercise it without
/// a postgres connection.
#[cfg(test)]
fn match_rules(
    data: &Value,
    request: &PolicyCheckRequestBody,
    frontier: &Frontier,
    policy_version: &str,
) -> PolicyDecision {
    match_rules_with_grants(data, request, frontier, policy_version, &[])
}

fn match_rules_with_grants(
    data: &Value,
    request: &PolicyCheckRequestBody,
    frontier: &Frontier,
    policy_version: &str,
    collaboration_grants: &[CollaborationCapabilityGrant],
) -> PolicyDecision {
    let actor_str = request.actor_id.as_str();
    let action_str = request.action.as_str();

    // Per-realm scope: rules MAY be nested under a `realms` object keyed
    // by realm id, with a `default` fall-through. When the loose JSON
    // is a flat object we treat it as the default scope.
    //
    // CAP-2 (R3 spec-sync) — when the request carries a circle target id
    // in `auth_context.circle_id` we ALSO consult a nested
    // `circles.<circle_id>` scope, allowing per-circle deny/review rules.
    // The flat rule list still applies for cases where the realm-scoped
    // rules don't carve out the circle.
    let realm_scope: &Value = data
        .get("realms")
        .and_then(|m| m.get(request.realm_id.as_str()))
        .unwrap_or(data);

    let circle_scope: Option<&Value> = request
        .auth_context
        .as_ref()
        .and_then(|context| context.get("circle_id"))
        .and_then(Value::as_str)
        .filter(|c| is_circle_selector(c))
        .and_then(|c| realm_scope.get("circles").and_then(|m| m.get(c)));

    let scopes: [&Value; 2] = match circle_scope {
        Some(circle) => [circle, realm_scope],
        None => [realm_scope, realm_scope],
    };

    if let Some(decision) =
        capability_action_gate_decision(data, &scopes, action_str, policy_version)
    {
        return decision;
    }

    for scope in scopes {
        if value_contains_str(scope.get("deny_actors"), actor_str) {
            return PolicyDecision {
                decision: AuthzDecision::HardDeny,
                reason_code: ReasonCode::from_wire(arkret_wire::ErrorCode::POLICY_VIOLATION),
                obligations: Vec::new(),
                next_retry_at: None,
                policy_version: policy_version.to_owned(),
            };
        }

        if value_contains_str(scope.get("deny_actions"), action_str) {
            return PolicyDecision {
                decision: AuthzDecision::HardDeny,
                reason_code: ReasonCode::from_wire(arkret_wire::ErrorCode::POLICY_VIOLATION),
                obligations: Vec::new(),
                next_retry_at: None,
                policy_version: policy_version.to_owned(),
            };
        }
    }

    for scope in scopes {
        if let Some(retry_after) = throttle_retry_after(scope, action_str) {
            return PolicyDecision::throttled(
                Utc::now() + retry_after,
                action_str.to_owned(),
                policy_version.to_owned(),
            );
        }
    }

    if freshness_requires_fail_closed(frontier.freshness_state, action_str) {
        return PolicyDecision {
            decision: AuthzDecision::HardDeny,
            reason_code: ReasonCode::RevocationFreshnessUnknown,
            obligations: vec![PolicyObligation {
                kind: "freshness_diagnostic".to_owned(),
                expires_at: None,
                payload: serde_json::json!({
                    "freshness_state": frontier.freshness_state,
                    "auth_state_digest": frontier.auth_state_digest,
                    "policy_frontier_digest": frontier.policy_frontier_digest,
                    "membership_frontier_digest": frontier.membership_frontier_digest,
                }),
            }],
            next_retry_at: None,
            policy_version: policy_version.to_owned(),
        };
    }

    for scope in scopes {
        if value_contains_str(scope.get("require_review_actions"), action_str) {
            return PolicyDecision {
                decision: AuthzDecision::RequireReview,
                reason_code: ReasonCode::from_wire("policy_review_required"),
                obligations: Vec::new(),
                next_retry_at: None,
                policy_version: policy_version.to_owned(),
            };
        }
    }

    if let Some(action) = CapabilityActionId::from_wire(action_str)
        .filter(|action| is_collaboration_capability_action(*action))
    {
        if collaboration_grants.iter().any(|grant| {
            collaboration_grant_matches_request(grant, request, action, chrono::Utc::now())
        }) {
            return PolicyDecision::allow(policy_version.to_owned());
        }
        return PolicyDecision::hard_deny(
            ReasonCode::from_wire("capability_denied"),
            policy_version.to_owned(),
        );
    }

    PolicyDecision::allow(policy_version.to_owned())
}

fn collaboration_grant_matches_request(
    grant: &CollaborationCapabilityGrant,
    request: &PolicyCheckRequestBody,
    action: CapabilityActionId,
    now: DateTime<Utc>,
) -> bool {
    grant.revoked_at.is_none()
        && grant.subject == request.actor_id.as_str()
        && grant.realm_id == request.realm_id.as_str()
        && grant.action == action
        && grant.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn capability_action_gate_decision(
    data: &Value,
    scopes: &[&Value],
    action: &str,
    policy_version: &str,
) -> Option<PolicyDecision> {
    if is_candidate_join_policy_action(action) {
        return Some(unsupported_feature(policy_version));
    }

    let descriptor = match arkret_schema::embedded_capability_action(action) {
        Ok(Some(descriptor)) => descriptor,
        Ok(None) => return Some(unsupported_feature(policy_version)),
        Err(error) => {
            tracing::warn!(
                error = %error,
                action = %action,
                "policy_evaluator: capability action registry unavailable, fail-closed"
            );
            return Some(PolicyDecision::hard_deny(
                ReasonCode::from_wire("policy_evaluator_error"),
                policy_version.to_owned(),
            ));
        }
    };

    if descriptor.profile.as_deref() == Some(ProfileId::CANDIDATE_JOIN_POLICY_V1) {
        return Some(unsupported_feature(policy_version));
    }
    if let Some(profile) = descriptor.profile.as_deref()
        && !profile_declared_for_policy(data, scopes, profile)
    {
        return Some(unsupported_feature(policy_version));
    }
    None
}

fn unsupported_feature(policy_version: &str) -> PolicyDecision {
    PolicyDecision::hard_deny(
        ReasonCode::from_wire(arkret_wire::ErrorCode::UNSUPPORTED_FEATURE),
        policy_version.to_owned(),
    )
}

fn is_candidate_join_policy_action(action: &str) -> bool {
    action == CapabilityActionId::REALM_JOIN_REVIEW
        || action == "ak.member.application"
        || action.starts_with("ak.member.application.")
}

fn profile_declared_for_policy(data: &Value, scopes: &[&Value], profile: &str) -> bool {
    policy_scope_declares_profile(data, profile)
        || scopes
            .iter()
            .any(|scope| policy_scope_declares_profile(scope, profile))
}

fn policy_scope_declares_profile(scope: &Value, profile: &str) -> bool {
    [
        "enabled_profile_refs",
        "claimed_profiles",
        "active_profiles",
        "profiles",
    ]
    .into_iter()
    .any(|field| profile_list_contains(scope.get(field), profile))
}

fn profile_list_contains(haystack: Option<&Value>, needle: &str) -> bool {
    haystack
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(needle)))
}

fn freshness_requires_fail_closed(freshness_state: FreshnessState, action: &str) -> bool {
    match freshness_state {
        FreshnessState::Fresh => false,
        FreshnessState::Stale | FreshnessState::Unknown => !is_local_pending_action(action),
    }
}

fn is_local_pending_action(action: &str) -> bool {
    matches!(
        action,
        "ak.message.create"
            | "ak.reaction.add"
            | "ak.read_cursor.advance"
            | "ak.strand.move"
            | "ak.strand.reorder"
    )
}

fn value_contains_str(haystack: Option<&Value>, needle: &str) -> bool {
    haystack
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(needle)))
}

/// Retry window a `throttle_actions` rule declares for `action`, if any.
///
/// The rule is either a bare action list — which takes the deployment default
/// window — or an object keyed by action carrying its own `retry_after_ms`.
/// A window of zero would tell the caller to retry immediately, which is not a
/// throttle, so it is treated as "no rule" rather than silently rounded up.
fn throttle_retry_after(scope: &Value, action: &str) -> Option<chrono::Duration> {
    let rule = scope.get("throttle_actions")?;
    let retry_after_ms = if rule.is_array() {
        value_contains_str(Some(rule), action).then_some(DEFAULT_THROTTLE_RETRY_AFTER_MS)?
    } else {
        let entry = rule.get(action)?;
        entry
            .get("retry_after_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_THROTTLE_RETRY_AFTER_MS)
    };
    if retry_after_ms == 0 {
        return None;
    }
    chrono::Duration::try_milliseconds(i64::try_from(retry_after_ms).ok()?)
}

/// Type alias for the depot-injected handle. The handler reads it via
/// `DepotExt::policy_evaluator`.
pub type PolicyEvaluatorHandle = Arc<dyn PolicyEvaluator>;

#[cfg(test)]
mod tests {
    use arkret_identifiers::{DidCoreId, Hash, RealmId};
    use arkret_models_collaboration::governance::policy_check::PolicyCheckSource;

    use super::*;

    fn req(actor: &str, action: &str) -> PolicyCheckRequestBody {
        PolicyCheckRequestBody {
            request_id: "req-1".into(),
            realm_id: RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
                .unwrap(),
            actor_id: DidCoreId::new(actor.to_owned()).unwrap(),
            device_id: None,
            action: action.to_owned(),
            request_canonical_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            source: PolicyCheckSource {
                service_id: DidCoreId::new("ak:did_core:web:soland.example").unwrap(),
                service_kind: "principal_server".into(),
                source_ip_digest: Some(Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap()),
                signed_transport: true,
            },
            event_preview: None,
            auth_context: None,
        }
    }

    fn frontier(freshness_state: FreshnessState) -> Frontier {
        let h = Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        Frontier {
            auth_state_digest: h.clone(),
            policy_frontier_digest: h.clone(),
            membership_frontier_digest: h,
            freshness_state,
            policy_version: Some("test".to_owned()),
        }
    }

    fn collaboration_grant(action: CapabilityActionId) -> CollaborationCapabilityGrant {
        CollaborationCapabilityGrant {
            id: "01HY0000000000000000000000".to_owned(),
            capability_grant_id: "ak:grant:AYdnNxQil6MnHQLqm01XNizblBlrjoob6Q1JlIVBUGig".to_owned(),
            grant_event_id: "ak:event:AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC".to_owned(),
            revoke_event_id: None,
            subject: "ak:did_core:web:alice.example".to_owned(),
            realm_id: "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO".to_owned(),
            action,
            expires_at: None,
            approval_evidence_ref: None,
            granted_by: "user:admin".to_owned(),
            granted_at: Utc::now(),
            revoked_at: None,
            grant_raw_payload_digest: format!("sha256:{}", "a".repeat(64)),
            grant_fanout_idempotency_key:
                "coauth:collaboration_capability_grant:01904100-0000-7000-8000-000000000010"
                    .to_owned(),
        }
    }

    #[test]
    fn empty_rules_yield_allow() {
        let data = serde_json::json!({});
        let r = req("ak:did_core:web:alice.example", "ak.message.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
        assert_eq!(d.reason_code.as_str(), "ok");
        assert!(d.next_retry_at.is_none());
    }

    #[test]
    fn throttled_action_carries_a_retry_time_and_a_rate_limit_obligation() {
        let data = serde_json::json!({
            "throttle_actions": {"ak.message.create": {"retry_after_ms": 45_000}}
        });
        let r = req("ak:did_core:web:alice.example", "ak.message.create");
        let before = Utc::now();
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");

        assert!(matches!(d.decision, AuthzDecision::SoftDeny));
        assert_eq!(d.reason_code.as_str(), "spam_flood");
        let next_retry_at = d.next_retry_at.expect("throttle must declare a retry time");
        assert!(next_retry_at >= before + chrono::Duration::milliseconds(45_000));
        assert_eq!(d.obligations.len(), 1);
        assert_eq!(d.obligations[0].kind, "rate_limit");
        assert_eq!(d.obligations[0].expires_at, Some(next_retry_at));
    }

    #[test]
    fn bare_throttle_action_list_uses_the_default_window() {
        let data = serde_json::json!({"throttle_actions": ["ak.message.create"]});
        let r = req("ak:did_core:web:alice.example", "ak.message.create");
        let before = Utc::now();
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");

        let next_retry_at = d.next_retry_at.expect("throttle must declare a retry time");
        assert!(
            next_retry_at
                >= before
                    + chrono::Duration::milliseconds(
                        i64::try_from(DEFAULT_THROTTLE_RETRY_AFTER_MS).unwrap()
                    )
        );
    }

    #[test]
    fn unthrottled_actions_and_zero_windows_leave_next_retry_at_absent() {
        // A zero window would tell the caller to retry immediately, which is
        // not a throttle — it must not surface as a signed retry time.
        for data in [
            serde_json::json!({"throttle_actions": ["ak.message.update"]}),
            serde_json::json!({"throttle_actions": {"ak.message.create": {"retry_after_ms": 0}}}),
        ] {
            let r = req("ak:did_core:web:alice.example", "ak.message.create");
            let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
            assert!(matches!(d.decision, AuthzDecision::Allow), "{data}");
            assert!(d.next_retry_at.is_none(), "{data}");
        }
    }

    #[test]
    fn deny_rules_outrank_a_throttle_on_the_same_action() {
        let data = serde_json::json!({
            "deny_actions": ["ak.message.create"],
            "throttle_actions": ["ak.message.create"]
        });
        let r = req("ak:did_core:web:alice.example", "ak.message.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");

        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert!(d.next_retry_at.is_none());
    }

    #[test]
    fn absent_rules_still_reject_candidate_join_policy_profile_action() {
        let r = req("ak:did_core:web:alice.example", "ak.realm.join.review");
        let d = match_rules(
            &Value::Null,
            &r,
            &frontier(FreshnessState::Fresh),
            "default",
        );
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "unsupported_feature");
    }

    #[test]
    fn candidate_join_policy_profile_action_cannot_be_enabled_by_loose_rules() {
        let data = serde_json::json!({
            "require_review_actions": ["ak.realm.join.review"]
        });
        let r = req("ak:did_core:web:alice.example", "ak.realm.join.review");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "unsupported_feature");
    }

    #[test]
    fn candidate_join_policy_profile_action_cannot_be_enabled_by_profile_claim() {
        let data = serde_json::json!({
            "enabled_profile_refs": ["ak.profile.candidate.join_policy.v1"],
            "require_review_actions": ["ak.realm.join.review"]
        });
        let r = req("ak:did_core:web:alice.example", "ak.realm.join.review");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "unsupported_feature");
    }

    #[test]
    fn bare_candidate_member_application_actions_fail_closed() {
        let data = serde_json::json!({});
        let r = req("ak:did_core:web:alice.example", "member.application.review");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "unsupported_feature");
    }

    #[test]
    fn unknown_capability_action_fails_closed() {
        let data = serde_json::json!({});
        let r = req("ak:did_core:web:alice.example", "ak.not_registered.action");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "unsupported_feature");
    }

    #[test]
    fn profile_capability_action_requires_declared_profile_and_grant() {
        let r = req("ak:did_core:web:alice.example", "ak.pin.add");

        let denied = match_rules(
            &serde_json::json!({}),
            &r,
            &frontier(FreshnessState::Fresh),
            "default",
        );
        assert!(matches!(denied.decision, AuthzDecision::HardDeny));
        assert_eq!(denied.reason_code.as_str(), "unsupported_feature");

        let missing_grant = match_rules(
            &serde_json::json!({
                "enabled_profile_refs": ["ak.profile.pinned_items.v1"]
            }),
            &r,
            &frontier(FreshnessState::Fresh),
            "v",
        );
        assert!(matches!(missing_grant.decision, AuthzDecision::HardDeny));
        assert_eq!(missing_grant.reason_code.as_str(), "capability_denied");

        let grant = collaboration_grant(CapabilityActionId::PinAdd);
        let allowed = match_rules_with_grants(
            &serde_json::json!({
                "enabled_profile_refs": ["ak.profile.pinned_items.v1"]
            }),
            &r,
            &frontier(FreshnessState::Fresh),
            "v",
            &[grant],
        );
        assert!(matches!(allowed.decision, AuthzDecision::Allow));
        assert_eq!(allowed.reason_code.as_str(), "ok");
    }

    #[test]
    fn expired_collaboration_capability_grant_denies() {
        let r = req("ak:did_core:web:alice.example", "ak.pin.add");
        let mut grant = collaboration_grant(CapabilityActionId::PinAdd);
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));

        let denied = match_rules_with_grants(
            &serde_json::json!({
                "enabled_profile_refs": ["ak.profile.pinned_items.v1"]
            }),
            &r,
            &frontier(FreshnessState::Fresh),
            "v",
            &[grant],
        );
        assert!(matches!(denied.decision, AuthzDecision::HardDeny));
        assert_eq!(denied.reason_code.as_str(), "capability_denied");
    }

    #[test]
    fn deny_actor_matches() {
        let data = serde_json::json!({
            "deny_actors": ["ak:did_core:web:mallory.example"]
        });
        let r = req("ak:did_core:web:mallory.example", "ak.message.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "policy_violation");
    }

    #[test]
    fn deny_action_matches() {
        let data = serde_json::json!({
            "deny_actions": ["ak.invite.create"]
        });
        let r = req("ak:did_core:web:alice.example", "ak.invite.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
    }

    #[test]
    fn require_review_action_matches() {
        let data = serde_json::json!({
            "require_review_actions": ["ak.invite.create"]
        });
        let r = req("ak:did_core:web:alice.example", "ak.invite.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::RequireReview));
        assert_eq!(d.reason_code.as_str(), "policy_review_required");
    }

    #[test]
    fn unknown_freshness_fails_closed_for_high_risk_action() {
        let data = serde_json::json!({});
        let r = req("ak:did_core:web:alice.example", "ak.capability.revoke");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Unknown), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "revocation_freshness_unknown");
        assert_eq!(d.obligations[0].kind, "freshness_diagnostic");
    }

    #[test]
    fn unknown_freshness_keeps_local_pending_actions_out_of_high_risk_bucket() {
        let data = serde_json::json!({});
        let r = req("ak:did_core:web:alice.example", "ak.message.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Unknown), "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
        assert_eq!(d.reason_code.as_str(), "ok");
    }

    #[test]
    fn realm_scope_overrides_default() {
        let data = serde_json::json!({
            "deny_actors": ["ak:did_core:web:alice.example"],
            "realms": {
                "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO": {
                    // Realm-specific scope: NO deny_actors, so alice is
                    // allowed in this realm even though the default
                    // scope would deny her.
                    "deny_actions": ["ak.evil"]
                }
            }
        });
        let r = req("ak:did_core:web:alice.example", "ak.message.create");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
    }

    #[test]
    fn cap1_deny_action_on_cx_call_join_matches() {
        let data = serde_json::json!({
            "deny_actions": ["ak.call.join"]
        });
        let r = req("ak:did_core:web:alice.example", "ak.call.join");
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code.as_str(), "policy_violation");
    }

    #[test]
    fn cap2_circle_selector_accepts_valid_typed_id() {
        assert!(is_circle_selector(
            "ak:circle:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
        ));
        assert!(!is_circle_selector("not-a-circle"));
        assert!(!is_circle_selector(
            "ak:space:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
        ));
    }

    #[test]
    fn cap2_circle_scoped_deny_overrides_realm_default() {
        let circle_id = "ak:circle:AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC";
        let data = serde_json::json!({
            "circles": {
                circle_id: {
                    "deny_actions": ["ak.call.record"],
                }
            }
        });
        let mut r = req("ak:did_core:web:alice.example", "ak.call.record");
        r.auth_context =
            Some(serde_json::from_value(serde_json::json!({ "circle_id": circle_id })).unwrap());
        let d = match_rules(&data, &r, &frontier(FreshnessState::Fresh), "v");
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
    }

    #[test]
    fn obligation_wire_form_includes_kind_and_payload() {
        let o = PolicyObligation {
            kind: "rate_limit".to_owned(),
            expires_at: None,
            payload: serde_json::json!({"bucket": "message", "remaining": 20}),
        };
        let wire = o.to_wire();
        assert_eq!(wire["kind"], "rate_limit");
        assert_eq!(wire["payload"]["bucket"], "message");
        assert!(wire.get("expires_at").is_none());
    }
}
