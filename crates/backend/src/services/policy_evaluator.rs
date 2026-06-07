// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 — pluggable evaluator for `ck.self.policy.check`.
//!
//! The spec [`policy-server.md` §4] defines the decision lattice as
//! `allow | soft_deny | hard_deny | quarantine | require_review`; the
//! SDK type [`cokret_core::AuthzDecision`] exposes these as
//! `Allow | Deny | Quarantine | RequireReview | SoftFail`. This module
//! is responsible for picking one of those values, plus the
//! `reason_code` and the optional `obligations` array, for every
//! incoming `PolicyCheckRequestBody`.
//!
//! ## Why a separate trait
//!
//! The legacy `coauth_policy::PolicyFactory` evaluator only understands
//! `register` / `email` / `client_registration` / `authorization_grant`
//! shapes — it predates the round-4 `ck.self.policy.check` request and does
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
//! - `require_review_actions[]` — actions that route to manual review.
//!
//! When the loose policy data is absent or empty we default to `allow`
//! with `reason_code = "ok"` — which preserves the legacy stub
//! behaviour while still threading the rest of the binding (frontier,
//! signature, audit) through the real path.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use coauth_data::{BoxRepositoryFactory, RepositoryAccess as _};
use cokret_core::{
    AuthzDecision, CAP_ACTION_CALL_JOIN, CAP_ACTION_CALL_MODERATE, CAP_ACTION_CALL_RECORD,
    CAP_ACTION_CALL_SCREEN_SHARE, CAP_ACTION_CALL_TRANSCRIBE, PolicyCheckRequestBody,
};
use serde_json::Value;
use thiserror::Error;

use crate::services::policy_frontier::Frontier;

/// Local (non-registry) reason codes. `"ok"` and `"policy_review_required"`
/// are evaluator-internal `reason_code` values that are NOT part of the
/// canonical `cokret_core::error::ERROR_CODE_*` wire-error registry, so
/// they are kept as local constants rather than aliased to SDK symbols.
const REASON_CODE_OK: &str = "ok";
const REASON_CODE_POLICY_REVIEW_REQUIRED: &str = "policy_review_required";

/// CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — call /
/// media capability actions registered in
/// `capability-action-registry.json`. CAP-1: capability evaluator MUST
/// recognise these five actions so deny/review/allow rules can target
/// them by name. Mirrors `cokret_core::CALL_CAPABILITY_ACTIONS`.
pub const RECOGNISED_CALL_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CALL_JOIN,
    CAP_ACTION_CALL_SCREEN_SHARE,
    CAP_ACTION_CALL_RECORD,
    CAP_ACTION_CALL_TRANSCRIBE,
    CAP_ACTION_CALL_MODERATE,
];

/// CAP-1: returns true when `action` is one of the five CKP-0010 call /
/// media capability actions. Used by handlers that need to short-circuit
/// validation when the realm policy hasn't loaded yet but the action is
/// nevertheless known to the evaluator.
#[must_use]
pub fn is_recognised_call_capability_action(action: &str) -> bool {
    RECOGNISED_CALL_CAPABILITY_ACTIONS.contains(&action)
}

/// CAP-2: returns true when the candidate resource selector wire string
/// is a `ck:circle:<uuid>` typed id. The evaluator accepts `circle`
/// selectors verbatim as `deny_actors` / `deny_actions` / target lists
/// per `resource-selector-grammar.md` §6 (R3).
#[must_use]
pub fn is_circle_selector(selector: &str) -> bool {
    cokret_core::CircleId::new(selector.to_owned()).is_ok()
}

/// POLICY-1: deployment-level "strict reject" mode for unverified
/// `accountable_principal_ids[]` entries. When the
/// `ck.profile.accountable_principals.strict_reject.v1` profile is
/// declared by the deployment, Actor Profile create/update events that
/// carry unverified `accountable_principal_ids[]` entries
/// MUST be rejected wholesale with `failed_precondition /
/// accountability_grant_missing`. Otherwise, the legacy strip+audit-log
/// path applies.
///
/// Signalled to the reducer / submit endpoint via shared policy
/// decisions: see [`PolicyDecision::strict_reject_accountable_principals`] and
/// the `obligations[]` carrying the `accountability_grant_required`
/// kind so the caller knows the reducer will hard-reject rather than
/// strip.
#[must_use]
pub fn strict_reject_profile_active(profile_ids: &[&str]) -> bool {
    profile_ids.contains(&"ck.profile.accountable_principals.strict_reject.v1")
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
    /// [`cokret_core::PolicyCheckOutcome::obligations`].
    pub fn to_wire(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("kind".to_owned(), Value::String(self.kind.clone()));
        if let Some(expires_at) = self.expires_at {
            obj.insert(
                "expires_at".to_owned(),
                Value::String(expires_at.to_rfc3339()),
            );
        }
        if !self.payload.is_null() {
            obj.insert("payload".to_owned(), self.payload.clone());
        }
        Value::Object(obj)
    }
}

/// What the evaluator produces. The handler turns this into the wire
/// [`cokret_core::PolicyCheckOutcome`].
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: AuthzDecision,
    /// Stable reason code per [`policy-server.md` §4]. MUST be set.
    pub reason_code: String,
    /// Obligations the calling service MUST execute before / after
    /// applying the decision. Empty for plain `allow` paths.
    pub obligations: Vec<PolicyObligation>,
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
            reason_code: REASON_CODE_OK.to_owned(),
            obligations: Vec::new(),
            policy_version,
        }
    }

    /// Convenience: hard deny with a stable reason code. Used by the
    /// fail-closed timeout path in the handler.
    #[must_use]
    pub fn hard_deny(reason_code: impl Into<String>, policy_version: String) -> Self {
        Self {
            decision: AuthzDecision::Deny,
            reason_code: reason_code.into(),
            obligations: Vec::new(),
            policy_version,
        }
    }

    /// POLICY-1: signal "strict reject" mode for the
    /// `ck.profile.accountable_principals.strict_reject.v1` deployment profile.
    /// When the profile is declared, Actor Profile create/update events
    /// containing unverified `accountable_principal_ids[]` entries MUST be
    /// rejected with `failed_precondition / accountability_grant_missing`
    /// (the reducer and submit endpoint use this signal to short-circuit
    /// the legacy strip+audit path).
    ///
    /// The reason code on the wire is `failed_precondition`; the
    /// obligation carries the canonical
    /// [`cokret_core::error::REASON_ACCOUNTABILITY_GRANT_MISSING`]
    /// string so downstream consumers can render the exact registry
    /// rejection.
    #[must_use]
    pub fn strict_reject_accountable_principals(policy_version: String) -> Self {
        Self {
            decision: AuthzDecision::Deny,
            reason_code: cokret_core::error::ERROR_CODE_FAILED_PRECONDITION.to_owned(),
            obligations: vec![PolicyObligation {
                kind: "accountability_grant_required".to_owned(),
                expires_at: None,
                payload: serde_json::json!({
                    "reason": cokret_core::error::REASON_ACCOUNTABILITY_GRANT_MISSING,
                    "profile": "ck.profile.accountable_principals.strict_reject.v1",
                }),
            }],
            policy_version,
        }
    }
}

/// Evaluate a `ck.self.policy.check` request against the configured rules.
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
        _frontier: &'a Frontier,
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
                Ok::<_, EvaluatorError>(rules)
            };

            let rules = match tokio::time::timeout(self.inner_timeout, work).await {
                Ok(Ok(rules)) => rules,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(EvaluatorError::Timeout),
            };

            let Some(rules) = rules else {
                // No policy_data row yet → default-allow path. We still
                // tag `policy_version = "default"` so the audit trail
                // distinguishes "matched default policy" from "matched
                // configured allow rule".
                return Ok(PolicyDecision::allow("default".to_owned()));
            };

            let policy_version = rules.id.to_string();
            let decision = match_rules(&rules.data, request, &policy_version);
            Ok(decision)
        })
    }
}

/// Pure rule-matcher; pulled out so unit tests can exercise it without
/// a postgres connection.
fn match_rules(
    data: &Value,
    request: &PolicyCheckRequestBody,
    policy_version: &str,
) -> PolicyDecision {
    let actor_str = request.actor.as_str();
    let action_str = request.action.as_str();

    // POLICY-1 (R3 spec-sync) — if the loose JSON declares the
    // `strict_reject_profile` flag (deployment has enabled
    // `ck.profile.accountable_principals.strict_reject.v1`), AND the request
    // carries an Actor Profile create/update with an unverified
    // `accountable_principal_ids[]` entry, short-circuit with
    // `failed_precondition / accountability_grant_missing`. Only the
    // explicit flag form is checked here — the reducer-side strict
    // path lives in soland.
    if data
        .get("strict_reject_profile")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && action_str.starts_with("ck.actor.profile.")
        && request
            .event_preview
            .get("accountable_principal_ids_unverified")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return PolicyDecision::strict_reject_accountable_principals(policy_version.to_owned());
    }

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
        .get("circle_id")
        .and_then(Value::as_str)
        .filter(|c| is_circle_selector(c))
        .and_then(|c| realm_scope.get("circles").and_then(|m| m.get(c)));

    let scopes: [&Value; 2] = match circle_scope {
        Some(circle) => [circle, realm_scope],
        None => [realm_scope, realm_scope],
    };

    for scope in scopes {
        if value_contains_str(scope.get("deny_actors"), actor_str) {
            return PolicyDecision {
                decision: AuthzDecision::Deny,
                reason_code: cokret_core::error::ERROR_CODE_POLICY_VIOLATION.to_owned(),
                obligations: Vec::new(),
                policy_version: policy_version.to_owned(),
            };
        }

        if value_contains_str(scope.get("deny_actions"), action_str) {
            return PolicyDecision {
                decision: AuthzDecision::Deny,
                reason_code: cokret_core::error::ERROR_CODE_POLICY_VIOLATION.to_owned(),
                obligations: Vec::new(),
                policy_version: policy_version.to_owned(),
            };
        }

        if value_contains_str(scope.get("require_review_actions"), action_str) {
            return PolicyDecision {
                decision: AuthzDecision::RequireReview,
                reason_code: REASON_CODE_POLICY_REVIEW_REQUIRED.to_owned(),
                obligations: Vec::new(),
                policy_version: policy_version.to_owned(),
            };
        }
    }

    // CAP-1 (R3 spec-sync) — `ck.call.{join,screen_share,record,
    // transcribe,moderate}` are recognised capability actions even when
    // no realm rule names them explicitly. Default-allow path; the
    // recognition is a no-op for matching purposes but ensures the
    // evaluator surface knows about the action namespace so handlers
    // can branch on it without re-importing the constants.
    let _recognised_call_action = is_recognised_call_capability_action(action_str);

    PolicyDecision::allow(policy_version.to_owned())
}

fn value_contains_str(haystack: Option<&Value>, needle: &str) -> bool {
    haystack
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(needle)))
}

/// Type alias for the depot-injected handle. The handler reads it via
/// `DepotExt::policy_evaluator`.
pub type PolicyEvaluatorHandle = Arc<dyn PolicyEvaluator>;

#[cfg(test)]
mod tests {
    use cokret_core::{Did, Hash, PolicyCheckSource, RealmId};

    use super::*;

    fn req(actor: &str, action: &str) -> PolicyCheckRequestBody {
        PolicyCheckRequestBody {
            request_id: "req-1".into(),
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor: Did::new(actor.to_owned()).unwrap(),
            action: action.to_owned(),
            request_canonical_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            source: PolicyCheckSource {
                service_did: Did::new("did:web:soland.example").unwrap(),
                service_type: "principal_server".into(),
            },
            source_ip_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            signed_transport: serde_json::json!({"signature": "stub"}),
            event_preview: Value::Null,
            auth_context: Value::Null,
        }
    }

    #[test]
    fn empty_rules_yield_allow() {
        let data = serde_json::json!({});
        let r = req("did:web:alice.example", "ck.message.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
        assert_eq!(d.reason_code, "ok");
    }

    #[test]
    fn deny_actor_matches() {
        let data = serde_json::json!({
            "deny_actors": ["did:web:mallory.example"]
        });
        let r = req("did:web:mallory.example", "ck.message.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
        assert_eq!(d.reason_code, "policy_violation");
    }

    #[test]
    fn deny_action_matches() {
        let data = serde_json::json!({
            "deny_actions": ["ck.invite.create"]
        });
        let r = req("did:web:alice.example", "ck.invite.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
    }

    #[test]
    fn require_review_action_matches() {
        let data = serde_json::json!({
            "require_review_actions": ["ck.member.application"]
        });
        let r = req("did:web:alice.example", "ck.member.application");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::RequireReview));
        assert_eq!(d.reason_code, "policy_review_required");
    }

    #[test]
    fn realm_scope_overrides_default() {
        let data = serde_json::json!({
            "deny_actors": ["did:web:alice.example"],
            "realms": {
                "ck:realm:01904100-0000-7000-8000-000000000001": {
                    // Realm-specific scope: NO deny_actors, so alice is
                    // allowed in this realm even though the default
                    // scope would deny her.
                    "deny_actions": ["ck.evil"]
                }
            }
        });
        let r = req("did:web:alice.example", "ck.message.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
    }

    #[test]
    fn cap1_recognises_call_actions() {
        assert!(is_recognised_call_capability_action("ck.call.join"));
        assert!(is_recognised_call_capability_action("ck.call.screen_share"));
        assert!(is_recognised_call_capability_action("ck.call.record"));
        assert!(is_recognised_call_capability_action("ck.call.transcribe"));
        assert!(is_recognised_call_capability_action("ck.call.moderate"));
        assert!(!is_recognised_call_capability_action("ck.message.create"));
    }

    #[test]
    fn cap1_deny_action_on_cx_call_join_matches() {
        let data = serde_json::json!({
            "deny_actions": ["ck.call.join"]
        });
        let r = req("did:web:alice.example", "ck.call.join");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
        assert_eq!(d.reason_code, "policy_violation");
    }

    #[test]
    fn cap2_circle_selector_accepts_valid_typed_id() {
        assert!(is_circle_selector(
            "ck:circle:01904100-0000-7000-8000-000000000001"
        ));
        assert!(!is_circle_selector("not-a-circle"));
        assert!(!is_circle_selector(
            "ck:space:01904100-0000-7000-8000-000000000001"
        ));
    }

    #[test]
    fn cap2_circle_scoped_deny_overrides_realm_default() {
        let circle_id = "ck:circle:01904100-0000-7000-8000-000000000002";
        let data = serde_json::json!({
            "circles": {
                circle_id: {
                    "deny_actions": ["ck.call.record"],
                }
            }
        });
        let mut r = req("did:web:alice.example", "ck.call.record");
        r.auth_context = serde_json::json!({ "circle_id": circle_id });
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
    }

    #[test]
    fn policy1_strict_reject_yields_failed_precondition() {
        let data = serde_json::json!({
            "strict_reject_profile": true,
        });
        let mut r = req("did:web:alice.example", "ck.actor.profile.update");
        r.event_preview = serde_json::json!({ "accountable_principal_ids_unverified": true });
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
        assert_eq!(d.reason_code, "failed_precondition");
        assert_eq!(d.obligations.len(), 1);
        assert_eq!(d.obligations[0].kind, "accountability_grant_required");
    }

    #[test]
    fn policy1_strict_reject_inert_when_profile_off() {
        let data = serde_json::json!({});
        let mut r = req("did:web:alice.example", "ck.actor.profile.update");
        r.event_preview = serde_json::json!({ "accountable_principal_ids_unverified": true });
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
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
