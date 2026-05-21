// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 — pluggable evaluator for `cx.policy.check`.
//!
//! The spec [`policy-server.md` §4] defines the decision lattice as
//! `allow | soft_deny | hard_deny | quarantine | require_review`; the
//! SDK type [`contrix_core::AuthzDecision`] exposes these as
//! `Allow | Deny | Quarantine | RequireReview | SoftFail`. This module
//! is responsible for picking one of those values, plus the
//! `reason_code` and the optional `obligations` array, for every
//! incoming `PolicyCheckRequest`.
//!
//! ## Why a separate trait
//!
//! The legacy `coauth_policy::PolicyFactory` evaluator only understands
//! `register` / `email` / `client_registration` / `authorization_grant`
//! shapes — it predates the round-4 `cx.policy.check` request and does
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
use contrix_core::{AuthzDecision, PolicyCheckRequest};
use serde_json::Value;
use thiserror::Error;

use crate::services::policy_frontier::Frontier;

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
    /// [`contrix_core::PolicyCheckResponse::obligations`].
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
/// [`contrix_core::PolicyCheckResponse`].
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
            reason_code: "ok".to_owned(),
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
}

/// Evaluate a `cx.policy.check` request against the configured rules.
/// Object-safe: handlers carry an `Arc<dyn PolicyEvaluator>`.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate<'a>(
        &'a self,
        request: &'a PolicyCheckRequest,
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
        request: &'a PolicyCheckRequest,
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
fn match_rules(data: &Value, request: &PolicyCheckRequest, policy_version: &str) -> PolicyDecision {
    let actor_str = request.actor.as_str();
    let action_str = request.action.as_str();

    // Per-realm scope: rules MAY be nested under a `realms` object keyed
    // by realm id, with a `default` fall-through. When the loose JSON
    // is a flat object we treat it as the default scope.
    let scope: &Value = data
        .get("realms")
        .and_then(|m| m.get(request.realm_id.as_str()))
        .unwrap_or(data);

    if value_contains_str(scope.get("deny_actors"), actor_str) {
        return PolicyDecision {
            decision: AuthzDecision::Deny,
            reason_code: "policy_violation".to_owned(),
            obligations: Vec::new(),
            policy_version: policy_version.to_owned(),
        };
    }

    if value_contains_str(scope.get("deny_actions"), action_str) {
        return PolicyDecision {
            decision: AuthzDecision::Deny,
            reason_code: "policy_violation".to_owned(),
            obligations: Vec::new(),
            policy_version: policy_version.to_owned(),
        };
    }

    if value_contains_str(scope.get("require_review_actions"), action_str) {
        return PolicyDecision {
            decision: AuthzDecision::RequireReview,
            reason_code: "policy_review_required".to_owned(),
            obligations: Vec::new(),
            policy_version: policy_version.to_owned(),
        };
    }

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
    use super::*;
    use contrix_core::{Did, Hash, PolicyCheckSource, RealmId};

    fn req(actor: &str, action: &str) -> PolicyCheckRequest {
        PolicyCheckRequest {
            request_id: "req-1".into(),
            realm_id: RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor: Did::new(actor.to_owned()).unwrap(),
            action: action.to_owned(),
            request_canonical_hash: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            source: PolicyCheckSource {
                service_did: Did::new("did:web:soland.example").unwrap(),
                service_type: "principal_server".into(),
            },
            source_ip_hash: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            signed_transport: serde_json::json!({"signature": "stub"}),
            event_preview: Value::Null,
            auth_context: Value::Null,
        }
    }

    #[test]
    fn empty_rules_yield_allow() {
        let data = serde_json::json!({});
        let r = req("did:web:alice.example", "cx.message.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Allow));
        assert_eq!(d.reason_code, "ok");
    }

    #[test]
    fn deny_actor_matches() {
        let data = serde_json::json!({
            "deny_actors": ["did:web:mallory.example"]
        });
        let r = req("did:web:mallory.example", "cx.message.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
        assert_eq!(d.reason_code, "policy_violation");
    }

    #[test]
    fn deny_action_matches() {
        let data = serde_json::json!({
            "deny_actions": ["cx.invite.create"]
        });
        let r = req("did:web:alice.example", "cx.invite.create");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::Deny));
    }

    #[test]
    fn require_review_action_matches() {
        let data = serde_json::json!({
            "require_review_actions": ["cx.member.application"]
        });
        let r = req("did:web:alice.example", "cx.member.application");
        let d = match_rules(&data, &r, "v");
        assert!(matches!(d.decision, AuthzDecision::RequireReview));
        assert_eq!(d.reason_code, "policy_review_required");
    }

    #[test]
    fn realm_scope_overrides_default() {
        let data = serde_json::json!({
            "deny_actors": ["did:web:alice.example"],
            "realms": {
                "cx:realm:01904100-0000-7000-8000-000000000001": {
                    // Realm-specific scope: NO deny_actors, so alice is
                    // allowed in this realm even though the default
                    // scope would deny her.
                    "deny_actions": ["cx.evil"]
                }
            }
        });
        let r = req("did:web:alice.example", "cx.message.create");
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
