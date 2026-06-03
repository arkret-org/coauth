//! Policy dry-run and decision-audit contract endpoints.

use coauth_data::{
    RepositoryAccess,
    audit::{AdminOperation, NewAdminOperationLog},
};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::admin::{CreatedJson, call_context::extract_call_context},
};

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "PolicyDryRunRequest")]
#[allow(dead_code)]
pub struct PolicyDryRunRequest {
    /// Principal DID or account subject.
    subject: String,

    /// Requested action.
    action: String,

    /// Target resource identifier.
    resource: String,

    /// Optional object facets supplied by the Principal Server reducer.
    object_facets: Option<serde_json::Value>,

    /// Additional policy attributes such as organization role, risk, or MFA.
    attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PolicyDryRunResponse {
    /// Signed decision audit identifier.
    audit_id: String,

    /// Dry-run decision effect.
    effect: PolicyEffect,

    /// Policy identifier that produced the decision.
    policy_id: Option<String>,

    /// Policy version that produced the decision.
    policy_version: Option<String>,

    /// Human-readable explanation for administrators.
    reason: Option<String>,

    /// Facets preserved from the reducer output.
    facet_allow: Option<serde_json::Value>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PolicyDecisionAuditRecord {
    /// Audit record identifier.
    id: String,

    /// Policy decision payload plus its integrity digest.
    decision_record: serde_json::Value,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_checks.dry_run", skip_all)]
pub async fn dry_run(req: &mut Request, depot: &Depot) -> CreatedJsonResult<PolicyDryRunResponse> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let Some(admin_user) = admin_user else {
        return Err(AppError::forbidden(
            "policy dry-run requires an authenticated admin user for audit",
        ));
    };
    let mut rng = crate::handlers::account::make_rng();
    let body: PolicyDryRunRequest = req.parse_json().await.map_err(AppError::internal)?;
    let request = body.normalized()?;

    let policy_data = repo.policy_data().get().await?;
    let decision = evaluate_policy_dry_run(&request, policy_data.as_ref().map(|p| &p.data));
    let issued_at = clock.now();
    let decision_record = decision_digest_payload(
        &request,
        &decision,
        policy_data.as_ref().map(|p| p.id.to_string()),
        issued_at,
    )?;

    let audit = repo
        .audit()
        .add_admin_operation(
            &mut rng,
            &*clock,
            NewAdminOperationLog::new(
                admin_user.id,
                AdminOperation::Other("policy_check.dry_run".to_owned()),
                "policy_decision_audit",
                serde_json::json!({
                    "request": request,
                    "decision": decision,
                    "decision_record": decision_record,
                }),
            ),
        )
        .await?;
    repo.save().await?;

    Ok(CreatedJson(PolicyDryRunResponse {
        audit_id: audit.id.to_string(),
        effect: decision.effect,
        policy_id: decision.policy_id,
        policy_version: decision.policy_version,
        reason: decision.reason,
        facet_allow: decision.facet_allow,
    }))
}

#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.policy_checks.signed_decision_audit",
    skip_all
)]
pub async fn get_signed_decision_audit(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PolicyDecisionAuditRecord> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::bad_request("missing decision audit id"))?;
    let id = Ulid::from_string(id.trim())
        .map_err(|_| AppError::bad_request("invalid decision audit id"))?;

    let audit = repo
        .audit()
        .lookup_admin_operation(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Policy decision audit {id} not found")))?;
    if audit.resource_type != "policy_decision_audit" {
        return Err(AppError::not_found(format!(
            "Policy decision audit {id} not found"
        )));
    }
    let decision_record = audit
        .details
        .get("decision_record")
        .cloned()
        .ok_or_else(|| AppError::not_found(format!("Policy decision audit {id} not found")))?;
    repo.cancel().await?;

    Ok(Json(PolicyDecisionAuditRecord {
        id: id.to_string(),
        decision_record,
    }))
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedPolicyDryRunRequest {
    subject: String,
    action: String,
    resource: String,
    object_facets: Option<serde_json::Value>,
    attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyDryRunDecision {
    effect: PolicyEffect,
    policy_id: Option<String>,
    policy_version: Option<String>,
    reason: Option<String>,
    facet_allow: Option<serde_json::Value>,
}

impl PolicyDryRunRequest {
    fn normalized(self) -> Result<NormalizedPolicyDryRunRequest, AppError> {
        let subject = self.subject.trim().to_owned();
        let action = self.action.trim().to_owned();
        let resource = self.resource.trim().to_owned();
        if subject.is_empty() {
            return Err(AppError::bad_request("subject is required"));
        }
        if action.is_empty() {
            return Err(AppError::bad_request("action is required"));
        }
        if resource.is_empty() {
            return Err(AppError::bad_request("resource is required"));
        }
        Ok(NormalizedPolicyDryRunRequest {
            subject,
            action,
            resource,
            object_facets: self.object_facets,
            attributes: self.attributes,
        })
    }
}

fn evaluate_policy_dry_run(
    request: &NormalizedPolicyDryRunRequest,
    policy_data: Option<&serde_json::Value>,
) -> PolicyDryRunDecision {
    let matching_rule = policy_data
        .and_then(policy_rules)
        .and_then(|rules| rules.iter().find(|rule| rule_matches(rule, request)));

    if let Some(rule) = matching_rule {
        return PolicyDryRunDecision {
            effect: rule
                .get("effect")
                .and_then(|v| v.as_str())
                .and_then(parse_policy_effect)
                .unwrap_or(PolicyEffect::Deny),
            policy_id: rule
                .get("policy_id")
                .or_else(|| rule.get("id"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            policy_version: rule
                .get("policy_version")
                .or_else(|| rule.get("version"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            reason: rule
                .get("reason")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
                .or_else(|| Some("matched persisted policy dry-run rule".to_owned())),
            facet_allow: rule
                .get("facet_allow")
                .cloned()
                .or_else(|| request.object_facets.clone()),
        };
    }

    let effect = request
        .attributes
        .as_ref()
        .and_then(|attrs| attrs.get("effect"))
        .and_then(|v| v.as_str())
        .and_then(parse_policy_effect)
        .unwrap_or(PolicyEffect::Allow);

    PolicyDryRunDecision {
        effect,
        policy_id: policy_data
            .and_then(|data| data.get("policy_id").or_else(|| data.get("id")))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        policy_version: policy_data
            .and_then(|data| data.get("policy_version").or_else(|| data.get("version")))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        reason: Some("no matching policy dry-run rule; default decision applied".to_owned()),
        facet_allow: request.object_facets.clone(),
    }
}

fn policy_rules(data: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    data.get("dry_run_rules")
        .or_else(|| data.get("policy_checks"))
        .and_then(|v| v.as_array())
}

fn rule_matches(rule: &serde_json::Value, request: &NormalizedPolicyDryRunRequest) -> bool {
    field_matches(rule, "subject", &request.subject)
        && field_matches(rule, "action", &request.action)
        && field_matches(rule, "resource", &request.resource)
}

fn field_matches(rule: &serde_json::Value, field: &str, actual: &str) -> bool {
    rule.get(field)
        .and_then(|v| v.as_str())
        .is_none_or(|expected| expected == "*" || expected == actual)
}

fn parse_policy_effect(value: &str) -> Option<PolicyEffect> {
    match value {
        "allow" => Some(PolicyEffect::Allow),
        "deny" => Some(PolicyEffect::Deny),
        "quarantine" => Some(PolicyEffect::Quarantine),
        "require_review" => Some(PolicyEffect::RequireReview),
        _ => None,
    }
}

/// Build the dry-run decision record with an integrity digest.
///
/// This is a plaintext SHA-256 *integrity digest*, NOT a cryptographic
/// signature: it carries no key material and anyone can recompute it. It is
/// deliberately named `integrity` (and the digest is taken over the spec
/// canonical-JSON byte form via [`cokret_core::canonical::canonical_sha256`])
/// to avoid being confused with the keyed admin-audit signatures produced by
/// `audit_helper`, which are unforgeable and verifiable against the service
/// public key.
fn decision_digest_payload(
    request: &NormalizedPolicyDryRunRequest,
    decision: &PolicyDryRunDecision,
    policy_data_revision: Option<String>,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value, AppError> {
    let payload = serde_json::json!({
        "type": "coauth.policy.decision.v1",
        "request": request,
        "decision": decision,
        "policy_data_revision": policy_data_revision,
        "issued_at": issued_at,
    });
    let digest = cokret_core::canonical::canonical_sha256(&payload).map_err(AppError::internal)?;

    Ok(serde_json::json!({
        "payload": payload,
        "integrity": {
            "digest_algorithm": "sha256",
            "digest": digest,
        }
    }))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};
    use hyper::{Request, StatusCode};

    use super::*;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[test]
    fn dry_run_matches_persisted_rule() {
        let request = PolicyDryRunRequest {
            subject: "did:cokret:alice".to_owned(),
            action: "read".to_owned(),
            resource: "space:demo".to_owned(),
            object_facets: None,
            attributes: None,
        }
        .normalized()
        .unwrap();
        let data = serde_json::json!({
            "dry_run_rules": [{
                "subject": "did:cokret:alice",
                "action": "read",
                "resource": "space:demo",
                "effect": "deny",
                "policy_id": "policy.demo",
                "policy_version": "v1",
                "reason": "blocked in dry-run"
            }]
        });

        let decision = evaluate_policy_dry_run(&request, Some(&data));

        assert!(matches!(decision.effect, PolicyEffect::Deny));
        assert_eq!(decision.policy_id.as_deref(), Some("policy.demo"));
        assert_eq!(decision.policy_version.as_deref(), Some("v1"));
        assert_eq!(decision.reason.as_deref(), Some("blocked in dry-run"));
    }

    #[test]
    fn signed_decision_contains_stable_digest_shape() {
        let request = PolicyDryRunRequest {
            subject: "did:cokret:alice".to_owned(),
            action: "read".to_owned(),
            resource: "space:demo".to_owned(),
            object_facets: None,
            attributes: Some(serde_json::json!({ "effect": "allow" })),
        }
        .normalized()
        .unwrap();
        let decision = evaluate_policy_dry_run(&request, None);
        let issued_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();

        let record = decision_digest_payload(&request, &decision, None, issued_at).unwrap();

        assert_eq!(record["payload"]["type"], "coauth.policy.decision.v1");
        assert_eq!(record["integrity"]["digest_algorithm"], "sha256");
        assert!(
            record["integrity"]["digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[tokio::test]
    async fn policy_dry_run_persists_signed_decision_audit() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        repo.policy_data()
            .set(
                &mut rng,
                &*state.clock,
                serde_json::json!({
                    "dry_run_rules": [{
                        "subject": "did:cokret:alice",
                        "action": "read",
                        "resource": "space:demo",
                        "effect": "deny",
                        "policy_id": "policy.demo",
                        "policy_version": "v1",
                        "reason": "blocked in test"
                    }]
                }),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let response = state
            .request(
                Request::post("/_cokret/local/admin/policy-checks/dry-run")
                    .bearer(&token)
                    .json(serde_json::json!({
                        "subject": "did:cokret:alice",
                        "action": "read",
                        "resource": "space:demo"
                    })),
            )
            .await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["effect"], "deny");
        assert_eq!(body["policy_id"], "policy.demo");
        let audit_id = body["audit_id"].as_str().unwrap();

        let response = state
            .request(
                Request::get(format!(
                    "/_cokret/local/admin/policy-decision-audits/{audit_id}"
                ))
                .bearer(&token)
                .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["id"], audit_id);
        assert_eq!(
            body["decision_record"]["payload"]["decision"]["effect"],
            "deny"
        );
        assert_eq!(
            body["decision_record"]["integrity"]["digest_algorithm"],
            "sha256"
        );
    }
}
