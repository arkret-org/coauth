//! Policy dry-run and decision-audit contract endpoints.

use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AppError, CreatedJsonResult, JsonResult, handlers::admin::call_context::extract_call_context,
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

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PolicyDryRunResponse {
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
pub struct SignedPolicyDecisionAudit {
    /// Audit record identifier.
    id: String,

    /// Signed policy decision payload.
    signed_decision: serde_json::Value,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_checks.dry_run", skip_all)]
pub async fn dry_run(req: &mut Request, depot: &Depot) -> CreatedJsonResult<PolicyDryRunResponse> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): evaluate Cedar/OPA policy without granting capabilities.
    Err(AppError::not_implemented(
        "policy dry-run is not implemented yet",
    ))
}

#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.policy_checks.signed_decision_audit",
    skip_all
)]
pub async fn get_signed_decision_audit(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SignedPolicyDecisionAudit> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): retrieve signed decision audit records by ID.
    Err(AppError::not_implemented(
        "signed policy decision audit lookup is not implemented yet",
    ))
}
