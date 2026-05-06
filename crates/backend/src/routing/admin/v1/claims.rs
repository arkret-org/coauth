//! Contrix claim and attestation administration endpoints.

use chrono::{DateTime, Utc};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AppError, CreatedJsonResult, JsonResult, routing::admin::call_context::extract_call_context,
};

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct ClaimRecord {
    /// Claim identifier.
    id: String,

    /// Claim type, for example `verified_email_domain` or `org_role`.
    claim_type: String,

    /// Subject account or DID.
    subject: String,

    /// Issuer DID or trusted issuer identifier.
    issuer: String,

    /// Claim payload.
    payload: serde_json::Value,

    /// Current lifecycle state.
    status: ClaimStatus,

    /// When the claim was issued.
    issued_at: DateTime<Utc>,

    /// When the claim expires.
    expires_at: Option<DateTime<Utc>>,

    /// When the claim was revoked.
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct ClaimListResponse {
    data: Vec<ClaimRecord>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "IssueClaimRequest")]
#[allow(dead_code)]
pub struct IssueClaimRequest {
    /// Claim type, for example `verified_email_domain` or `org_role`.
    claim_type: String,

    /// Subject account or DID.
    subject: String,

    /// Claim payload.
    payload: serde_json::Value,

    /// Optional expiry.
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "RevokeClaimRequest")]
#[allow(dead_code)]
pub struct RevokeClaimRequest {
    /// Operator-supplied revocation reason for audit.
    reason: String,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.claims.issue", skip_all)]
pub async fn issue_claim(req: &mut Request, depot: &Depot) -> CreatedJsonResult<ClaimRecord> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): persist signed claim issuance with issuer policy checks.
    Err(AppError::not_implemented(
        "claim issuance is not implemented yet",
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.claims.status", skip_all)]
pub async fn list_claim_status(req: &mut Request, depot: &Depot) -> JsonResult<ClaimListResponse> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): return claim status list records with revocation state.
    Err(AppError::not_implemented(
        "claim status listing is not implemented yet",
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.claims.revoke", skip_all)]
pub async fn revoke_claim(req: &mut Request, depot: &Depot) -> JsonResult<ClaimRecord> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): revoke claim and publish status-list update.
    Err(AppError::not_implemented(
        "claim revocation is not implemented yet",
    ))
}
