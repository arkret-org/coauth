// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Administrator review of the issuing deployment's registration-token outbox.
//!
//! `batch_invite` saves a pending row in `admin_invite_review_queue` when its
//! local minting gate needs review. This is an administrator-owned management
//! object, separate from holder-private invite delivery and Consent state.
//!
//! - `GET /_coauth/admin/invite-reviews` lists pending rows.
//! - `POST /_coauth/admin/invite-reviews/{id}/resolve` accepts `approve` or `reject` plus an
//!   optional note. Approve resolves the row and mints tokens from the saved parameters; reject
//!   resolves it without minting.
//!
//! Approval records an administrator decision. It does not grant holder Consent
//! or implement the holder Station's `ak.account.holder_quarantine` contract.
//! Existing failure behavior is retained: if minting fails after resolution,
//! the row remains approved and the response contains no minted tokens.

use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use coauth_data::audit::AdminOperation;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::handlers::admin::audit_helper::record_admin_operation;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::UserRegistrationToken;
use crate::handlers::admin::response::SingleOutcome;
use crate::handlers::admin::v1::accounts::create::{
    MintRegistrationTokensParams, mint_registration_tokens,
};
use crate::handlers::common::DepotExt;
use crate::services::admin_invite_review::{
    AdminInviteReviewError, AdminInviteReviewRecord, AdminInviteReviewStatus,
};
use crate::{AppError, JsonResult};

// ── Wire types ─────────────────────────────────────────────────

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdminInviteReviewWireStatus {
    Pending,
    Approved,
    Rejected,
}

impl From<AdminInviteReviewStatus> for AdminInviteReviewWireStatus {
    fn from(s: AdminInviteReviewStatus) -> Self {
        match s {
            AdminInviteReviewStatus::Pending => Self::Pending,
            AdminInviteReviewStatus::Approved => Self::Approved,
            AdminInviteReviewStatus::Rejected => Self::Rejected,
        }
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminInviteReviewEntry {
    pub id: String,
    pub created_at: DateTime<Utc>,
    #[schemars(with = "String")]
    #[salvo(schema(value_type = String))]
    pub peer_principal_id: DidCoreId,
    #[schemars(with = "String")]
    #[salvo(schema(value_type = String))]
    pub target_holder_principal_id: DidCoreId,
    pub consent_id: String,
    pub scope: String,
    pub requesting_admin_localpart: Option<String>,
    /// Original invitation review document; `status` only records the review
    /// lifecycle and does not discriminate this document.
    pub payload: serde_json::Value,
    pub status: AdminInviteReviewWireStatus,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
}

impl From<AdminInviteReviewRecord> for AdminInviteReviewEntry {
    fn from(r: AdminInviteReviewRecord) -> Self {
        Self {
            id: r.id.to_string(),
            created_at: r.created_at,
            peer_principal_id: r.peer_principal_id,
            target_holder_principal_id: r.target_holder_principal_id,
            consent_id: r.consent_id,
            scope: r.scope,
            requesting_admin_localpart: r.requesting_admin_localpart,
            payload: r.payload,
            status: r.status.into(),
            resolved_at: r.resolved_at,
            resolution_note: r.resolution_note,
        }
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminInviteReviewListOutcome {
    pub data: Vec<AdminInviteReviewEntry>,
}

#[derive(Deserialize, Default, JsonSchema)]
pub struct AdminInviteReviewListQuery {
    /// Maximum rows to return (1-1000, default 100).
    pub limit: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdminInviteReviewDecision {
    Approve,
    Reject,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AdminInviteReviewResolveRequestBody")]
pub struct AdminInviteReviewResolveRequestBody {
    pub decision: AdminInviteReviewDecision,

    /// Optional operator note recorded alongside the resolution.
    #[serde(default)]
    pub note: Option<String>,
}

/// Response from `resolve_admin_invite_review`. On `approve`, the queue
/// row is marked resolved *and* the original `batch_invite` is re-run
/// (current admin behavior) — the freshly minted registration tokens are returned in
/// `minted_tokens`. On `reject`, only the entry is updated and
/// `minted_tokens` is empty.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminInviteReviewResolveOutcome {
    pub entry: AdminInviteReviewEntry,

    /// Empty when `decision = reject` or when the original payload had
    /// no mintable parameters. Each element matches the shape returned
    /// by `POST /_coauth/admin/accounts/batch-invite`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub minted_tokens: Vec<SingleOutcome<UserRegistrationToken>>,
}

// ── Helpers ────────────────────────────────────────────────────

fn map_admin_invite_review_error(error: AdminInviteReviewError) -> AppError {
    match error {
        AdminInviteReviewError::Storage(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
    }
}

fn extract_uuid_param(req: &Request) -> Result<Uuid, AppError> {
    let id_str: String = req
        .param::<String>("id")
        .ok_or_else(|| AppError::bad_request("Missing id parameter"))?;
    id_str
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid id parameter (expected UUID v7)"))
}

// ── Handlers ───────────────────────────────────────────────────

/// `GET /_coauth/admin/invite-reviews`
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.admin_invite_review.list", skip_all)]
pub async fn list_admin_invite_review(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AdminInviteReviewListOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { repo, .. } = ctx;
    let query: AdminInviteReviewListQuery = req
        .parse_queries()
        .map_err(|error| AppError::bad_request(format!("Invalid filter parameters: {error}")))?;
    let queue = depot.admin_invite_review_service()?;
    // REL-10: clamp the caller-supplied limit so an unbounded / negative
    // value cannot drive an oversized scan. Mirrors the 1-1000 range
    // documented on `AdminInviteReviewListQuery::limit`.
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    repo.cancel().await?;

    let data = queue
        .list_pending(limit)
        .await
        .map_err(map_admin_invite_review_error)?
        .into_iter()
        .map(AdminInviteReviewEntry::from)
        .collect();

    Ok(Json(AdminInviteReviewListOutcome { data }))
}

/// `POST /_coauth/admin/invite-reviews/{id}/resolve`
///
/// `approve` mints registration tokens from the parameters captured at enqueue
/// time and returns them in `AdminInviteReviewResolveOutcome.minted_tokens`.
/// The local gate is not re-evaluated: this is the administrator's minting
/// decision, which neither grants nor changes the recipient's Consent state.
///
/// `reject` is unchanged: marks the row resolved and records an audit
/// op without minting anything.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.admin_invite_review.resolve", skip_all)]
pub async fn resolve_admin_invite_review(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AdminInviteReviewResolveOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let id = extract_uuid_param(req)?;
    let body: AdminInviteReviewResolveRequestBody =
        req.parse_json().await.map_err(AppError::internal)?;
    let queue = depot.admin_invite_review_service()?;
    let now = clock.now();

    let new_status = match body.decision {
        AdminInviteReviewDecision::Approve => AdminInviteReviewStatus::Approved,
        AdminInviteReviewDecision::Reject => AdminInviteReviewStatus::Rejected,
    };

    let record = queue
        .mark_resolved(id, new_status, body.note.clone(), now)
        .await
        .map_err(map_admin_invite_review_error)?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "Admin invite review entry {id} not found or already resolved"
            ))
        })?;

    // ── Approve auto-replay (current admin behavior) ───────────────────────────
    //
    // batch_invite enqueues the original mint params (count /
    // usage_limit / expires_in_hours) into `payload` at review
    // time. On approve, re-mint the same number of tokens against
    // `repo` and return them in the response. We deliberately do NOT
    // re-run the consent gate here — the operator approving the queue
    // row has approved these registration-token mint parameters.
    //
    // If `payload` has no recognisable mint params (for example manual
    // queue inserts), we log a warning and fall through to the
    // flag-flip-only path. Reject always falls through.
    let mut minted_tokens: Vec<SingleOutcome<UserRegistrationToken>> = Vec::new();
    if matches!(body.decision, AdminInviteReviewDecision::Approve) {
        if let Some(params) = mint_params_from_payload(&record.payload) {
            match mint_registration_tokens(
                &mut repo,
                &clock,
                &mut rng,
                &params,
                admin_user.as_ref().map(|u| u.id),
            )
            .await
            {
                Ok(tokens) => minted_tokens = tokens,
                Err(error) => {
                    // Don't fail the resolve — the queue row is already
                    // flipped to Approved and the operator has expressed
                    // intent. Log loudly and surface an empty token list
                    // so they can re-issue manually if needed.
                    warn!(
                        admin_invite_review_id = %record.id,
                        ?error,
                        "admin_invite_review.approve: token mint failed; row resolved without tokens",
                    );
                }
            }
        } else {
            warn!(
                admin_invite_review_id = %record.id,
                "admin_invite_review.approve: payload has no mint params; row resolved without minting",
            );
        }
    }

    let op_label = match body.decision {
        AdminInviteReviewDecision::Approve => "admin_invite_review.approve",
        AdminInviteReviewDecision::Reject => "admin_invite_review.reject",
    };

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::Other(op_label.to_owned()),
        "admin_invite_review_queue",
        // Audit table uses Ulid; the queue id is uuid-v7. Pass None
        // for the resource_id slot and stash the uuid in the metadata
        // payload so audit-feed consumers can correlate.
        None,
        serde_json::json!({
            "admin_invite_review_id": record.id.to_string(),
            "decision": op_label.split('.').next_back().unwrap_or(""),
            "peer_principal_id": &record.peer_principal_id,
            "target_holder_principal_id": &record.target_holder_principal_id,
            "consent_id": &record.consent_id,
            "scope": &record.scope,
            "note": body.note,
            "minted_token_count": minted_tokens.len(),
        }),
    )
    .await?;

    repo.save().await?;

    Ok(Json(AdminInviteReviewResolveOutcome {
        entry: AdminInviteReviewEntry::from(record),
        minted_tokens,
    }))
}

/// Pull mint parameters out of the queue row's `payload` JSON. The
/// shape is the one written in
/// `handlers::admin::v1::accounts::create::batch_invite` at review
/// time:
///
/// ```json
/// {"count": <u32>, "usage_limit": <u32?>, "expires_in_hours": <u64?>}
/// ```
///
/// Returns `None` when `count` is missing or out of range — the
/// resolve handler then falls through to flag-flip-only behaviour.
fn mint_params_from_payload(payload: &serde_json::Value) -> Option<MintRegistrationTokensParams> {
    let count = payload.get("count")?.as_u64()?;
    if count == 0 || count > 100 {
        return None;
    }
    let usage_limit = payload
        .get("usage_limit")
        .and_then(serde_json::Value::as_u64)
        .map(|n| n as u32);
    let expires_in_hours = payload
        .get("expires_in_hours")
        .and_then(serde_json::Value::as_u64);
    Some(MintRegistrationTokensParams {
        count: count as u32,
        usage_limit,
        expires_in_hours,
    })
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Pure DTO helpers; the sibling `pg_tests` module exercises real routes,
    //! PostgreSQL persistence, token minting and audit records.

    use super::*;

    #[test]
    fn wire_status_round_trip() {
        let cases = [
            (AdminInviteReviewStatus::Pending, "pending"),
            (AdminInviteReviewStatus::Approved, "approved"),
            (AdminInviteReviewStatus::Rejected, "rejected"),
        ];
        for (svc, expected) in cases {
            let wire: AdminInviteReviewWireStatus = svc.into();
            let v = serde_json::to_value(wire).unwrap();
            assert_eq!(v, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn entry_from_record_preserves_fields() {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let rec = AdminInviteReviewRecord {
            id,
            created_at: now,
            peer_principal_id: DidCoreId::new("ak:did_core:web:peer").unwrap(),
            target_holder_principal_id: DidCoreId::new("ak:did_core:web:holder").unwrap(),
            consent_id: "c-99".into(),
            scope: "invite".into(),
            requesting_admin_localpart: Some("admin1".into()),
            payload: serde_json::json!({"count": 3}),
            status: AdminInviteReviewStatus::Pending,
            resolved_at: None,
            resolution_note: None,
        };
        let entry = AdminInviteReviewEntry::from(rec);
        assert_eq!(entry.id, id.to_string());
        assert_eq!(entry.peer_principal_id.as_str(), "ak:did_core:web:peer");
        assert_eq!(
            entry.target_holder_principal_id.as_str(),
            "ak:did_core:web:holder"
        );
        assert_eq!(entry.consent_id, "c-99");
        assert_eq!(entry.scope, "invite");
        assert_eq!(entry.requesting_admin_localpart.as_deref(), Some("admin1"));
        assert_eq!(entry.payload["count"], 3);
        assert!(matches!(entry.status, AdminInviteReviewWireStatus::Pending));
    }

    #[test]
    fn resolve_request_parses_approve() {
        let body: AdminInviteReviewResolveRequestBody =
            serde_json::from_str(r#"{"decision": "approve"}"#).unwrap();
        assert_eq!(body.decision, AdminInviteReviewDecision::Approve);
        assert!(body.note.is_none());
    }

    #[test]
    fn resolve_request_parses_reject_with_note() {
        let body: AdminInviteReviewResolveRequestBody =
            serde_json::from_str(r#"{"decision": "reject", "note": "spam"}"#).unwrap();
        assert_eq!(body.decision, AdminInviteReviewDecision::Reject);
        assert_eq!(body.note.as_deref(), Some("spam"));
    }

    #[test]
    fn resolve_request_rejects_unknown_decision() {
        let res: Result<AdminInviteReviewResolveRequestBody, _> =
            serde_json::from_str(r#"{"decision": "maybe"}"#);
        assert!(res.is_err(), "unknown decision must not parse");
    }

    #[test]
    fn mint_params_from_payload_round_trips() {
        let v = serde_json::json!({
            "count": 5,
            "usage_limit": 1,
            "expires_in_hours": 24,
        });
        let params = mint_params_from_payload(&v).expect("should parse");
        assert_eq!(params.count, 5);
        assert_eq!(params.usage_limit, Some(1));
        assert_eq!(params.expires_in_hours, Some(24));
    }

    #[test]
    fn mint_params_from_payload_handles_partial() {
        let v = serde_json::json!({"count": 3});
        let params = mint_params_from_payload(&v).expect("count alone is enough");
        assert_eq!(params.count, 3);
        assert_eq!(params.usage_limit, None);
        assert_eq!(params.expires_in_hours, None);
    }

    #[test]
    fn mint_params_from_payload_rejects_zero_count() {
        assert!(mint_params_from_payload(&serde_json::json!({"count": 0})).is_none());
    }

    #[test]
    fn mint_params_from_payload_rejects_overlimit_count() {
        assert!(mint_params_from_payload(&serde_json::json!({"count": 101})).is_none());
    }

    #[test]
    fn mint_params_from_payload_rejects_missing_count() {
        assert!(mint_params_from_payload(&serde_json::json!({"reason": "x"})).is_none());
    }
}

#[cfg(all(test, feature = "cedar"))]
#[path = "admin_invite_review_tests.rs"]
mod pg_tests;
