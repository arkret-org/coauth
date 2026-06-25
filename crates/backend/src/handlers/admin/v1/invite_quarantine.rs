// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Admin review surface for the invite-quarantine outbox queue.
//!
//! Spec context: `cokret-spec` `consent-model.md` §6.1 default-profile
//! path. When the consent gate in `batch_invite` returns `Quarantined`,
//! the invite intent is persisted to `invite_quarantine_queue` (see
//! `crates/backend/src/services/invite_quarantine.rs`). Operators
//! (sodmin / yougen) review the queue here.
//!
//! Endpoints:
//!
//! - `GET  /_coauth/admin/invite-quarantine` — list pending entries.
//! - `POST /_coauth/admin/invite-quarantine/{id}/resolve` — body `{ "decision": "approve"|"reject",
//!   "note"?: "..." }`. Approve marks the row resolved (the actual re-run of the original invite is
//!   the caller's responsibility — sodmin re-issues `batch-invite` once it has verified consent out
//!   of band). Reject marks the row resolved without re-running.
//!
//! ## Why approve does not auto-mint
//!
//! The original `batch_invite` only minted registration tokens; the
//! consent decision context (peer DID, target holder DID) lives in the
//! queue row but the *registration policy* (count, `usage_limit`, expiry)
//! is in the `payload` JSON. Re-issuing requires the admin to confirm
//! those parameters via a fresh batch-invite call. The "approve"
//! transition therefore unblocks future calls (the holder's consent has
//! been resolved out of band) rather than auto-minting tokens that the
//! caller never reviewed.

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
use crate::handlers::admin::v1::users::create::{
    MintRegistrationTokensParams, mint_registration_tokens,
};
use crate::handlers::common::DepotExt;
use crate::services::invite_quarantine::{
    InviteQuarantineError, InviteQuarantineRecord, InviteQuarantineStatus,
};
use crate::{AppError, JsonResult};

// ── Wire types ─────────────────────────────────────────────────

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WireStatus {
    Pending,
    Approved,
    Rejected,
}

impl From<InviteQuarantineStatus> for WireStatus {
    fn from(s: InviteQuarantineStatus) -> Self {
        match s {
            InviteQuarantineStatus::Pending => Self::Pending,
            InviteQuarantineStatus::Approved => Self::Approved,
            InviteQuarantineStatus::Rejected => Self::Rejected,
        }
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct InviteQuarantineEntry {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub peer_did: String,
    pub target_holder_did: String,
    pub consent_id: String,
    pub scope: String,
    pub requesting_admin_did: Option<String>,
    pub payload: serde_json::Value,
    pub status: WireStatus,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
}

impl From<InviteQuarantineRecord> for InviteQuarantineEntry {
    fn from(r: InviteQuarantineRecord) -> Self {
        Self {
            id: r.id.to_string(),
            created_at: r.created_at,
            peer_did: r.peer_did,
            target_holder_did: r.target_holder_did,
            consent_id: r.consent_id,
            scope: r.scope,
            requesting_admin_did: r.requesting_admin_did,
            payload: r.payload,
            status: r.status.into(),
            resolved_at: r.resolved_at,
            resolution_note: r.resolution_note,
        }
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct InviteQuarantineListOutcome {
    pub data: Vec<InviteQuarantineEntry>,
}

#[derive(Deserialize, Default, JsonSchema)]
pub struct InviteQuarantineListQuery {
    /// Maximum rows to return (1-1000, default 100).
    pub limit: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResolveDecision {
    Approve,
    Reject,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "ResolveInviteQuarantineRequest")]
pub struct ResolveRequestBody {
    pub decision: ResolveDecision,

    /// Optional operator note recorded alongside the resolution.
    #[serde(default)]
    pub note: Option<String>,
}

/// Response from `resolve_invite_quarantine`. On `approve`, the queue
/// row is marked resolved *and* the original `batch_invite` is re-run
/// (round 21) — the freshly minted registration tokens are returned in
/// `minted_tokens`. On `reject`, only the entry is updated and
/// `minted_tokens` is empty.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct ResolveOutcome {
    pub entry: InviteQuarantineEntry,

    /// Empty when `decision = reject` or when the original payload had
    /// no mintable parameters. Each element matches the shape returned
    /// by `POST /_coauth/admin/users/batch-invite`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub minted_tokens: Vec<SingleOutcome<UserRegistrationToken>>,
}

// ── Helpers ────────────────────────────────────────────────────

fn map_quarantine_error(error: InviteQuarantineError) -> AppError {
    match error {
        InviteQuarantineError::Storage(error) => {
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

/// `GET /_coauth/admin/invite-quarantine`
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.invite_quarantine.list", skip_all)]
pub async fn list_invite_quarantine(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<InviteQuarantineListOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { repo, .. } = ctx;
    let query: InviteQuarantineListQuery = req.parse_queries().unwrap_or_default();
    let queue = depot.invite_quarantine_service()?;
    // REL-10: clamp the caller-supplied limit so an unbounded / negative
    // value cannot drive an oversized scan. Mirrors the 1-1000 range
    // documented on `InviteQuarantineListQuery::limit`.
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    repo.cancel().await?;

    let data = queue
        .list_pending(limit)
        .await
        .map_err(map_quarantine_error)?
        .into_iter()
        .map(InviteQuarantineEntry::from)
        .collect();

    Ok(Json(InviteQuarantineListOutcome { data }))
}

/// `POST /_coauth/admin/invite-quarantine/{id}/resolve`
///
/// Round-21 update: `approve` now actually re-runs the original
/// `batch_invite` using the parameters captured in `payload` at enqueue
/// time. The minted tokens are returned in `ResolveOutcome.minted_tokens`
/// so the caller (sodmin / yougen) doesn't need a follow-up call. The
/// consent gate is not re-evaluated — the operator approving the queue
/// row has explicitly vouched for the consent decision out of band.
///
/// `reject` is unchanged: marks the row resolved and records an audit
/// op without minting anything.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.invite_quarantine.resolve", skip_all)]
pub async fn resolve_invite_quarantine(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ResolveOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let id = extract_uuid_param(req)?;
    let body: ResolveRequestBody = req.parse_json().await.map_err(AppError::internal)?;
    let queue = depot.invite_quarantine_service()?;
    let now = clock.now();

    let new_status = match body.decision {
        ResolveDecision::Approve => InviteQuarantineStatus::Approved,
        ResolveDecision::Reject => InviteQuarantineStatus::Rejected,
    };

    let record = queue
        .mark_resolved(id, new_status, body.note.clone(), now)
        .await
        .map_err(map_quarantine_error)?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "Invite-quarantine entry {id} not found or already resolved"
            ))
        })?;

    // ── Approve auto-replay (round 21) ───────────────────────────
    //
    // batch_invite enqueues the original mint params (count /
    // usage_limit / expires_in_hours) into `payload` at quarantine
    // time. On approve, re-mint the same number of tokens against
    // `repo` and return them in the response. We deliberately do NOT
    // re-run the consent gate here — the operator approving the queue
    // row has already vouched for the consent decision.
    //
    // If `payload` has no recognisable mint params (for example manual
    // queue inserts), we log a warning and fall through to the
    // flag-flip-only path. Reject always falls through.
    let mut minted_tokens: Vec<SingleOutcome<UserRegistrationToken>> = Vec::new();
    if matches!(body.decision, ResolveDecision::Approve) {
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
                        quarantine_id = %record.id,
                        ?error,
                        "invite_quarantine.approve: token mint failed; row resolved without tokens",
                    );
                }
            }
        } else {
            warn!(
                quarantine_id = %record.id,
                "invite_quarantine.approve: payload has no mint params; row resolved without minting",
            );
        }
    }

    let op_label = match body.decision {
        ResolveDecision::Approve => "invite_quarantine.approve",
        ResolveDecision::Reject => "invite_quarantine.reject",
    };

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::Other(op_label.to_owned()),
        "invite_quarantine_queue",
        // Audit table uses Ulid; the queue id is uuid-v7. Pass None
        // for the resource_id slot and stash the uuid in the metadata
        // payload so audit-feed consumers can correlate.
        None,
        serde_json::json!({
            "quarantine_id": record.id.to_string(),
            "decision": op_label.split('.').next_back().unwrap_or(""),
            "peer_did": &record.peer_did,
            "target_holder_did": &record.target_holder_did,
            "consent_id": &record.consent_id,
            "scope": &record.scope,
            "note": body.note,
            "minted_token_count": minted_tokens.len(),
        }),
    )
    .await?;

    repo.save().await?;

    Ok(Json(ResolveOutcome {
        entry: InviteQuarantineEntry::from(record),
        minted_tokens,
    }))
}

/// Pull mint parameters out of the queue row's `payload` JSON. The
/// shape is the one written in
/// `handlers::admin::v1::users::create::batch_invite` at quarantine
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
    //! Pure-helper tests for wire-type mapping. End-to-end coverage of
    //! the list/resolve handlers requires the test-db harness; the
    //! `batch_invite` wiring tests in `users::tests` already exercise the
    //! enqueue path on the same harness.

    use super::*;

    #[test]
    fn wire_status_round_trip() {
        let cases = [
            (InviteQuarantineStatus::Pending, "pending"),
            (InviteQuarantineStatus::Approved, "approved"),
            (InviteQuarantineStatus::Rejected, "rejected"),
        ];
        for (svc, expected) in cases {
            let wire: WireStatus = svc.into();
            let v = serde_json::to_value(wire).unwrap();
            assert_eq!(v, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn entry_from_record_preserves_fields() {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let rec = InviteQuarantineRecord {
            id,
            created_at: now,
            peer_did: "did:web:peer".into(),
            target_holder_did: "did:web:holder".into(),
            consent_id: "c-99".into(),
            scope: "invite".into(),
            requesting_admin_did: Some("admin1".into()),
            payload: serde_json::json!({"count": 3}),
            status: InviteQuarantineStatus::Pending,
            resolved_at: None,
            resolution_note: None,
        };
        let entry = InviteQuarantineEntry::from(rec);
        assert_eq!(entry.id, id.to_string());
        assert_eq!(entry.peer_did, "did:web:peer");
        assert_eq!(entry.target_holder_did, "did:web:holder");
        assert_eq!(entry.consent_id, "c-99");
        assert_eq!(entry.scope, "invite");
        assert_eq!(entry.requesting_admin_did.as_deref(), Some("admin1"));
        assert_eq!(entry.payload["count"], 3);
        assert!(matches!(entry.status, WireStatus::Pending));
    }

    #[test]
    fn resolve_request_parses_approve() {
        let body: ResolveRequestBody = serde_json::from_str(r#"{"decision": "approve"}"#).unwrap();
        assert_eq!(body.decision, ResolveDecision::Approve);
        assert!(body.note.is_none());
    }

    #[test]
    fn resolve_request_parses_reject_with_note() {
        let body: ResolveRequestBody =
            serde_json::from_str(r#"{"decision": "reject", "note": "spam"}"#).unwrap();
        assert_eq!(body.decision, ResolveDecision::Reject);
        assert_eq!(body.note.as_deref(), Some("spam"));
    }

    #[test]
    fn resolve_request_rejects_unknown_decision() {
        let res: Result<ResolveRequestBody, _> = serde_json::from_str(r#"{"decision": "maybe"}"#);
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
