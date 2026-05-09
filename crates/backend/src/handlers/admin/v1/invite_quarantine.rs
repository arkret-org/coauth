// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Admin review surface for the invite-quarantine outbox queue.
//!
//! Spec context: `contrix-spec` `consent-model.md` §6.1 default-profile
//! path. When the consent gate in `batch_invite` returns `Quarantined`,
//! the invite intent is persisted to `invite_quarantine_queue` (see
//! `crates/backend/src/services/invite_quarantine.rs`). Operators
//! (sodmin / yougen) review the queue here.
//!
//! Endpoints:
//!
//! - `GET  /api/admin/v1/invite-quarantine` — list pending entries.
//! - `POST /api/admin/v1/invite-quarantine/{id}/resolve` — body
//!   `{ "decision": "approve"|"reject", "note"?: "..." }`. Approve marks
//!   the row resolved (the actual re-run of the original invite is the
//!   caller's responsibility — sodmin re-issues `batch-invite` once it
//!   has verified consent out of band). Reject marks the row resolved
//!   without re-running.
//!
//! ## Why approve does not auto-mint
//!
//! The original `batch_invite` only minted registration tokens; the
//! consent decision context (peer DID, target holder DID) lives in the
//! queue row but the *registration policy* (count, usage_limit, expiry)
//! is in the `payload` JSON. Re-issuing requires the admin to confirm
//! those parameters via a fresh batch-invite call. The "approve"
//! transition therefore unblocks future calls (the holder's consent has
//! been resolved out of band) rather than auto-minting tokens that the
//! caller never reviewed.

use chrono::{DateTime, Utc};
use coauth_data::audit::AdminOperation;
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppError, JsonResult,
    handlers::{
        admin::{audit_helper::record_admin_operation, call_context::extract_call_context},
        common::DepotExt,
    },
    services::invite_quarantine::{
        InviteQuarantineError, InviteQuarantineRecord, InviteQuarantineStatus,
    },
};

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
pub struct InviteQuarantineListResponse {
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
pub struct ResolveRequest {
    pub decision: ResolveDecision,

    /// Optional operator note recorded alongside the resolution.
    #[serde(default)]
    pub note: Option<String>,
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

/// `GET /api/admin/v1/invite-quarantine`
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.invite_quarantine.list", skip_all)]
pub async fn list_invite_quarantine(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<InviteQuarantineListResponse> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { repo, .. } = ctx;
    let query: InviteQuarantineListQuery = req.parse_queries().unwrap_or_default();
    let queue = depot.invite_quarantine_service()?;
    let limit = query.limit.unwrap_or(100);
    repo.cancel().await?;

    let data = queue
        .list_pending(limit)
        .await
        .map_err(map_quarantine_error)?
        .into_iter()
        .map(InviteQuarantineEntry::from)
        .collect();

    Ok(Json(InviteQuarantineListResponse { data }))
}

/// `POST /api/admin/v1/invite-quarantine/{id}/resolve`
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.invite_quarantine.resolve", skip_all)]
pub async fn resolve_invite_quarantine(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<InviteQuarantineEntry> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let id = extract_uuid_param(req)?;
    let body: ResolveRequest = req.parse_json().await.map_err(AppError::internal)?;
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

    // Note: Approve is intentionally a *flag flip* — it does not
    // auto-replay the original `batch_invite`. See module docs.
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
        }),
    )
    .await?;

    repo.save().await?;

    Ok(Json(InviteQuarantineEntry::from(record)))
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Pure-helper tests for wire-type mapping. End-to-end coverage of
    //! the list/resolve handlers requires the test-db harness; the
    //! batch_invite wiring tests in `users::tests` already exercise the
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
        let body: ResolveRequest =
            serde_json::from_str(r#"{"decision": "approve"}"#).unwrap();
        assert_eq!(body.decision, ResolveDecision::Approve);
        assert!(body.note.is_none());
    }

    #[test]
    fn resolve_request_parses_reject_with_note() {
        let body: ResolveRequest =
            serde_json::from_str(r#"{"decision": "reject", "note": "spam"}"#).unwrap();
        assert_eq!(body.decision, ResolveDecision::Reject);
        assert_eq!(body.note.as_deref(), Some("spam"));
    }

    #[test]
    fn resolve_request_rejects_unknown_decision() {
        let res: Result<ResolveRequest, _> =
            serde_json::from_str(r#"{"decision": "maybe"}"#);
        assert!(res.is_err(), "unknown decision must not parse");
    }
}
