// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Invite-quarantine outbox queue (C10.E §6.1 default-profile path).
//!
//! When the consent gate in `batch_invite` returns `Quarantined` (and the
//! per-recipient relay path returns `Quarantine`), spec §6.1 says the
//! invite intent should be persisted to a holder-side queue rather than
//! immediately rejected. Sodmin / inkson review the queue and either
//! re-run the original invite or mark it rejected.
//!
//! This module is the persistence layer for that queue. The admin review
//! UI lives at `crates/backend/src/handlers/admin/v1/invite_quarantine.rs`.
//!
//! Design notes:
//!
//! - We use raw SQL via diesel's `sql_query` to stay consistent with the `account_claims` service
//!   style. The queue table is small and write- through; no need for the full `Repository`
//!   abstraction.
//! - `payload` carries an opaque JSON envelope so callers can stash the minted-but-quarantined
//!   token bundle (or the original invite request body) without coupling the queue schema to one
//!   caller's shape.
//! - Status transitions are intentionally narrow: `pending` → `approved` or `pending` → `rejected`.
//!   Re-opening a resolved row is a future concern (out of scope this round).

use std::sync::Arc;

use arkret_wire::DidCoreId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::QueryableByName;
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid};
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub type InviteQuarantineServiceHandle = Arc<dyn InviteQuarantineService>;

/// Lifecycle state of a queued invite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteQuarantineStatus {
    Pending,
    Approved,
    Rejected,
}

impl InviteQuarantineStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Outbound DTO for a queued row.
#[derive(Clone, Debug)]
pub struct InviteQuarantineRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub peer_principal_id: DidCoreId,
    pub target_holder_id: DidCoreId,
    pub consent_id: String,
    pub scope: String,
    pub requesting_admin_localpart: Option<String>,
    /// Original quarantined invite document. Its shape is independent of the
    /// quarantine lifecycle `status` and is never dispatched by that status.
    pub payload: Value,
    pub status: InviteQuarantineStatus,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
}

/// Inbound DTO for `enqueue`. `payload` may be `Value::Null` when the
/// caller only needs to record the gate decision (the typical case for
/// `batch_invite`, which has not minted any tokens yet at the gate point).
#[derive(Clone, Debug)]
pub struct EnqueueInviteQuarantine {
    pub peer_principal_id: DidCoreId,
    pub target_holder_id: DidCoreId,
    pub consent_id: String,
    pub scope: String,
    pub requesting_admin_localpart: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Error)]
pub enum InviteQuarantineError {
    #[error("invite quarantine storage failed: {0}")]
    Storage(#[from] anyhow::Error),
}

#[async_trait]
pub trait InviteQuarantineService: Send + Sync {
    async fn enqueue(
        &self,
        input: EnqueueInviteQuarantine,
    ) -> Result<InviteQuarantineRecord, InviteQuarantineError>;

    async fn list_pending(
        &self,
        limit: i64,
    ) -> Result<Vec<InviteQuarantineRecord>, InviteQuarantineError>;

    async fn get(&self, id: Uuid) -> Result<Option<InviteQuarantineRecord>, InviteQuarantineError>;

    /// Mark a row as resolved (`approved` or `rejected`). Returns `Ok(None)`
    /// when the row does not exist or is already resolved.
    async fn mark_resolved(
        &self,
        id: Uuid,
        new_status: InviteQuarantineStatus,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
    ) -> Result<Option<InviteQuarantineRecord>, InviteQuarantineError>;
}

#[derive(Debug, QueryableByName)]
struct InviteQuarantineRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    peer_principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    target_holder_id: DidCoreId,
    #[diesel(sql_type = Text)]
    consent_id: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Nullable<Text>)]
    requesting_admin_localpart: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    resolved_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    resolution_note: Option<String>,
}

impl InviteQuarantineRow {
    fn try_into_record(self) -> anyhow::Result<InviteQuarantineRecord> {
        let status = InviteQuarantineStatus::parse(&self.status)
            .ok_or_else(|| anyhow::anyhow!("invalid invite quarantine status: {}", self.status))?;
        Ok(InviteQuarantineRecord {
            id: self.id,
            created_at: self.created_at,
            peer_principal_id: self.peer_principal_id,
            target_holder_id: self.target_holder_id,
            consent_id: self.consent_id,
            scope: self.scope,
            requesting_admin_localpart: self.requesting_admin_localpart,
            payload: self.payload,
            status,
            resolved_at: self.resolved_at,
            resolution_note: self.resolution_note,
        })
    }
}

pub struct PgInviteQuarantineService {
    pool: DieselPool<AsyncPgConnection>,
}

impl PgInviteQuarantineService {
    fn new(pool: DieselPool<AsyncPgConnection>) -> Self {
        Self { pool }
    }

    async fn enqueue_inner(
        &self,
        input: EnqueueInviteQuarantine,
    ) -> anyhow::Result<InviteQuarantineRecord> {
        let id = Uuid::now_v7();
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            INSERT INTO invite_quarantine_queue (
                id,
                peer_principal_id,
                target_holder_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
            RETURNING
                id,
                created_at,
                peer_principal_id,
                target_holder_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status,
                resolved_at,
                resolution_note
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<Text, _>(input.peer_principal_id.as_str())
        .bind::<Text, _>(input.target_holder_id.as_str())
        .bind::<Text, _>(input.consent_id)
        .bind::<Text, _>(input.scope)
        .bind::<Nullable<Text>, _>(input.requesting_admin_localpart)
        .bind::<Jsonb, _>(input.payload)
        .get_results::<InviteQuarantineRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(InviteQuarantineRow::try_into_record)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("invite_quarantine_queue insert returned no row"))
    }

    async fn list_pending_inner(&self, limit: i64) -> anyhow::Result<Vec<InviteQuarantineRecord>> {
        let limit = limit.clamp(1, 1000);
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            SELECT
                id,
                created_at,
                peer_principal_id,
                target_holder_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status,
                resolved_at,
                resolution_note
            FROM invite_quarantine_queue
            WHERE status = 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT $1
            ",
        )
        .bind::<BigInt, _>(limit)
        .get_results::<InviteQuarantineRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .map(InviteQuarantineRow::try_into_record)
            .collect()
    }

    async fn get_inner(&self, id: Uuid) -> anyhow::Result<Option<InviteQuarantineRecord>> {
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            SELECT
                id,
                created_at,
                peer_principal_id,
                target_holder_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status,
                resolved_at,
                resolution_note
            FROM invite_quarantine_queue
            WHERE id = $1
            ",
        )
        .bind::<DieselUuid, _>(id)
        .get_results::<InviteQuarantineRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(InviteQuarantineRow::try_into_record)
            .transpose()
    }

    async fn mark_resolved_inner(
        &self,
        id: Uuid,
        new_status: InviteQuarantineStatus,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<InviteQuarantineRecord>> {
        let mut conn = self.pool.get().await?;
        // Only transition `pending` rows. Already-resolved rows are
        // returned as `None` so the caller can render a 409.
        let rows = diesel::sql_query(
            r"
            UPDATE invite_quarantine_queue
            SET
                status = $2,
                resolved_at = $3,
                resolution_note = $4
            WHERE id = $1 AND status = 'pending'
            RETURNING
                id,
                created_at,
                peer_principal_id,
                target_holder_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status,
                resolved_at,
                resolution_note
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<Text, _>(new_status.as_str().to_owned())
        .bind::<Timestamptz, _>(resolved_at)
        .bind::<Nullable<Text>, _>(note)
        .get_results::<InviteQuarantineRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(InviteQuarantineRow::try_into_record)
            .transpose()
    }
}

#[async_trait]
impl InviteQuarantineService for PgInviteQuarantineService {
    async fn enqueue(
        &self,
        input: EnqueueInviteQuarantine,
    ) -> Result<InviteQuarantineRecord, InviteQuarantineError> {
        self.enqueue_inner(input)
            .await
            .map_err(InviteQuarantineError::from)
    }

    async fn list_pending(
        &self,
        limit: i64,
    ) -> Result<Vec<InviteQuarantineRecord>, InviteQuarantineError> {
        self.list_pending_inner(limit)
            .await
            .map_err(InviteQuarantineError::from)
    }

    async fn get(&self, id: Uuid) -> Result<Option<InviteQuarantineRecord>, InviteQuarantineError> {
        self.get_inner(id)
            .await
            .map_err(InviteQuarantineError::from)
    }

    async fn mark_resolved(
        &self,
        id: Uuid,
        new_status: InviteQuarantineStatus,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
    ) -> Result<Option<InviteQuarantineRecord>, InviteQuarantineError> {
        self.mark_resolved_inner(id, new_status, note, resolved_at)
            .await
            .map_err(InviteQuarantineError::from)
    }
}

#[must_use]
pub fn invite_quarantine_service(
    pool: DieselPool<AsyncPgConnection>,
) -> InviteQuarantineServiceHandle {
    Arc::new(PgInviteQuarantineService::new(pool))
}

#[cfg(test)]
mod tests {
    //! Pure-helper tests. The full enqueue/list/resolve loop requires a
    //! Postgres pool — covered by the existing test-db harness in the
    //! admin handler tests, alongside the round-19 wiremock pattern.

    use super::*;

    #[test]
    fn status_round_trips() {
        for s in [
            InviteQuarantineStatus::Pending,
            InviteQuarantineStatus::Approved,
            InviteQuarantineStatus::Rejected,
        ] {
            assert_eq!(InviteQuarantineStatus::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn status_parse_unknown_returns_none() {
        assert!(InviteQuarantineStatus::parse("bogus").is_none());
        assert!(InviteQuarantineStatus::parse("").is_none());
    }

    #[test]
    fn row_into_record_rejects_unknown_status() {
        let row = InviteQuarantineRow {
            id: Uuid::now_v7(),
            created_at: Utc::now(),
            peer_principal_id: "ak:did_core:web:p".parse().unwrap(),
            target_holder_id: "ak:did_core:web:h".parse().unwrap(),
            consent_id: "c-1".into(),
            scope: "invite".into(),
            requesting_admin_localpart: None,
            payload: serde_json::json!({}),
            status: "totally-bogus".into(),
            resolved_at: None,
            resolution_note: None,
        };
        assert!(row.try_into_record().is_err());
    }

    #[test]
    fn enqueue_dto_carries_payload() {
        let dto = EnqueueInviteQuarantine {
            peer_principal_id: DidCoreId::new("ak:did_core:web:peer").unwrap(),
            target_holder_id: DidCoreId::new("ak:did_core:web:holder").unwrap(),
            consent_id: "c-1".into(),
            scope: "invite".into(),
            requesting_admin_localpart: Some("admin".into()),
            payload: serde_json::json!({"reason": "missing-grant"}),
        };
        assert_eq!(dto.scope, "invite");
        assert_eq!(dto.payload["reason"], "missing-grant");
    }
}
