// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Persistence for the initiating deployment's administrator invite review queue.
//!
//! `batch_invite` saves registration-token mint parameters here when its local
//! gate needs administrator review. These rows belong to the issuing Coauth
//! deployment, and administrators resolve them through the admin API.
//!
//! Holder-private invite admission and `ak.account.holder_quarantine` are owned
//! by the holder Station; this administrative outbox does not implement them
//! or change a holder's Consent state.
//!
//! Design notes:
//!
//! - We use raw SQL via diesel's `sql_query` to stay consistent with the `account_claims` service
//!   style. The queue table is small and write- through; no need for the full `Repository`
//!   abstraction.
//! - `payload` carries an opaque JSON envelope so callers can stash the deferred token bundle (or
//!   the original invite request body) without coupling the queue schema to one caller's shape.
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

pub type AdminInviteReviewServiceHandle = Arc<dyn AdminInviteReviewService>;

/// Lifecycle state of a queued invite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminInviteReviewStatus {
    Pending,
    Approved,
    Rejected,
}

impl AdminInviteReviewStatus {
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
pub struct AdminInviteReviewRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub peer_principal_id: DidCoreId,
    pub target_holder_principal_id: DidCoreId,
    pub consent_id: String,
    pub scope: String,
    pub requesting_admin_localpart: Option<String>,
    /// Original invite review document. Its shape is independent of the
    /// review lifecycle `status` and is never dispatched by that status.
    pub payload: Value,
    pub status: AdminInviteReviewStatus,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
}

/// Inbound DTO for `enqueue`. `payload` may be `Value::Null` when the
/// caller only needs to record the gate decision (the typical case for
/// `batch_invite`, which has not minted any tokens yet at the gate point).
#[derive(Clone, Debug)]
pub struct EnqueueAdminInviteReview {
    pub peer_principal_id: DidCoreId,
    pub target_holder_principal_id: DidCoreId,
    pub consent_id: String,
    pub scope: String,
    pub requesting_admin_localpart: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Error)]
pub enum AdminInviteReviewError {
    #[error("admin invite review storage failed: {0}")]
    Storage(#[from] anyhow::Error),
}

#[async_trait]
pub trait AdminInviteReviewService: Send + Sync {
    async fn enqueue(
        &self,
        input: EnqueueAdminInviteReview,
    ) -> Result<AdminInviteReviewRecord, AdminInviteReviewError>;

    async fn list_pending(
        &self,
        limit: i64,
    ) -> Result<Vec<AdminInviteReviewRecord>, AdminInviteReviewError>;

    async fn get(
        &self,
        id: Uuid,
    ) -> Result<Option<AdminInviteReviewRecord>, AdminInviteReviewError>;

    /// Mark a row as resolved (`approved` or `rejected`). Returns `Ok(None)`
    /// when the row does not exist or is already resolved.
    async fn mark_resolved(
        &self,
        id: Uuid,
        new_status: AdminInviteReviewStatus,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
    ) -> Result<Option<AdminInviteReviewRecord>, AdminInviteReviewError>;
}

#[derive(Debug, QueryableByName)]
struct AdminInviteReviewRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    peer_principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    target_holder_principal_id: DidCoreId,
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

impl AdminInviteReviewRow {
    fn try_into_record(self) -> anyhow::Result<AdminInviteReviewRecord> {
        let status = AdminInviteReviewStatus::parse(&self.status).ok_or_else(|| {
            anyhow::anyhow!("invalid admin invite review status: {}", self.status)
        })?;
        Ok(AdminInviteReviewRecord {
            id: self.id,
            created_at: self.created_at,
            peer_principal_id: self.peer_principal_id,
            target_holder_principal_id: self.target_holder_principal_id,
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

pub struct PgAdminInviteReviewService {
    pool: DieselPool<AsyncPgConnection>,
}

impl PgAdminInviteReviewService {
    fn new(pool: DieselPool<AsyncPgConnection>) -> Self {
        Self { pool }
    }

    async fn enqueue_inner(
        &self,
        input: EnqueueAdminInviteReview,
    ) -> anyhow::Result<AdminInviteReviewRecord> {
        let id = Uuid::now_v7();
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            INSERT INTO admin_invite_review_queue (
                id,
                peer_principal_id,
                target_holder_principal_id,
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
                target_holder_principal_id,
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
        .bind::<Text, _>(input.target_holder_principal_id.as_str())
        .bind::<Text, _>(input.consent_id)
        .bind::<Text, _>(input.scope)
        .bind::<Nullable<Text>, _>(input.requesting_admin_localpart)
        .bind::<Jsonb, _>(input.payload)
        .get_results::<AdminInviteReviewRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(AdminInviteReviewRow::try_into_record)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("admin_invite_review_queue insert returned no row"))
    }

    async fn list_pending_inner(&self, limit: i64) -> anyhow::Result<Vec<AdminInviteReviewRecord>> {
        let limit = limit.clamp(1, 1000);
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            SELECT
                id,
                created_at,
                peer_principal_id,
                target_holder_principal_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status,
                resolved_at,
                resolution_note
            FROM admin_invite_review_queue
            WHERE status = 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT $1
            ",
        )
        .bind::<BigInt, _>(limit)
        .get_results::<AdminInviteReviewRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .map(AdminInviteReviewRow::try_into_record)
            .collect()
    }

    async fn get_inner(&self, id: Uuid) -> anyhow::Result<Option<AdminInviteReviewRecord>> {
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            SELECT
                id,
                created_at,
                peer_principal_id,
                target_holder_principal_id,
                consent_id,
                scope,
                requesting_admin_localpart,
                payload,
                status,
                resolved_at,
                resolution_note
            FROM admin_invite_review_queue
            WHERE id = $1
            ",
        )
        .bind::<DieselUuid, _>(id)
        .get_results::<AdminInviteReviewRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(AdminInviteReviewRow::try_into_record)
            .transpose()
    }

    async fn mark_resolved_inner(
        &self,
        id: Uuid,
        new_status: AdminInviteReviewStatus,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<AdminInviteReviewRecord>> {
        let mut conn = self.pool.get().await?;
        // Only transition `pending` rows. Already-resolved rows are
        // returned as `None` so the caller can render the existing not-found outcome.
        let rows = diesel::sql_query(
            r"
            UPDATE admin_invite_review_queue
            SET
                status = $2,
                resolved_at = $3,
                resolution_note = $4
            WHERE id = $1 AND status = 'pending'
            RETURNING
                id,
                created_at,
                peer_principal_id,
                target_holder_principal_id,
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
        .get_results::<AdminInviteReviewRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(AdminInviteReviewRow::try_into_record)
            .transpose()
    }
}

#[async_trait]
impl AdminInviteReviewService for PgAdminInviteReviewService {
    async fn enqueue(
        &self,
        input: EnqueueAdminInviteReview,
    ) -> Result<AdminInviteReviewRecord, AdminInviteReviewError> {
        self.enqueue_inner(input)
            .await
            .map_err(AdminInviteReviewError::from)
    }

    async fn list_pending(
        &self,
        limit: i64,
    ) -> Result<Vec<AdminInviteReviewRecord>, AdminInviteReviewError> {
        self.list_pending_inner(limit)
            .await
            .map_err(AdminInviteReviewError::from)
    }

    async fn get(
        &self,
        id: Uuid,
    ) -> Result<Option<AdminInviteReviewRecord>, AdminInviteReviewError> {
        self.get_inner(id)
            .await
            .map_err(AdminInviteReviewError::from)
    }

    async fn mark_resolved(
        &self,
        id: Uuid,
        new_status: AdminInviteReviewStatus,
        note: Option<String>,
        resolved_at: DateTime<Utc>,
    ) -> Result<Option<AdminInviteReviewRecord>, AdminInviteReviewError> {
        self.mark_resolved_inner(id, new_status, note, resolved_at)
            .await
            .map_err(AdminInviteReviewError::from)
    }
}

#[must_use]
pub fn admin_invite_review_service(
    pool: DieselPool<AsyncPgConnection>,
) -> AdminInviteReviewServiceHandle {
    Arc::new(PgAdminInviteReviewService::new(pool))
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
            AdminInviteReviewStatus::Pending,
            AdminInviteReviewStatus::Approved,
            AdminInviteReviewStatus::Rejected,
        ] {
            assert_eq!(AdminInviteReviewStatus::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn status_parse_unknown_returns_none() {
        assert!(AdminInviteReviewStatus::parse("bogus").is_none());
        assert!(AdminInviteReviewStatus::parse("").is_none());
    }

    #[test]
    fn row_into_record_rejects_unknown_status() {
        let row = AdminInviteReviewRow {
            id: Uuid::now_v7(),
            created_at: Utc::now(),
            peer_principal_id: "ak:did_core:web:p".parse().unwrap(),
            target_holder_principal_id: "ak:did_core:web:h".parse().unwrap(),
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
        let dto = EnqueueAdminInviteReview {
            peer_principal_id: DidCoreId::new("ak:did_core:web:peer").unwrap(),
            target_holder_principal_id: DidCoreId::new("ak:did_core:web:holder").unwrap(),
            consent_id: "c-1".into(),
            scope: "invite".into(),
            requesting_admin_localpart: Some("admin".into()),
            payload: serde_json::json!({"reason": "missing-grant"}),
        };
        assert_eq!(dto.scope, "invite");
        assert_eq!(dto.payload["reason"], "missing-grant");
    }
}
