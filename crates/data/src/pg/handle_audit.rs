//! PostgreSQL implementation of the append-only [`HandleAuditRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::audit::{
    HandleAuditEvent, HandleAuditEventType, HandleAuditRepository, NewHandleAuditEvent,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::handle_audit_log;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`HandleAuditRepository`].
pub struct PgHandleAuditRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgHandleAuditRepository<'c> {
    /// Construct from an active connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = handle_audit_log)]
struct HandleAuditRow {
    id: Uuid,
    user_id: Option<Uuid>,
    event_type: String,
    handle: Option<String>,
    handle_aliases: Vec<String>,
    old_did: Option<String>,
    new_did: Option<String>,
    issuer_service_did: Option<String>,
    audience: Option<String>,
    claim_digest: Option<String>,
    details: serde_json::Value,
    actor_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl TryFrom<HandleAuditRow> for HandleAuditEvent {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: HandleAuditRow) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let event_type = parse_event_type(&value.event_type, id)?;
        Ok(HandleAuditEvent {
            id,
            user_id: value.user_id.map(Into::into),
            event_type,
            handle: value.handle,
            handle_aliases: value.handle_aliases,
            old_did: value.old_did,
            new_did: value.new_did,
            issuer_service_did: value.issuer_service_did,
            audience: value.audience,
            claim_digest: value.claim_digest,
            details: value.details,
            actor_id: value.actor_id.map(Into::into),
            created_at: value.created_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = handle_audit_log)]
struct InsertableHandleAudit {
    id: Uuid,
    user_id: Option<Uuid>,
    event_type: String,
    handle: Option<String>,
    handle_aliases: Vec<String>,
    old_did: Option<String>,
    new_did: Option<String>,
    issuer_service_did: Option<String>,
    audience: Option<String>,
    claim_digest: Option<String>,
    details: serde_json::Value,
    actor_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

fn event_type_to_db(event_type: &HandleAuditEventType) -> String {
    serde_json::to_value(event_type)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn parse_event_type(
    raw: &str,
    id: Ulid,
) -> Result<HandleAuditEventType, DatabaseInconsistencyError> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned())).map_err(|e| {
        DatabaseInconsistencyError::on("handle_audit_log")
            .column("event_type")
            .row(id)
            .source(e)
    })
}

#[async_trait]
impl HandleAuditRepository for PgHandleAuditRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.handle_audit.record",
        skip_all,
        fields(
            handle_audit_log.id,
            handle_audit_log.user_id = params.user_id().map(|u| u.to_string()),
        ),
        err,
    )]
    async fn record(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewHandleAuditEvent,
    ) -> Result<HandleAuditEvent, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("handle_audit_log.id", tracing::field::display(id));

        let row = InsertableHandleAudit {
            id: Uuid::from(id),
            user_id: params.user_id().map(Uuid::from),
            event_type: event_type_to_db(params.event_type()),
            handle: params.handle().map(ToOwned::to_owned),
            handle_aliases: params.handle_aliases().to_vec(),
            old_did: params.old_did().map(ToOwned::to_owned),
            new_did: params.new_did().map(ToOwned::to_owned),
            issuer_service_did: params.issuer_service_did().map(ToOwned::to_owned),
            audience: params.audience().map(ToOwned::to_owned),
            claim_digest: params.claim_digest().map(ToOwned::to_owned),
            details: params.details().clone(),
            actor_id: params.actor_id().map(Uuid::from),
            created_at,
        };

        diesel::insert_into(handle_audit_log::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(HandleAuditEvent {
            id,
            user_id: params.user_id(),
            event_type: *params.event_type(),
            handle: row.handle,
            handle_aliases: row.handle_aliases,
            old_did: row.old_did,
            new_did: row.new_did,
            issuer_service_did: row.issuer_service_did,
            audience: row.audience,
            claim_digest: row.claim_digest,
            details: row.details,
            actor_id: params.actor_id(),
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.handle_audit.list_for_user",
        skip_all,
        fields(handle_audit_log.user_id = %user_id),
        err,
    )]
    async fn list_for_user(
        &mut self,
        user_id: Ulid,
        limit: usize,
    ) -> Result<Vec<HandleAuditEvent>, Self::Error> {
        let limit = i64::try_from(limit).unwrap_or(100);
        handle_audit_log::table
            .filter(handle_audit_log::user_id.eq(Some(Uuid::from(user_id))))
            .order(handle_audit_log::created_at.desc())
            .limit(limit)
            .select(HandleAuditRow::as_select())
            .load::<HandleAuditRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.handle_audit.list_by_event_type", skip_all, err)]
    async fn list_by_event_type(
        &mut self,
        event_type: HandleAuditEventType,
        limit: usize,
    ) -> Result<Vec<HandleAuditEvent>, Self::Error> {
        let limit = i64::try_from(limit).unwrap_or(100);
        let kind = event_type_to_db(&event_type);
        handle_audit_log::table
            .filter(handle_audit_log::event_type.eq(kind))
            .order(handle_audit_log::created_at.desc())
            .limit(limit)
            .select(HandleAuditRow::as_select())
            .load::<HandleAuditRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.handle_audit.lookup",
        skip_all,
        fields(handle_audit_log.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<HandleAuditEvent>, Self::Error> {
        handle_audit_log::table
            .find(Uuid::from(id))
            .select(HandleAuditRow::as_select())
            .first::<HandleAuditRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.handle_audit.count_for_user",
        skip_all,
        fields(handle_audit_log.user_id = %user_id),
        err,
    )]
    async fn count_for_user(&mut self, user_id: Ulid) -> Result<usize, Self::Error> {
        let count: i64 = handle_audit_log::table
            .filter(handle_audit_log::user_id.eq(Some(Uuid::from(user_id))))
            .count()
            .get_result(self.conn)
            .await?;
        Ok(count as usize)
    }
}
