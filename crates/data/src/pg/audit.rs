use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock,
    audit::{
        AccountSecurityEvent, AdminOperation, AdminOperationFilter, AdminOperationLog,
        AuditRepository, NewAccountSecurityEvent, NewAdminOperationLog, SecurityEventType,
    },
    new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    schema::{account_security_events, admin_operation_logs},
};

/// PostgreSQL implementation of [`AuditRepository`].
pub struct PgAuditRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAuditRepository<'c> {
    /// Create a new [`PgAuditRepository`] from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = admin_operation_logs)]
struct AdminOperationLogRow {
    id: Uuid,
    admin_user_id: Uuid,
    operation: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    details: serde_json::Value,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
    audit_signature: Option<String>,
}

impl TryFrom<AdminOperationLogRow> for AdminOperationLog {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AdminOperationLogRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        let operation = parse_admin_operation(&value.operation, id)?;

        Ok(AdminOperationLog {
            id,
            admin_user_id: value.admin_user_id.into(),
            operation,
            resource_type: value.resource_type,
            resource_id: value.resource_id.map(Into::into),
            details: value.details,
            ip_address: value.ip_address.map(|ip| ip.ip()),
            user_agent: value.user_agent,
            created_at: value.created_at,
            audit_signature: value.audit_signature,
        })
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = account_security_events)]
struct AccountSecurityEventRow {
    id: Uuid,
    user_id: Uuid,
    event_type: String,
    metadata: serde_json::Value,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
}

impl TryFrom<AccountSecurityEventRow> for AccountSecurityEvent {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AccountSecurityEventRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        let event_type = parse_security_event_type(&value.event_type, id)?;

        Ok(AccountSecurityEvent {
            id,
            user_id: value.user_id.into(),
            event_type,
            metadata: value.metadata,
            ip_address: value.ip_address.map(|ip| ip.ip()),
            user_agent: value.user_agent,
            created_at: value.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Insertable types
// ---------------------------------------------------------------------------

#[derive(Insertable)]
#[diesel(table_name = admin_operation_logs)]
struct InsertableAdminOperationLog {
    id: Uuid,
    admin_user_id: Uuid,
    operation: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    details: serde_json::Value,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
    audit_signature: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = account_security_events)]
struct InsertableAccountSecurityEvent {
    id: Uuid,
    user_id: Uuid,
    event_type: String,
    metadata: serde_json::Value,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Enum serialization helpers
// ---------------------------------------------------------------------------

fn admin_operation_to_db(op: &AdminOperation) -> String {
    // serde_json serializes the enum to a JSON value; for unit variants this is
    // a JSON string like `"user_created"`, for `Other(s)` it produces
    // `{"other":"s"}`.  We store the JSON representation as text.
    serde_json::to_string(op).expect("AdminOperation should always serialize")
}

fn parse_admin_operation(
    raw: &str,
    id: Ulid,
) -> Result<AdminOperation, DatabaseInconsistencyError> {
    serde_json::from_str(raw).map_err(|e| {
        DatabaseInconsistencyError::on("admin_operation_logs")
            .column("operation")
            .row(id)
            .source(e)
    })
}

fn security_event_type_to_db(evt: &SecurityEventType) -> String {
    serde_json::to_string(evt).expect("SecurityEventType should always serialize")
}

fn parse_security_event_type(
    raw: &str,
    id: Ulid,
) -> Result<SecurityEventType, DatabaseInconsistencyError> {
    serde_json::from_str(raw).map_err(|e| {
        DatabaseInconsistencyError::on("account_security_events")
            .column("event_type")
            .row(id)
            .source(e)
    })
}

// ---------------------------------------------------------------------------
// Repository implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl AuditRepository for PgAuditRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.audit.add_admin_operation",
        skip_all,
        fields(
            admin_operation_log.id,
            admin_operation_log.admin_user_id = %params.admin_user_id(),
        ),
        err,
    )]
    async fn add_admin_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAdminOperationLog,
    ) -> Result<AdminOperationLog, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("admin_operation_log.id", tracing::field::display(id));

        let operation = params.operation().clone();
        let ip_address = params.ip_address();

        let row = InsertableAdminOperationLog {
            id: Uuid::from(id),
            admin_user_id: Uuid::from(params.admin_user_id()),
            operation: admin_operation_to_db(&operation),
            resource_type: params.resource_type().to_owned(),
            resource_id: params.resource_id().map(Uuid::from),
            details: params.details().clone(),
            ip_address: ip_address.map(IpNetwork::from),
            user_agent: params.user_agent().map(ToOwned::to_owned),
            created_at,
            audit_signature: params.audit_signature().map(ToOwned::to_owned),
        };

        diesel::insert_into(admin_operation_logs::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(AdminOperationLog {
            id,
            admin_user_id: params.admin_user_id(),
            operation,
            resource_type: row.resource_type,
            resource_id: params.resource_id(),
            details: row.details,
            ip_address,
            user_agent: row.user_agent,
            created_at,
            audit_signature: row.audit_signature,
        })
    }

    #[tracing::instrument(
        name = "db.audit.lookup_admin_operation",
        skip_all,
        fields(admin_operation_log.id = %id),
        err,
    )]
    async fn lookup_admin_operation(
        &mut self,
        id: Ulid,
    ) -> Result<Option<AdminOperationLog>, Self::Error> {
        admin_operation_logs::table
            .find(Uuid::from(id))
            .select(AdminOperationLogRow::as_select())
            .first::<AdminOperationLogRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.audit.list_admin_operations",
        skip_all,
        fields(
            filter.admin_user_id = filter.admin_user_id.map(|id| id.to_string()),
            filter.resource_type = filter.resource_type.as_deref(),
        ),
        err,
    )]
    async fn list_admin_operations(
        &mut self,
        filter: AdminOperationFilter,
    ) -> Result<Vec<AdminOperationLog>, Self::Error> {
        let limit = filter
            .limit
            .and_then(|l| i64::try_from(l).ok())
            .unwrap_or(100);

        let mut query = admin_operation_logs::table
            .order(admin_operation_logs::created_at.desc())
            .limit(limit)
            .select(AdminOperationLogRow::as_select())
            .into_boxed();

        if let Some(admin_user_id) = filter.admin_user_id {
            query = query.filter(admin_operation_logs::admin_user_id.eq(Uuid::from(admin_user_id)));
        }

        if let Some(ref resource_type) = filter.resource_type {
            query = query.filter(admin_operation_logs::resource_type.eq(resource_type));
        }

        if let Some(created_after) = filter.created_after {
            query = query.filter(admin_operation_logs::created_at.ge(created_after));
        }

        if let Some(created_before) = filter.created_before {
            query = query.filter(admin_operation_logs::created_at.le(created_before));
        }

        query
            .load::<AdminOperationLogRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.audit.count_admin_operations",
        skip_all,
        fields(
            filter.admin_user_id = filter.admin_user_id.map(|id| id.to_string()),
            filter.resource_type = filter.resource_type.as_deref(),
        ),
        err,
    )]
    async fn count_admin_operations(
        &mut self,
        filter: AdminOperationFilter,
    ) -> Result<usize, Self::Error> {
        let mut query = admin_operation_logs::table.into_boxed();

        if let Some(admin_user_id) = filter.admin_user_id {
            query = query.filter(admin_operation_logs::admin_user_id.eq(Uuid::from(admin_user_id)));
        }

        if let Some(ref resource_type) = filter.resource_type {
            query = query.filter(admin_operation_logs::resource_type.eq(resource_type));
        }

        if let Some(created_after) = filter.created_after {
            query = query.filter(admin_operation_logs::created_at.ge(created_after));
        }

        if let Some(created_before) = filter.created_before {
            query = query.filter(admin_operation_logs::created_at.le(created_before));
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        Ok(count as usize)
    }

    #[tracing::instrument(
        name = "db.audit.add_security_event",
        skip_all,
        fields(
            account_security_event.id,
            account_security_event.user_id = %params.user_id(),
        ),
        err,
    )]
    async fn add_security_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountSecurityEvent,
    ) -> Result<AccountSecurityEvent, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("account_security_event.id", tracing::field::display(id));

        let event_type = params.event_type().clone();
        let ip_address = params.ip_address();

        let row = InsertableAccountSecurityEvent {
            id: Uuid::from(id),
            user_id: Uuid::from(params.user_id()),
            event_type: security_event_type_to_db(&event_type),
            metadata: params.metadata().clone(),
            ip_address: ip_address.map(IpNetwork::from),
            user_agent: params.user_agent().map(ToOwned::to_owned),
            created_at,
        };

        diesel::insert_into(account_security_events::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(AccountSecurityEvent {
            id,
            user_id: params.user_id(),
            event_type,
            metadata: row.metadata,
            ip_address,
            user_agent: row.user_agent,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.audit.list_security_events",
        skip_all,
        fields(
            account_security_event.user_id = %user_id,
        ),
        err,
    )]
    async fn list_security_events(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountSecurityEvent>, Self::Error> {
        account_security_events::table
            .filter(account_security_events::user_id.eq(Uuid::from(user_id)))
            .order(account_security_events::created_at.desc())
            .limit(100)
            .select(AccountSecurityEventRow::as_select())
            .load::<AccountSecurityEventRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}
