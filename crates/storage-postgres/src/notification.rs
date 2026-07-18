use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::notification::{
    NewNotificationDelivery, NewNotificationEventLog, NewNotificationRequest,
    NotificationRepository,
};
use coauth_data::{
    Clock, NotificationChannel, NotificationDelivery, NotificationDeliveryFailure,
    NotificationDeliveryStatus, NotificationEventKind, NotificationEventLog,
    NotificationPreference, NotificationRequest, NotificationRequestStatus, User, new_id,
};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid};
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use serde::de::DeserializeOwned;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{
    notification_deliveries, notification_event_logs, notification_preferences,
    notification_requests,
};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`NotificationRepository`].
pub struct PgNotificationRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgNotificationRepository<'c> {
    /// Create a new [`PgNotificationRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = notification_requests)]
struct NotificationRequestRow {
    id: Uuid,
    template_key: String,
    locale: String,
    source: serde_json::Value,
    payload: serde_json::Value,
    status: String,
    dedupe_key: Option<String>,
    correlation_key: Option<String>,
    created_at: DateTime<Utc>,
    scheduled_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    cancelled_at: Option<DateTime<Utc>>,
}

impl TryFrom<NotificationRequestRow> for NotificationRequest {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: NotificationRequestRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(NotificationRequest {
            id,
            template_key: value.template_key,
            locale: value.locale,
            source: deserialize_json("notification_requests", "source", id, value.source)?,
            payload: value.payload,
            status: parse_request_status(&value.status, id)?,
            dedupe_key: value.dedupe_key,
            correlation_key: value.correlation_key,
            created_at: value.created_at,
            scheduled_at: value.scheduled_at,
            started_at: value.started_at,
            completed_at: value.completed_at,
            cancelled_at: value.cancelled_at,
        })
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = notification_deliveries)]
struct NotificationDeliveryRow {
    id: Uuid,
    notification_request_id: Uuid,
    channel: String,
    destination: serde_json::Value,
    provider_binding_key: Option<String>,
    provider_message_id: Option<String>,
    attempt_count: i32,
    status: String,
    last_failure: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    reserved_at: Option<DateTime<Utc>>,
    sent_at: Option<DateTime<Utc>>,
    delivered_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    next_retry_at: Option<DateTime<Utc>>,
}

impl TryFrom<NotificationDeliveryRow> for NotificationDelivery {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: NotificationDeliveryRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(NotificationDelivery {
            id,
            notification_request_id: value.notification_request_id.into(),
            channel: parse_channel(&value.channel, id)?,
            destination: deserialize_json(
                "notification_deliveries",
                "destination",
                id,
                value.destination,
            )?,
            provider_binding_key: value.provider_binding_key,
            provider_message_id: value.provider_message_id,
            attempt_count: value.attempt_count.try_into().map_err(|e| {
                DatabaseInconsistencyError::on("notification_deliveries")
                    .column("attempt_count")
                    .row(id)
                    .source(e)
            })?,
            status: parse_delivery_status(&value.status, id)?,
            last_failure: value
                .last_failure
                .map(|failure| {
                    deserialize_json("notification_deliveries", "last_failure", id, failure)
                })
                .transpose()?,
            created_at: value.created_at,
            reserved_at: value.reserved_at,
            sent_at: value.sent_at,
            delivered_at: value.delivered_at,
            failed_at: value.failed_at,
            next_retry_at: value.next_retry_at,
        })
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = notification_event_logs)]
struct NotificationEventLogRow {
    id: Uuid,
    notification_request_id: Uuid,
    notification_delivery_id: Option<Uuid>,
    kind: String,
    actor: serde_json::Value,
    summary: Option<String>,
    metadata: serde_json::Value,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = notification_preferences)]
struct NotificationPreferenceRow {
    id: Uuid,
    user_id: Uuid,
    channel: String,
    enabled: bool,
    updated_at: DateTime<Utc>,
}

impl TryFrom<NotificationPreferenceRow> for NotificationPreference {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: NotificationPreferenceRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(Self {
            id,
            user_id: value.user_id.into(),
            channel: parse_channel(&value.channel, id)?,
            enabled: value.enabled,
            updated_at: value.updated_at,
        })
    }
}

impl TryFrom<NotificationEventLogRow> for NotificationEventLog {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: NotificationEventLogRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(NotificationEventLog {
            id,
            notification_request_id: value.notification_request_id.into(),
            notification_delivery_id: value.notification_delivery_id.map(Into::into),
            kind: parse_event_kind(&value.kind, id)?,
            actor: deserialize_json("notification_event_logs", "actor", id, value.actor)?,
            summary: value.summary,
            metadata: value.metadata,
            occurred_at: value.occurred_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = notification_requests)]
struct NewNotificationRequestRow {
    id: Uuid,
    template_key: String,
    locale: String,
    source: serde_json::Value,
    payload: serde_json::Value,
    status: String,
    dedupe_key: Option<String>,
    correlation_key: Option<String>,
    created_at: DateTime<Utc>,
    scheduled_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    cancelled_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = notification_deliveries)]
struct NewNotificationDeliveryRow {
    id: Uuid,
    notification_request_id: Uuid,
    channel: String,
    destination: serde_json::Value,
    provider_binding_key: Option<String>,
    provider_message_id: Option<String>,
    attempt_count: i32,
    status: String,
    last_failure: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    reserved_at: Option<DateTime<Utc>>,
    sent_at: Option<DateTime<Utc>>,
    delivered_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    next_retry_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = notification_event_logs)]
struct NewNotificationEventLogRow {
    id: Uuid,
    notification_request_id: Uuid,
    notification_delivery_id: Option<Uuid>,
    kind: String,
    actor: serde_json::Value,
    summary: Option<String>,
    metadata: serde_json::Value,
    occurred_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = notification_preferences)]
struct NewNotificationPreferenceRow {
    id: Uuid,
    user_id: Uuid,
    channel: String,
    enabled: bool,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, QueryableByName)]
struct ReservedDeliveryRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = DieselUuid)]
    notification_request_id: Uuid,
    #[diesel(sql_type = Text)]
    channel: String,
    #[diesel(sql_type = Jsonb)]
    destination: serde_json::Value,
    #[diesel(sql_type = Nullable<Text>)]
    provider_binding_key: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    provider_message_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    attempt_count: i32,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    last_failure: Option<serde_json::Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    reserved_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    sent_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    delivered_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    failed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    next_retry_at: Option<DateTime<Utc>>,
}

impl TryFrom<ReservedDeliveryRow> for NotificationDelivery {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: ReservedDeliveryRow) -> Result<Self, Self::Error> {
        NotificationDeliveryRow {
            id: value.id,
            notification_request_id: value.notification_request_id,
            channel: value.channel,
            destination: value.destination,
            provider_binding_key: value.provider_binding_key,
            provider_message_id: value.provider_message_id,
            attempt_count: value.attempt_count,
            status: value.status,
            last_failure: value.last_failure,
            created_at: value.created_at,
            reserved_at: value.reserved_at,
            sent_at: value.sent_at,
            delivered_at: value.delivered_at,
            failed_at: value.failed_at,
            next_retry_at: value.next_retry_at,
        }
        .try_into()
    }
}

#[async_trait]
impl NotificationRepository for PgNotificationRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.notification.lookup_request",
        skip_all,
        fields(notification_request.id = %id),
        err,
    )]
    async fn lookup_request(
        &mut self,
        id: Ulid,
    ) -> Result<Option<NotificationRequest>, Self::Error> {
        let request = notification_requests::table
            .find(Uuid::from(id))
            .select(NotificationRequestRow::as_select())
            .first::<NotificationRequestRow>(self.conn)
            .await
            .optional()?;

        request
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.add_request",
        skip_all,
        fields(
            notification_request.id,
            notification_request.template_key = params.template_key(),
        ),
        err,
    )]
    async fn add_request(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewNotificationRequest,
    ) -> Result<NotificationRequest, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("notification_request.id", tracing::field::display(id));

        let scheduled_at = params.scheduled_at().unwrap_or(created_at);
        let source =
            serde_json::to_value(params.source()).map_err(DatabaseError::to_invalid_operation)?;

        let row = NewNotificationRequestRow {
            id: Uuid::from(id),
            template_key: params.template_key().to_owned(),
            locale: params.locale().to_owned(),
            source,
            payload: params.payload().clone(),
            status: request_status_to_db(NotificationRequestStatus::Pending).to_owned(),
            dedupe_key: params.dedupe_key().map(ToOwned::to_owned),
            correlation_key: params.correlation_key().map(ToOwned::to_owned),
            created_at,
            scheduled_at,
            started_at: None,
            completed_at: None,
            cancelled_at: None,
        };

        diesel::insert_into(notification_requests::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(NotificationRequest {
            id,
            template_key: row.template_key,
            locale: row.locale,
            source: params.source().clone(),
            payload: row.payload,
            status: NotificationRequestStatus::Pending,
            dedupe_key: row.dedupe_key,
            correlation_key: row.correlation_key,
            created_at,
            scheduled_at,
            started_at: None,
            completed_at: None,
            cancelled_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.notification.set_request_status",
        skip_all,
        fields(
            notification_request.id = %notification_request.id,
            notification_request.status = ?status,
        ),
        err,
    )]
    async fn set_request_status(
        &mut self,
        clock: &dyn Clock,
        mut notification_request: NotificationRequest,
        status: NotificationRequestStatus,
    ) -> Result<NotificationRequest, Self::Error> {
        let now = clock.now();

        notification_request.status = status;
        match status {
            NotificationRequestStatus::Pending => {
                notification_request.started_at = None;
                notification_request.completed_at = None;
                notification_request.cancelled_at = None;
            }
            NotificationRequestStatus::Processing => {
                notification_request.started_at.get_or_insert(now);
                notification_request.completed_at = None;
                notification_request.cancelled_at = None;
            }
            NotificationRequestStatus::Succeeded => {
                notification_request.started_at.get_or_insert(now);
                notification_request.completed_at = Some(now);
                notification_request.cancelled_at = None;
            }
            NotificationRequestStatus::Failed => {
                notification_request.started_at.get_or_insert(now);
                notification_request.completed_at = None;
                notification_request.cancelled_at = None;
            }
            NotificationRequestStatus::Cancelled => {
                notification_request.cancelled_at = Some(now);
            }
        }

        let rows_affected = diesel::update(
            notification_requests::table
                .filter(notification_requests::id.eq(Uuid::from(notification_request.id))),
        )
        .set((
            notification_requests::status.eq(request_status_to_db(notification_request.status)),
            notification_requests::started_at.eq(notification_request.started_at),
            notification_requests::completed_at.eq(notification_request.completed_at),
            notification_requests::cancelled_at.eq(notification_request.cancelled_at),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(notification_request)
    }

    #[tracing::instrument(
        name = "db.notification.lookup_delivery",
        skip_all,
        fields(notification_delivery.id = %id),
        err,
    )]
    async fn lookup_delivery(
        &mut self,
        id: Ulid,
    ) -> Result<Option<NotificationDelivery>, Self::Error> {
        let delivery = notification_deliveries::table
            .find(Uuid::from(id))
            .select(NotificationDeliveryRow::as_select())
            .first::<NotificationDeliveryRow>(self.conn)
            .await
            .optional()?;

        delivery
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.lookup_delivery_by_provider_message_id",
        skip_all,
        fields(provider_binding_key, provider_message_id),
        err
    )]
    async fn lookup_delivery_by_provider_message_id(
        &mut self,
        provider_binding_key: &str,
        provider_message_id: &str,
    ) -> Result<Option<NotificationDelivery>, Self::Error> {
        use crate::schema::notification_deliveries::dsl;

        dsl::notification_deliveries
            .filter(dsl::provider_binding_key.eq(provider_binding_key))
            .filter(dsl::provider_message_id.eq(provider_message_id))
            .first::<NotificationDeliveryRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.list_deliveries",
        skip_all,
        fields(notification_request.id = %notification_request.id),
        err,
    )]
    async fn list_deliveries(
        &mut self,
        notification_request: &NotificationRequest,
    ) -> Result<Vec<NotificationDelivery>, Self::Error> {
        notification_deliveries::table
            .filter(
                notification_deliveries::notification_request_id
                    .eq(Uuid::from(notification_request.id)),
            )
            .order(notification_deliveries::id.asc())
            .select(NotificationDeliveryRow::as_select())
            .load::<NotificationDeliveryRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.add_delivery",
        skip_all,
        fields(
            notification_request.id = %notification_request.id,
            notification_delivery.id,
            notification_delivery.channel = ?params.channel(),
        ),
        err,
    )]
    async fn add_delivery(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        notification_request: &NotificationRequest,
        params: NewNotificationDelivery,
    ) -> Result<NotificationDelivery, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("notification_delivery.id", tracing::field::display(id));

        let row = NewNotificationDeliveryRow {
            id: Uuid::from(id),
            notification_request_id: Uuid::from(notification_request.id),
            channel: channel_to_db(params.channel()).to_owned(),
            destination: serde_json::to_value(params.destination())
                .map_err(DatabaseError::to_invalid_operation)?,
            provider_binding_key: params.provider_binding_key().map(ToOwned::to_owned),
            provider_message_id: None,
            attempt_count: 0,
            status: delivery_status_to_db(NotificationDeliveryStatus::Pending).to_owned(),
            last_failure: None,
            created_at,
            reserved_at: None,
            sent_at: None,
            delivered_at: None,
            failed_at: None,
            next_retry_at: None,
        };

        diesel::insert_into(notification_deliveries::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(NotificationDelivery {
            id,
            notification_request_id: notification_request.id,
            channel: params.channel(),
            destination: params.destination().clone(),
            provider_binding_key: row.provider_binding_key,
            provider_message_id: None,
            attempt_count: 0,
            status: NotificationDeliveryStatus::Pending,
            last_failure: None,
            created_at,
            reserved_at: None,
            sent_at: None,
            delivered_at: None,
            failed_at: None,
            next_retry_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.notification.reserve_deliveries",
        skip_all,
        fields(limit = limit),
        err,
    )]
    async fn reserve_deliveries(
        &mut self,
        clock: &dyn Clock,
        limit: usize,
    ) -> Result<Vec<NotificationDelivery>, Self::Error> {
        let now = clock.now();
        let max_count = i64::try_from(limit).unwrap_or(i64::MAX);

        let rows: Vec<ReservedDeliveryRow> = diesel::sql_query(
            r"
                WITH locked_deliveries AS (
                    SELECT id
                    FROM notification_deliveries
                    WHERE status = 'pending'
                       OR (
                            status = 'failed'
                            AND next_retry_at IS NOT NULL
                            AND next_retry_at <= $1
                       )
                    ORDER BY COALESCE(next_retry_at, created_at), id
                    LIMIT $2
                    FOR UPDATE
                    SKIP LOCKED
                )
                UPDATE notification_deliveries
                SET status = 'reserved',
                    reserved_at = $1,
                    attempt_count = notification_deliveries.attempt_count + 1
                FROM locked_deliveries
                WHERE notification_deliveries.id = locked_deliveries.id
                RETURNING
                    notification_deliveries.id,
                    notification_deliveries.notification_request_id,
                    notification_deliveries.channel,
                    notification_deliveries.destination,
                    notification_deliveries.provider_binding_key,
                    notification_deliveries.provider_message_id,
                    notification_deliveries.attempt_count,
                    notification_deliveries.status,
                    notification_deliveries.last_failure,
                    notification_deliveries.created_at,
                    notification_deliveries.reserved_at,
                    notification_deliveries.sent_at,
                    notification_deliveries.delivered_at,
                    notification_deliveries.failed_at,
                    notification_deliveries.next_retry_at
            ",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<BigInt, _>(max_count)
        .get_results(self.conn)
        .await?;

        rows.into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.mark_delivery_sending",
        skip_all,
        fields(notification_delivery.id = %notification_delivery.id),
        err,
    )]
    async fn mark_delivery_sending(
        &mut self,
        clock: &dyn Clock,
        mut notification_delivery: NotificationDelivery,
        provider_message_id: Option<String>,
    ) -> Result<NotificationDelivery, Self::Error> {
        let now = clock.now();
        notification_delivery.status = NotificationDeliveryStatus::Sending;
        notification_delivery.sent_at.get_or_insert(now);
        notification_delivery.provider_message_id =
            provider_message_id.or(notification_delivery.provider_message_id.take());
        notification_delivery.last_failure = None;
        notification_delivery.failed_at = None;
        notification_delivery.next_retry_at = None;

        persist_delivery(self.conn, &notification_delivery).await?;

        Ok(notification_delivery)
    }

    #[tracing::instrument(
        name = "db.notification.mark_delivery_delivered",
        skip_all,
        fields(notification_delivery.id = %notification_delivery.id),
        err,
    )]
    async fn mark_delivery_delivered(
        &mut self,
        clock: &dyn Clock,
        mut notification_delivery: NotificationDelivery,
        provider_message_id: Option<String>,
    ) -> Result<NotificationDelivery, Self::Error> {
        let now = clock.now();
        notification_delivery.status = NotificationDeliveryStatus::Delivered;
        notification_delivery.sent_at.get_or_insert(now);
        notification_delivery.delivered_at = Some(now);
        notification_delivery.failed_at = None;
        notification_delivery.next_retry_at = None;
        notification_delivery.last_failure = None;
        notification_delivery.provider_message_id =
            provider_message_id.or(notification_delivery.provider_message_id.take());

        persist_delivery(self.conn, &notification_delivery).await?;

        Ok(notification_delivery)
    }

    #[tracing::instrument(
        name = "db.notification.mark_delivery_failed",
        skip_all,
        fields(notification_delivery.id = %notification_delivery.id),
        err,
    )]
    async fn mark_delivery_failed(
        &mut self,
        clock: &dyn Clock,
        mut notification_delivery: NotificationDelivery,
        failure: NotificationDeliveryFailure,
        provider_message_id: Option<String>,
        next_retry_at: Option<DateTime<Utc>>,
    ) -> Result<NotificationDelivery, Self::Error> {
        let now = clock.now();
        notification_delivery.status = NotificationDeliveryStatus::Failed;
        notification_delivery.delivered_at = None;
        notification_delivery.failed_at = Some(now);
        notification_delivery.last_failure = Some(failure);
        notification_delivery.next_retry_at = next_retry_at;
        notification_delivery.provider_message_id =
            provider_message_id.or(notification_delivery.provider_message_id.take());

        persist_delivery(self.conn, &notification_delivery).await?;

        Ok(notification_delivery)
    }

    #[tracing::instrument(
        name = "db.notification.cancel_delivery",
        skip_all,
        fields(notification_delivery.id = %notification_delivery.id),
        err,
    )]
    async fn cancel_delivery(
        &mut self,
        clock: &dyn Clock,
        mut notification_delivery: NotificationDelivery,
    ) -> Result<NotificationDelivery, Self::Error> {
        notification_delivery.status = NotificationDeliveryStatus::Cancelled;
        notification_delivery.failed_at = Some(clock.now());
        notification_delivery.next_retry_at = None;

        persist_delivery(self.conn, &notification_delivery).await?;

        Ok(notification_delivery)
    }

    #[tracing::instrument(
        name = "db.notification.append_event",
        skip_all,
        fields(
            notification_request.id = %notification_request.id,
            notification_event.kind = ?params.kind(),
        ),
        err,
    )]
    async fn append_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        notification_request: &NotificationRequest,
        notification_delivery: Option<&NotificationDelivery>,
        params: NewNotificationEventLog,
    ) -> Result<NotificationEventLog, Self::Error> {
        let occurred_at = clock.now();
        let id = new_id(occurred_at, rng);

        let row = NewNotificationEventLogRow {
            id: Uuid::from(id),
            notification_request_id: Uuid::from(notification_request.id),
            notification_delivery_id: notification_delivery.map(|delivery| Uuid::from(delivery.id)),
            kind: event_kind_to_db(params.kind()).to_owned(),
            actor: serde_json::to_value(params.actor())
                .map_err(DatabaseError::to_invalid_operation)?,
            summary: params.summary().map(ToOwned::to_owned),
            metadata: params.metadata().clone(),
            occurred_at,
        };

        diesel::insert_into(notification_event_logs::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(NotificationEventLog {
            id,
            notification_request_id: notification_request.id,
            notification_delivery_id: notification_delivery.map(|delivery| delivery.id),
            kind: params.kind(),
            actor: params.actor().clone(),
            summary: row.summary,
            metadata: row.metadata,
            occurred_at,
        })
    }

    #[tracing::instrument(
        name = "db.notification.list_events",
        skip_all,
        fields(notification_request.id = %notification_request.id),
        err,
    )]
    async fn list_events(
        &mut self,
        notification_request: &NotificationRequest,
    ) -> Result<Vec<NotificationEventLog>, Self::Error> {
        notification_event_logs::table
            .filter(
                notification_event_logs::notification_request_id
                    .eq(Uuid::from(notification_request.id)),
            )
            .order((
                notification_event_logs::occurred_at.asc(),
                notification_event_logs::id.asc(),
            ))
            .select(NotificationEventLogRow::as_select())
            .load::<NotificationEventLogRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.list_preferences",
        skip_all,
        fields(user.id = %user.id),
        err,
    )]
    async fn list_preferences(
        &mut self,
        user: &User,
    ) -> Result<Vec<NotificationPreference>, Self::Error> {
        notification_preferences::table
            .filter(notification_preferences::user_id.eq(Uuid::from(user.id)))
            .order(notification_preferences::channel.asc())
            .select(NotificationPreferenceRow::as_select())
            .load::<NotificationPreferenceRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.notification.replace_preferences",
        skip_all,
        fields(user.id = %user.id),
        err,
    )]
    async fn replace_preferences(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        preferences: Vec<(NotificationChannel, bool)>,
    ) -> Result<Vec<NotificationPreference>, Self::Error> {
        diesel::delete(
            notification_preferences::table
                .filter(notification_preferences::user_id.eq(Uuid::from(user.id))),
        )
        .execute(self.conn)
        .await?;

        let updated_at = clock.now();
        let rows: Vec<NewNotificationPreferenceRow> = preferences
            .into_iter()
            .map(|(channel, enabled)| NewNotificationPreferenceRow {
                id: Uuid::from(new_id(updated_at, rng)),
                user_id: Uuid::from(user.id),
                channel: channel_to_db(channel).to_owned(),
                enabled,
                updated_at,
            })
            .collect();

        if !rows.is_empty() {
            diesel::insert_into(notification_preferences::table)
                .values(&rows)
                .execute(self.conn)
                .await?;
        }

        rows.into_iter()
            .map(|row| {
                NotificationPreferenceRow {
                    id: row.id,
                    user_id: row.user_id,
                    channel: row.channel,
                    enabled: row.enabled,
                    updated_at: row.updated_at,
                }
                .try_into()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

async fn persist_delivery(
    conn: &mut diesel_async::AsyncPgConnection,
    notification_delivery: &NotificationDelivery,
) -> Result<(), DatabaseError> {
    let rows_affected = diesel::update(
        notification_deliveries::table
            .filter(notification_deliveries::id.eq(Uuid::from(notification_delivery.id))),
    )
    .set((
        notification_deliveries::provider_message_id
            .eq(notification_delivery.provider_message_id.as_deref()),
        notification_deliveries::status.eq(delivery_status_to_db(notification_delivery.status)),
        notification_deliveries::last_failure.eq(notification_delivery
            .last_failure
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?),
        notification_deliveries::reserved_at.eq(notification_delivery.reserved_at),
        notification_deliveries::sent_at.eq(notification_delivery.sent_at),
        notification_deliveries::delivered_at.eq(notification_delivery.delivered_at),
        notification_deliveries::failed_at.eq(notification_delivery.failed_at),
        notification_deliveries::next_retry_at.eq(notification_delivery.next_retry_at),
    ))
    .execute(conn)
    .await?;

    DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

    Ok(())
}

const fn request_status_to_db(status: NotificationRequestStatus) -> &'static str {
    match status {
        NotificationRequestStatus::Pending => "pending",
        NotificationRequestStatus::Processing => "processing",
        NotificationRequestStatus::Succeeded => "succeeded",
        NotificationRequestStatus::Failed => "failed",
        NotificationRequestStatus::Cancelled => "cancelled",
    }
}

const fn delivery_status_to_db(status: NotificationDeliveryStatus) -> &'static str {
    match status {
        NotificationDeliveryStatus::Pending => "pending",
        NotificationDeliveryStatus::Reserved => "reserved",
        NotificationDeliveryStatus::Sending => "sending",
        NotificationDeliveryStatus::Delivered => "delivered",
        NotificationDeliveryStatus::Failed => "failed",
        NotificationDeliveryStatus::Cancelled => "cancelled",
    }
}

const fn channel_to_db(channel: NotificationChannel) -> &'static str {
    match channel {
        NotificationChannel::Email => "email",
        NotificationChannel::Sms => "sms",
        NotificationChannel::Webhook => "webhook",
        NotificationChannel::InApp => "in_app",
    }
}

const fn event_kind_to_db(kind: NotificationEventKind) -> &'static str {
    match kind {
        NotificationEventKind::RequestCreated => "request_created",
        NotificationEventKind::RequestScheduled => "request_scheduled",
        NotificationEventKind::DeliveryQueued => "delivery_queued",
        NotificationEventKind::DeliveryReserved => "delivery_reserved",
        NotificationEventKind::DeliverySendStarted => "delivery_send_started",
        NotificationEventKind::DeliveryAccepted => "delivery_accepted",
        NotificationEventKind::DeliveryDelivered => "delivery_delivered",
        NotificationEventKind::DeliveryFailed => "delivery_failed",
        NotificationEventKind::DeliveryRetried => "delivery_retried",
        NotificationEventKind::RequestCompleted => "request_completed",
        NotificationEventKind::RequestFailed => "request_failed",
        NotificationEventKind::RequestCancelled => "request_cancelled",
    }
}

fn parse_request_status(
    value: &str,
    row: Ulid,
) -> Result<NotificationRequestStatus, DatabaseInconsistencyError> {
    match value {
        "pending" => Ok(NotificationRequestStatus::Pending),
        "processing" => Ok(NotificationRequestStatus::Processing),
        "succeeded" => Ok(NotificationRequestStatus::Succeeded),
        "failed" => Ok(NotificationRequestStatus::Failed),
        "cancelled" => Ok(NotificationRequestStatus::Cancelled),
        _ => Err(DatabaseInconsistencyError::on("notification_requests")
            .column("status")
            .row(row)),
    }
}

fn parse_delivery_status(
    value: &str,
    row: Ulid,
) -> Result<NotificationDeliveryStatus, DatabaseInconsistencyError> {
    match value {
        "pending" => Ok(NotificationDeliveryStatus::Pending),
        "reserved" => Ok(NotificationDeliveryStatus::Reserved),
        "sending" => Ok(NotificationDeliveryStatus::Sending),
        "delivered" => Ok(NotificationDeliveryStatus::Delivered),
        "failed" => Ok(NotificationDeliveryStatus::Failed),
        "cancelled" => Ok(NotificationDeliveryStatus::Cancelled),
        _ => Err(DatabaseInconsistencyError::on("notification_deliveries")
            .column("status")
            .row(row)),
    }
}

fn parse_channel(
    value: &str,
    row: Ulid,
) -> Result<NotificationChannel, DatabaseInconsistencyError> {
    match value {
        "email" => Ok(NotificationChannel::Email),
        "sms" => Ok(NotificationChannel::Sms),
        "webhook" => Ok(NotificationChannel::Webhook),
        "in_app" => Ok(NotificationChannel::InApp),
        _ => Err(DatabaseInconsistencyError::on("notification_deliveries")
            .column("channel")
            .row(row)),
    }
}

fn parse_event_kind(
    value: &str,
    row: Ulid,
) -> Result<NotificationEventKind, DatabaseInconsistencyError> {
    match value {
        "request_created" => Ok(NotificationEventKind::RequestCreated),
        "request_scheduled" => Ok(NotificationEventKind::RequestScheduled),
        "delivery_queued" => Ok(NotificationEventKind::DeliveryQueued),
        "delivery_reserved" => Ok(NotificationEventKind::DeliveryReserved),
        "delivery_send_started" | "delivery_sending" => {
            Ok(NotificationEventKind::DeliverySendStarted)
        }
        "delivery_accepted" => Ok(NotificationEventKind::DeliveryAccepted),
        "delivery_delivered" => Ok(NotificationEventKind::DeliveryDelivered),
        "delivery_failed" => Ok(NotificationEventKind::DeliveryFailed),
        "delivery_retried" => Ok(NotificationEventKind::DeliveryRetried),
        "request_completed" => Ok(NotificationEventKind::RequestCompleted),
        "request_failed" => Ok(NotificationEventKind::RequestFailed),
        "request_cancelled" => Ok(NotificationEventKind::RequestCancelled),
        _ => Err(DatabaseInconsistencyError::on("notification_event_logs")
            .column("kind")
            .row(row)),
    }
}

fn deserialize_json<T>(
    table: &'static str,
    column: &'static str,
    row: Ulid,
    value: serde_json::Value,
) -> Result<T, DatabaseInconsistencyError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|e| {
        DatabaseInconsistencyError::on(table)
            .column(column)
            .row(row)
            .source(e)
    })
}
