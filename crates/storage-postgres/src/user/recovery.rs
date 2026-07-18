use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::user::UserRecoveryRepository;
use coauth_data::{Clock, UserEmail, UserRecoverySession, UserRecoveryTicket, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use rand_core::RngCore;
use subtle::ConstantTimeEq as _;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::{user_recovery_sessions, user_recovery_tickets};

/// An implementation of [`UserRecoveryRepository`] for a PostgreSQL connection
pub struct PgUserRecoveryRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserRecoveryRepository<'c> {
    /// Create a new [`PgUserRecoveryRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_recovery_sessions)]
struct UserRecoverySessionRow {
    id: Uuid,
    email: String,
    user_agent: String,
    ip_address: Option<IpNetwork>,
    locale: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

impl From<UserRecoverySessionRow> for UserRecoverySession {
    fn from(row: UserRecoverySessionRow) -> Self {
        UserRecoverySession {
            id: row.id.into(),
            email: row.email,
            user_agent: row.user_agent,
            ip_address: row.ip_address.map(|ip| ip.ip()),
            locale: row.locale,
            created_at: row.created_at,
            consumed_at: row.consumed_at,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_recovery_tickets)]
struct UserRecoveryTicketRow {
    id: Uuid,
    user_recovery_session_id: Uuid,
    user_email_id: Uuid,
    ticket: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<UserRecoveryTicketRow> for UserRecoveryTicket {
    fn from(row: UserRecoveryTicketRow) -> Self {
        Self {
            id: row.id.into(),
            user_recovery_session_id: row.user_recovery_session_id.into(),
            user_email_id: row.user_email_id.into(),
            ticket: row.ticket,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

/// Insertable row for creating a new recovery session
#[derive(Insertable)]
#[diesel(table_name = user_recovery_sessions)]
struct NewUserRecoverySession {
    id: Uuid,
    email: String,
    user_agent: String,
    ip_address: Option<IpNetwork>,
    locale: String,
    created_at: DateTime<Utc>,
}

/// Insertable row for creating a new recovery ticket
#[derive(Insertable)]
#[diesel(table_name = user_recovery_tickets)]
struct NewUserRecoveryTicket {
    id: Uuid,
    user_recovery_session_id: Uuid,
    user_email_id: Uuid,
    ticket: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Helper struct for extracting UUID from raw SQL RETURNING clause
#[derive(QueryableByName)]
struct UuidRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}

#[async_trait]
impl UserRecoveryRepository for PgUserRecoveryRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_recovery.lookup_session",
        skip_all,
        fields(
            user_recovery_session.id = %id,
        ),
        err,
    )]
    async fn lookup_session(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserRecoverySession>, Self::Error> {
        let row = user_recovery_sessions::table
            .find(Uuid::from(id))
            .select(UserRecoverySessionRow::as_select())
            .first::<UserRecoverySessionRow>(self.conn)
            .await
            .optional()?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(row.into()))
    }

    #[tracing::instrument(
        name = "db.user_recovery.add_session",
        skip_all,
        fields(
            user_recovery_session.id,
            user_recovery_session.email = email,
            user_recovery_session.user_agent = user_agent,
            user_recovery_session.ip_address = ip_address.map(|ip| ip.to_string()),
        )
    )]
    async fn add_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        user_agent: String,
        ip_address: Option<IpAddr>,
        locale: String,
    ) -> Result<UserRecoverySession, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_recovery_session.id", tracing::field::display(id));

        let new_session = NewUserRecoverySession {
            id: Uuid::from(id),
            email: email.clone(),
            user_agent: user_agent.clone(),
            ip_address: ip_address.map(IpNetwork::from),
            locale: locale.clone(),
            created_at,
        };

        diesel::insert_into(user_recovery_sessions::table)
            .values(&new_session)
            .execute(self.conn)
            .await?;

        let user_recovery_session = UserRecoverySession {
            id,
            email,
            user_agent,
            ip_address,
            locale,
            created_at,
            consumed_at: None,
        };

        Ok(user_recovery_session)
    }

    #[tracing::instrument(
        name = "db.user_recovery.find_ticket",
        skip_all,
        fields(
            user_recovery_ticket.id = ticket,
        ),
        err,
    )]
    async fn find_ticket(
        &mut self,
        ticket: &str,
    ) -> Result<Option<UserRecoveryTicket>, Self::Error> {
        // The ticket secret is deliberately NOT part of the SQL `WHERE` clause:
        // a DB equality filter on the secret leaks a timing side channel.
        // Instead we fetch the candidate tickets bound to still-open recovery
        // sessions (`consumed_at IS NULL`) and compare each ticket value in
        // constant time. The candidate set is naturally tiny: tickets are
        // short-lived and a session can only ever be consumed once, so already
        // used sessions are excluded here. Expiry is enforced separately by the
        // caller via `UserRecoveryTicket::active`.
        let candidates =
            user_recovery_tickets::table
                .inner_join(user_recovery_sessions::table.on(
                    user_recovery_tickets::user_recovery_session_id.eq(user_recovery_sessions::id),
                ))
                .filter(user_recovery_sessions::consumed_at.is_null())
                .select(UserRecoveryTicketRow::as_select())
                .load::<UserRecoveryTicketRow>(self.conn)
                .await?;

        let needle = ticket.as_bytes();
        let mut matched: Option<UserRecoveryTicket> = None;
        for row in candidates {
            let candidate = UserRecoveryTicket::from(row);
            let is_match: bool = candidate.ticket.as_bytes().ct_eq(needle).into();
            if is_match {
                matched = Some(candidate);
            }
        }

        Ok(matched)
    }

    #[tracing::instrument(
        name = "db.user_recovery.add_ticket",
        skip_all,
        fields(
            user_recovery_ticket.id,
            user_recovery_ticket.id = ticket,
            %user_recovery_session.id,
            %user_email.id,
        )
    )]
    async fn add_ticket(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_recovery_session: &UserRecoverySession,
        user_email: &UserEmail,
        ticket: String,
    ) -> Result<UserRecoveryTicket, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_recovery_ticket.id", tracing::field::display(id));

        // TODO: move that to a parameter
        let expires_at = created_at + Duration::minutes(10);

        let new_ticket = NewUserRecoveryTicket {
            id: Uuid::from(id),
            user_recovery_session_id: Uuid::from(user_recovery_session.id),
            user_email_id: Uuid::from(user_email.id),
            ticket: ticket.clone(),
            created_at,
            expires_at,
        };

        diesel::insert_into(user_recovery_tickets::table)
            .values(&new_ticket)
            .execute(self.conn)
            .await?;

        let ticket = UserRecoveryTicket {
            id,
            user_recovery_session_id: user_recovery_session.id,
            user_email_id: user_email.id,
            ticket,
            created_at,
            expires_at,
        };

        Ok(ticket)
    }

    #[tracing::instrument(
        name = "db.user_recovery.consume_ticket",
        skip_all,
        fields(
            %user_recovery_ticket.id,
            user_email.id = %user_recovery_ticket.user_email_id,
            %user_recovery_session.id,
            %user_recovery_session.email,
        ),
        err,
    )]
    async fn consume_ticket(
        &mut self,
        clock: &dyn Clock,
        user_recovery_ticket: UserRecoveryTicket,
        mut user_recovery_session: UserRecoverySession,
    ) -> Result<UserRecoverySession, Self::Error> {
        // We don't really use the ticket, we just want to make sure we drop it
        let _ = user_recovery_ticket;

        let consumed_at = clock.now();

        let rows_affected = diesel::update(
            user_recovery_sessions::table
                .filter(user_recovery_sessions::id.eq(Uuid::from(user_recovery_session.id)))
                .filter(user_recovery_sessions::consumed_at.is_null()),
        )
        .set(user_recovery_sessions::consumed_at.eq(Some(consumed_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_recovery_session.consumed_at = Some(consumed_at);

        Ok(user_recovery_session)
    }

    #[tracing::instrument(
        name = "db.user_recovery.cleanup",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error> {
        // Use ULID cursor-based pagination. Since ULIDs contain a timestamp,
        // we can efficiently delete old sessions without needing an index.
        // `MAX(uuid)` isn't a thing in Postgres, so we aggregate on the client side.
        let res: Vec<Uuid> = diesel::sql_query(
            r"
                WITH to_delete AS (
                    SELECT id
                    FROM user_recovery_sessions
                    WHERE ($1::uuid IS NULL OR id > $1)
                    AND id <= $2
                    ORDER BY id
                    LIMIT $3
                )
                DELETE FROM user_recovery_sessions
                USING to_delete
                WHERE user_recovery_sessions.id = to_delete.id
                RETURNING user_recovery_sessions.id
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(since.map(Uuid::from))
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(until))
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<UuidRow>(self.conn)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();

        let count = res.len();
        let max_id = res.into_iter().max();

        Ok((count, max_id.map(Ulid::from)))
    }
}
