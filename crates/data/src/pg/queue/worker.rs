//! A module containing the PostgreSQL implementation of the
//! [`QueueWorkerRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use diesel::{
    prelude::*,
    sql_types::{Nullable, Timestamptz, Uuid as DieselUuid},
};
use diesel_async::RunQueryDsl;
use coauth_data::{
    Clock, new_id,
    queue::{QueueWorkerRepository, ShutdownWorker, Worker},
};
use rand_core::RngCore;
use uuid::Uuid;

use crate::{
    DatabaseError,
    schema::{queue_leader, queue_workers},
};

/// An implementation of [`QueueWorkerRepository`] for a PostgreSQL connection.
pub struct PgQueueWorkerRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgQueueWorkerRepository<'c> {
    /// Create a new [`PgQueueWorkerRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Insertable row for registering a new worker.
#[derive(Insertable)]
#[diesel(table_name = queue_workers)]
struct NewWorker {
    id: Uuid,
    registered_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

#[derive(Debug, QueryableByName)]
struct WorkerStateRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    registered_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    last_seen_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    shutdown_at: Option<DateTime<Utc>>,
}

#[derive(Debug, QueryableByName)]
struct ShutdownWorkerRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    last_seen_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    shutdown_at: DateTime<Utc>,
}

impl From<ShutdownWorkerRow> for ShutdownWorker {
    fn from(value: ShutdownWorkerRow) -> Self {
        Self {
            id: value.id.into(),
            last_seen_at: value.last_seen_at,
            shutdown_at: value.shutdown_at,
        }
    }
}

impl<'c> PgQueueWorkerRepository<'c> {
    async fn load_worker_state(
        &mut self,
        worker: &Worker,
    ) -> Result<Option<WorkerStateRow>, DatabaseError> {
        let state = diesel::sql_query(
            r"
                SELECT id, registered_at, last_seen_at, shutdown_at
                FROM queue_workers
                WHERE id = $1
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(worker.id))
        .get_result(self.conn)
        .await
        .optional()?;

        Ok(state)
    }

    async fn log_worker_state(&mut self, worker: &Worker, reason: &str) {
        match self.load_worker_state(worker).await {
            Ok(Some(state)) => {
                let shutdown_at = state
                    .shutdown_at
                    .map(|ts| ts.to_rfc3339())
                    .unwrap_or_else(|| "null".to_owned());
                tracing::error!(
                    worker.id = %worker.id,
                    stored_worker.id = %state.id,
                    worker.registered_at = %state.registered_at,
                    worker.last_seen_at = %state.last_seen_at,
                    worker.shutdown_at = %shutdown_at,
                    "{}", reason
                );
            }

            Ok(None) => {
                tracing::error!(
                    worker.id = %worker.id,
                    "{}; queue_workers row is missing",
                    reason
                );
            }

            Err(error) => {
                tracing::error!(
                    error = &error as &dyn std::error::Error,
                    worker.id = %worker.id,
                    "{}; failed to inspect queue_workers row",
                    reason
                );
            }
        }
    }
}

#[async_trait]
impl QueueWorkerRepository for PgQueueWorkerRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.queue_worker.register",
        skip_all,
        fields(
            worker.id,
        ),
        err,
    )]
    async fn register(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<Worker, Self::Error> {
        let now = clock.now();
        let worker_id = new_id(now, rng);
        tracing::Span::current().record("worker.id", tracing::field::display(worker_id));

        let new_worker = NewWorker {
            id: Uuid::from(worker_id),
            registered_at: now,
            last_seen_at: now,
        };

        diesel::insert_into(queue_workers::table)
            .values(&new_worker)
            .execute(self.conn)
            .await?;

        Ok(Worker { id: worker_id })
    }

    #[tracing::instrument(
        name = "db.queue_worker.heartbeat",
        skip_all,
        fields(
            %worker.id,
        ),
        err,
    )]
    async fn heartbeat(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error> {
        let now = clock.now();
        let rows_affected = diesel::update(
            queue_workers::table
                .filter(queue_workers::id.eq(Uuid::from(worker.id)))
                .filter(queue_workers::shutdown_at.is_null()),
        )
        .set(queue_workers::last_seen_at.eq(now))
        .execute(self.conn)
        .await?;

        if rows_affected != 1 {
            self.log_worker_state(
                worker,
                "Heartbeat failed because the worker row was not updated",
            )
            .await;
        }

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.shutdown",
        skip_all,
        fields(
            %worker.id,
        ),
        err,
    )]
    async fn shutdown(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error> {
        let now = clock.now();
        let rows_affected = diesel::update(
            queue_workers::table.filter(queue_workers::id.eq(Uuid::from(worker.id))),
        )
        .set(queue_workers::shutdown_at.eq(Some(now)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        // Remove the leader lease if we were holding it
        let rows_affected = diesel::delete(
            queue_leader::table.filter(queue_leader::queue_worker_id.eq(Uuid::from(worker.id))),
        )
        .execute(self.conn)
        .await?;

        // If we were holding the leader lease, notify workers
        if rows_affected > 0 {
            diesel::sql_query("NOTIFY queue_leader_stepdown")
                .execute(self.conn)
                .await?;
        }

        Ok(())
    }

    #[tracing::instrument(name = "db.queue_worker.shutdown_dead_workers", skip_all, err)]
    async fn shutdown_dead_workers(
        &mut self,
        clock: &dyn Clock,
        threshold: Duration,
    ) -> Result<Vec<ShutdownWorker>, Self::Error> {
        // Here the threshold is usually set to a few minutes, so we don't need to use
        // the database time, as we can assume worker clocks have less than a minute
        // skew between each other, else other things would break
        let now = clock.now();
        let cutoff = now - threshold;
        let workers = diesel::sql_query(
            r"
                UPDATE queue_workers
                SET shutdown_at = $1
                WHERE shutdown_at IS NULL
                  AND last_seen_at < $2
                RETURNING id, last_seen_at, shutdown_at
            ",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(cutoff)
        .get_results::<ShutdownWorkerRow>(self.conn)
        .await?;

        Ok(workers.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(name = "db.queue_worker.remove_leader_lease_if_expired", skip_all, err)]
    async fn remove_leader_lease_if_expired(
        &mut self,
        _clock: &dyn Clock,
    ) -> Result<(), Self::Error> {
        // `expires_at` is a rare exception where we use the database time, as this
        // would be very sensitive to clock skew between workers
        diesel::sql_query("DELETE FROM queue_leader WHERE expires_at < NOW()")
            .execute(self.conn)
            .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.try_get_leader_lease",
        skip_all,
        fields(
            %worker.id,
        ),
        err,
    )]
    async fn try_get_leader_lease(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
    ) -> Result<bool, Self::Error> {
        let now = clock.now();
        // The queue_leader table is meant to only have a single row, which conflicts on
        // the `active` column.

        // If there is a conflict, we update the `expires_at` column ONLY IF the current
        // leader is ourselves.

        // `expires_at` is a rare exception where we use the database time, as this
        // would be very sensitive to clock skew between workers.
        let rows_affected: usize = match diesel::sql_query(
            r"
                INSERT INTO queue_leader (elected_at, expires_at, queue_worker_id)
                VALUES ($1, NOW() + INTERVAL '5 seconds', $2)
                ON CONFLICT (active)
                DO UPDATE SET expires_at = EXCLUDED.expires_at
                WHERE queue_leader.queue_worker_id = $2
            ",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<DieselUuid, _>(Uuid::from(worker.id))
        .execute(self.conn)
        .await
        {
            Ok(rows_affected) => rows_affected,
            Err(error) => {
                self.log_worker_state(
                    worker,
                    "Leader lease acquisition failed while inspecting worker state",
                )
                .await;
                return Err(error.into());
            }
        };

        // We can then detect whether we are the leader or not by checking how many rows
        // were affected by the upsert
        let am_i_the_leader = rows_affected == 1;

        Ok(am_i_the_leader)
    }
}
