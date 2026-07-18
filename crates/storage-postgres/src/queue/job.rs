//! A module containing the PostgreSQL implementation of the
//! [`QueueJobRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::queue::{AbandonedJob, Job, QueueJobRepository, Worker};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid};
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{queue_jobs, queue_schedules};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`QueueJobRepository`] for a PostgreSQL connection.
pub struct PgQueueJobRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgQueueJobRepository<'c> {
    /// Create a new [`PgQueueJobRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row returned from the reserve query (raw SQL with RETURNING).
#[derive(Debug, QueryableByName)]
struct JobReservationResult {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    queue_name: String,
    #[diesel(sql_type = Jsonb)]
    payload: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    metadata: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    attempt: i32,
}

impl TryFrom<JobReservationResult> for Job {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: JobReservationResult) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let queue_name = value.queue_name;
        let payload = value.payload;

        let metadata = serde_json::from_value(value.metadata).map_err(|e| {
            DatabaseInconsistencyError::on("queue_jobs")
                .column("metadata")
                .row(id)
                .source(e)
        })?;

        let attempt = value.attempt.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("queue_jobs")
                .column("attempt")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            queue_name,
            payload,
            metadata,
            attempt,
        })
    }
}

#[derive(Debug, QueryableByName)]
struct AbandonedJobResult {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    queue_name: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    attempt: i32,
    #[diesel(sql_type = DieselUuid)]
    started_by: Uuid,
    #[diesel(sql_type = Timestamptz)]
    started_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    worker_shutdown_at: DateTime<Utc>,
}

impl TryFrom<AbandonedJobResult> for AbandonedJob {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AbandonedJobResult) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let attempt = value.attempt.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("queue_jobs")
                .column("attempt")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            queue_name: value.queue_name,
            attempt,
            started_by: value.started_by.into(),
            started_at: value.started_at,
            worker_shutdown_at: value.worker_shutdown_at,
        })
    }
}

/// Insertable row for scheduling a new job immediately (status defaults to
/// 'available' via the database).
#[derive(Insertable)]
#[diesel(table_name = queue_jobs)]
struct NewJob {
    id: Uuid,
    queue_name: String,
    payload: serde_json::Value,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

/// Insertable row for scheduling a job at a later time.
#[derive(Insertable)]
#[diesel(table_name = queue_jobs)]
struct NewScheduledJob {
    id: Uuid,
    queue_name: String,
    payload: serde_json::Value,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    scheduled_at: Option<DateTime<Utc>>,
    schedule_name: Option<String>,
    status: String,
}

#[async_trait]
impl QueueJobRepository for PgQueueJobRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.queue_job.schedule",
        fields(
            queue_job.id,
            queue_job.queue_name = queue_name,
        ),
        skip_all,
        err,
    )]
    async fn schedule(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("queue_job.id", tracing::field::display(id));

        let new_job = NewJob {
            id: Uuid::from(id),
            queue_name: queue_name.to_owned(),
            payload,
            metadata,
            created_at,
        };

        diesel::insert_into(queue_jobs::table)
            .values(&new_job)
            .execute(self.conn)
            .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_job.schedule_later",
        fields(
            queue_job.id,
            queue_job.queue_name = queue_name,
            queue_job.scheduled_at = %scheduled_at,
        ),
        skip_all,
        err,
    )]
    async fn schedule_later(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
        scheduled_at: DateTime<Utc>,
        schedule_name: Option<&str>,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("queue_job.id", tracing::field::display(id));

        let new_job = NewScheduledJob {
            id: Uuid::from(id),
            queue_name: queue_name.to_owned(),
            payload,
            metadata,
            created_at,
            scheduled_at: Some(scheduled_at),
            schedule_name: schedule_name.map(ToOwned::to_owned),
            status: "scheduled".to_owned(),
        };

        diesel::insert_into(queue_jobs::table)
            .values(&new_job)
            .execute(self.conn)
            .await?;

        // If there was a schedule name supplied, update the queue_schedules table
        if let Some(schedule_name) = schedule_name {
            let rows_affected = diesel::update(
                queue_schedules::table.filter(queue_schedules::schedule_name.eq(schedule_name)),
            )
            .set((
                queue_schedules::last_scheduled_at.eq(Some(scheduled_at)),
                queue_schedules::last_scheduled_job_id.eq(Some(Uuid::from(id))),
            ))
            .execute(self.conn)
            .await?;

            DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        }

        Ok(())
    }

    #[tracing::instrument(name = "db.queue_job.reserve", skip_all, err)]
    async fn reserve(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        count: usize,
    ) -> Result<Vec<Job>, Self::Error> {
        let now = clock.now();
        let max_count = i64::try_from(count).unwrap_or(i64::MAX);
        let queues: Vec<String> = queues.iter().map(|&s| s.to_owned()).collect();

        let results: Vec<JobReservationResult> = diesel::sql_query(
            r"
                WITH locked_jobs AS (
                    SELECT id
                    FROM queue_jobs
                    WHERE
                        status = 'available'
                        AND queue_name = ANY($1)
                    ORDER BY id ASC
                    LIMIT $2
                    FOR UPDATE
                    SKIP LOCKED
                )
                UPDATE queue_jobs
                SET status = 'running', started_at = $3, started_by = $4
                FROM locked_jobs
                WHERE queue_jobs.id = locked_jobs.id
                RETURNING
                    queue_jobs.id,
                    queue_jobs.queue_name,
                    queue_jobs.payload,
                    queue_jobs.metadata,
                    queue_jobs.attempt
            ",
        )
        .bind::<Array<Text>, _>(&queues)
        .bind::<BigInt, _>(max_count)
        .bind::<Timestamptz, _>(now)
        .bind::<DieselUuid, _>(Uuid::from(worker.id))
        .get_results(self.conn)
        .await?;

        let jobs = results
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(jobs)
    }

    #[tracing::instrument(
        name = "db.queue_job.mark_as_completed",
        skip_all,
        fields(
            job.id = %id,
        ),
        err,
    )]
    async fn mark_as_completed(&mut self, clock: &dyn Clock, id: Ulid) -> Result<(), Self::Error> {
        let now = clock.now();
        let rows_affected = diesel::update(
            queue_jobs::table
                .filter(queue_jobs::id.eq(Uuid::from(id)))
                .filter(queue_jobs::status.eq("running")),
        )
        .set((
            queue_jobs::status.eq("completed"),
            queue_jobs::completed_at.eq(Some(now)),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_job.mark_as_failed",
        skip_all,
        fields(
            job.id = %id,
        ),
        err
    )]
    async fn mark_as_failed(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        reason: &str,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        let rows_affected = diesel::update(
            queue_jobs::table
                .filter(queue_jobs::id.eq(Uuid::from(id)))
                .filter(queue_jobs::status.eq("running")),
        )
        .set((
            queue_jobs::status.eq("failed"),
            queue_jobs::failed_at.eq(Some(now)),
            queue_jobs::failed_reason.eq(Some(reason)),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_job.retry",
        skip_all,
        fields(
            job.id = %id,
        ),
        err
    )]
    async fn retry(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        id: Ulid,
        delay: Duration,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        let scheduled_at = now + delay;
        let new_id = new_id(now, rng);

        // Create a new job with the same payload and metadata, but a new ID and
        // increment the attempt.
        // We make sure we do this only for 'failed' jobs.
        let rows_affected: usize = diesel::sql_query(
            r"
                INSERT INTO queue_jobs
                    (id, queue_name, payload, metadata, created_at,
                     attempt, scheduled_at, schedule_name, status)
                SELECT $1, queue_name, payload, metadata, $2, attempt + 1, $3, schedule_name, 'scheduled'
                FROM queue_jobs
                WHERE id = $4
                  AND status = 'failed'
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(new_id))
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(scheduled_at)
        .bind::<DieselUuid, _>(Uuid::from(id))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        // If that job was referenced by a schedule, update the schedule
        diesel::update(
            queue_schedules::table
                .filter(queue_schedules::last_scheduled_job_id.eq(Uuid::from(id))),
        )
        .set((
            queue_schedules::last_scheduled_at.eq(Some(scheduled_at)),
            queue_schedules::last_scheduled_job_id.eq(Some(Uuid::from(new_id))),
        ))
        .execute(self.conn)
        .await?;

        // Update the old job to point to the new attempt
        let rows_affected =
            diesel::update(queue_jobs::table.filter(queue_jobs::id.eq(Uuid::from(id))))
                .set(queue_jobs::next_attempt_id.eq(Some(Uuid::from(new_id))))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(name = "db.queue_job.schedule_available_jobs", skip_all, err)]
    async fn schedule_available_jobs(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error> {
        let now = clock.now();
        let count = diesel::update(
            queue_jobs::table
                .filter(queue_jobs::status.eq("scheduled"))
                .filter(queue_jobs::scheduled_at.le(Some(now))),
        )
        .set(queue_jobs::status.eq("available"))
        .execute(self.conn)
        .await?;

        Ok(count)
    }

    #[tracing::instrument(name = "db.queue_job.mark_abandoned_jobs_as_failed", skip_all, err)]
    async fn mark_abandoned_jobs_as_failed(
        &mut self,
        clock: &dyn Clock,
        reason: &str,
    ) -> Result<Vec<AbandonedJob>, Self::Error> {
        let now = clock.now();
        let jobs = diesel::sql_query(
            r"
                WITH abandoned_jobs AS (
                    SELECT
                        queue_jobs.id,
                        queue_jobs.queue_name,
                        queue_jobs.attempt,
                        queue_jobs.started_by,
                        queue_jobs.started_at,
                        queue_workers.shutdown_at AS worker_shutdown_at
                    FROM queue_jobs
                    JOIN queue_workers
                        ON queue_workers.id = queue_jobs.started_by
                    WHERE queue_jobs.status = 'running'
                      AND queue_workers.shutdown_at IS NOT NULL
                ),
                marked_jobs AS (
                    UPDATE queue_jobs
                    SET status = 'failed', failed_at = $1, failed_reason = $2
                    FROM abandoned_jobs
                    WHERE queue_jobs.id = abandoned_jobs.id
                      AND queue_jobs.status = 'running'
                    RETURNING queue_jobs.id
                )
                SELECT
                    abandoned_jobs.id,
                    abandoned_jobs.queue_name,
                    abandoned_jobs.attempt,
                    abandoned_jobs.started_by,
                    abandoned_jobs.started_at,
                    abandoned_jobs.worker_shutdown_at
                FROM abandoned_jobs
                JOIN marked_jobs USING (id)
            ",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<Text, _>(reason)
        .get_results::<AbandonedJobResult>(self.conn)
        .await?;

        let jobs = jobs
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(jobs)
    }

    #[tracing::instrument(
        name = "db.queue_job.cleanup",
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
        // Use ULID cursor-based pagination for completed and failed jobs.
        // We delete both completed and failed jobs in the same batch.
        // `MAX(uuid)` isn't a thing in Postgres, so we aggregate on the client side.
        let res: Vec<UuidRow> = diesel::sql_query(
            r"
                WITH to_delete AS (
                    SELECT id
                    FROM queue_jobs
                    WHERE (status = 'completed' OR status = 'failed')
                      AND ($1::uuid IS NULL OR id > $1)
                      AND id <= $2
                    ORDER BY id
                    LIMIT $3
                )
                DELETE FROM queue_jobs
                USING to_delete
                WHERE queue_jobs.id = to_delete.id
                RETURNING queue_jobs.id
            ",
        )
        .bind::<Nullable<DieselUuid>, _>(since.map(Uuid::from))
        .bind::<DieselUuid, _>(Uuid::from(until))
        .bind::<BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_results(self.conn)
        .await?;

        let count = res.len();
        let max_id = res.into_iter().map(|r| r.id).max();

        Ok((count, max_id.map(Ulid::from)))
    }
}

/// Helper struct for extracting a single UUID column from raw SQL results.
#[derive(Debug, QueryableByName)]
struct UuidRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::Duration;
    use coauth_data::clock::MockClock;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::PgRepositoryFactory;

    fn unique_queue_name() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        format!("queue-test-{now}")
    }

    #[tokio::test]
    async fn recovers_abandoned_jobs_from_shutdown_workers() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(42);
        let queue_name = unique_queue_name();

        let payload = serde_json::json!({ "kind": "test" });
        repo.queue_job()
            .schedule(
                &mut rng,
                &clock,
                &queue_name,
                payload.clone(),
                serde_json::json!({}),
            )
            .await
            .unwrap();

        let worker = repo
            .queue_worker()
            .register(&mut rng, &clock)
            .await
            .unwrap();
        let reserved = repo
            .queue_job()
            .reserve(&clock, &worker, &[queue_name.as_str()], 1)
            .await
            .unwrap();
        let job = reserved.into_iter().next().expect("reserved one job");

        clock.advance(Duration::minutes(3));

        let dead_workers = repo
            .queue_worker()
            .shutdown_dead_workers(&clock, Duration::minutes(2))
            .await
            .unwrap();
        assert_eq!(dead_workers.len(), 1);
        assert_eq!(dead_workers[0].id, worker.id);

        let abandoned_jobs = repo
            .queue_job()
            .mark_abandoned_jobs_as_failed(&clock, "worker lost heartbeat")
            .await
            .unwrap();
        assert_eq!(abandoned_jobs.len(), 1);
        assert_eq!(abandoned_jobs[0].id, job.id);
        assert_eq!(abandoned_jobs[0].queue_name.as_str(), queue_name.as_str());
        assert_eq!(abandoned_jobs[0].attempt, job.attempt);
        assert_eq!(abandoned_jobs[0].started_by, worker.id);

        repo.queue_job()
            .retry(&mut rng, &clock, job.id, Duration::zero())
            .await
            .unwrap();
        assert_eq!(
            repo.queue_job()
                .schedule_available_jobs(&clock)
                .await
                .unwrap(),
            1
        );

        let rescuer = repo
            .queue_worker()
            .register(&mut rng, &clock)
            .await
            .unwrap();
        let retried = repo
            .queue_job()
            .reserve(&clock, &rescuer, &[queue_name.as_str()], 1)
            .await
            .unwrap();
        assert_eq!(retried.len(), 1);
        assert_ne!(retried[0].id, job.id);
        assert_eq!(retried[0].queue_name.as_str(), queue_name.as_str());
        assert_eq!(retried[0].payload, payload);
        assert_eq!(retried[0].attempt, job.attempt + 1);
    }
}
