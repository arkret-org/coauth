//! A module containing the PostgreSQL implementation of the
//! [`QueueScheduleRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::queue::{QueueScheduleRepository, ScheduleStatus};
use diesel::prelude::*;
use diesel::sql_types::{Array, Bool, Nullable, Text, Timestamptz};
use horme::RunQueryDsl;

use crate::DatabaseError;

/// An implementation of [`QueueScheduleRepository`] for a PostgreSQL
/// connection.
pub struct PgQueueScheduleRepository<'c, P = diesel_async::AsyncPgConnection> {
    conn: &'c mut P,
}

impl<'c, P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    PgQueueScheduleRepository<'c, P>
{
    /// Create a new [`PgQueueScheduleRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut P) -> Self {
        Self { conn }
    }
}

/// Row returned from the schedule list query.
#[derive(Debug, QueryableByName)]
struct ScheduleLookup {
    #[diesel(sql_type = Text)]
    schedule_name: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_scheduled_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Bool>)]
    last_scheduled_job_completed: Option<bool>,
}

impl From<ScheduleLookup> for ScheduleStatus {
    fn from(value: ScheduleLookup) -> Self {
        ScheduleStatus {
            schedule_name: value.schedule_name,
            last_scheduled_at: value.last_scheduled_at,
            last_scheduled_job_completed: value.last_scheduled_job_completed,
        }
    }
}

#[async_trait]
impl<P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    QueueScheduleRepository for PgQueueScheduleRepository<'_, P>
{
    type Error = DatabaseError;

    async fn setup(&mut self, schedules: &[&'static str]) -> Result<(), Self::Error> {
        let schedule_names: Vec<String> = schedules.iter().map(|&s| s.to_owned()).collect();

        diesel::sql_query(
            r"
                INSERT INTO queue_schedules (schedule_name)
                SELECT * FROM UNNEST($1::text[]) AS t (schedule_name)
                ON CONFLICT (schedule_name) DO NOTHING
            ",
        )
        .bind::<Array<Text>, _>(&schedule_names)
        .execute(self.conn)
        .await?;

        Ok(())
    }

    async fn list(&mut self) -> Result<Vec<ScheduleStatus>, Self::Error> {
        let res: Vec<ScheduleLookup> = diesel::sql_query(
            r"
                SELECT
                    queue_schedules.schedule_name,
                    queue_schedules.last_scheduled_at,
                    queue_jobs.status IN ('completed', 'failed') as last_scheduled_job_completed
                FROM queue_schedules
                LEFT JOIN queue_jobs
                    ON queue_jobs.id = queue_schedules.last_scheduled_job_id
            ",
        )
        .get_results(self.conn)
        .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }
}
