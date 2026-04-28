use chrono::Duration;
use cron::Schedule;
use diesel::{sql_query, sql_types::Bool};
use diesel_async::RunQueryDsl;
use coauth_data::{DatabaseError, PgRepository, RepositoryAccess, queue::InsertableJob};

use super::{QueueRunnerError, shared::MAX_ATTEMPTS};
use crate::State;

/// Result of a `pg_try_advisory_lock` query.
#[derive(diesel::QueryableByName)]
struct AdvisoryLockResult {
    #[diesel(sql_type = Bool)]
    acquired: bool,
}

/// Derive a stable i64 key from a human-readable lock name using CRC-32.
fn advisory_lock_key(name: &str) -> i64 {
    const CRC_IEEE: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    i64::from(CRC_IEEE.checksum(name.as_bytes()))
}

/// A cron-like schedule definition that the leader evaluates every tick.
pub(super) struct ScheduleDefinition {
    pub(super) schedule_name: &'static str,
    pub(super) expression: Schedule,
    pub(super) queue_name: &'static str,
    pub(super) payload: serde_json::Value,
}

impl ScheduleDefinition {
    pub(super) fn new<T: InsertableJob>(
        schedule_name: &'static str,
        expression: Schedule,
        job: T,
    ) -> Self {
        let payload = serde_json::to_value(job).expect("failed to serialize job payload");

        Self {
            schedule_name,
            expression,
            queue_name: T::QUEUE_NAME,
            payload,
        }
    }
}

fn missing_schedule_names(
    schedules: &[ScheduleDefinition],
    statuses: &[coauth_data::queue::ScheduleStatus],
) -> Vec<&'static str> {
    schedules
        .iter()
        .filter_map(|schedule| {
            (!statuses
                .iter()
                .any(|status| status.schedule_name == schedule.schedule_name))
            .then_some(schedule.schedule_name)
        })
        .collect()
}

async fn recover_abandoned_jobs(
    repo: &mut PgRepository,
    rng: &mut rand_chacha::ChaChaRng,
    clock: &dyn coauth_data::Clock,
) -> Result<(), QueueRunnerError> {
    let dead_workers = repo
        .queue_worker()
        .shutdown_dead_workers(clock, Duration::minutes(2))
        .await?;

    match dead_workers.len() {
        0 => {}
        1 => tracing::warn!(
            worker.id = %dead_workers[0].id,
            worker.last_seen_at = %dead_workers[0].last_seen_at,
            worker.shutdown_at = %dead_workers[0].shutdown_at,
            "Marked one worker as shut down after missed heartbeats"
        ),
        _ => {
            for worker in &dead_workers {
                tracing::warn!(
                    worker.id = %worker.id,
                    worker.last_seen_at = %worker.last_seen_at,
                    worker.shutdown_at = %worker.shutdown_at,
                    "Marked worker as shut down after missed heartbeats"
                );
            }
        }
    }

    let abandoned_jobs = repo
        .queue_job()
        .mark_abandoned_jobs_as_failed(clock, "worker lost heartbeat")
        .await?;

    let mut recovered_jobs = 0;
    let mut abandoned_forever = 0;
    for job in abandoned_jobs {
        if job.attempt < MAX_ATTEMPTS {
            repo.queue_job()
                .retry(rng, clock, job.id, Duration::zero())
                .await?;
            recovered_jobs += 1;

            tracing::warn!(
                job.id = %job.id,
                job.queue.name = %job.queue_name,
                job.attempt = job.attempt,
                worker.id = %job.started_by,
                worker.shutdown_at = %job.worker_shutdown_at,
                "Recovered an abandoned job after worker shutdown"
            );
        } else {
            abandoned_forever += 1;

            tracing::error!(
                job.id = %job.id,
                job.queue.name = %job.queue_name,
                job.attempt = job.attempt,
                worker.id = %job.started_by,
                worker.shutdown_at = %job.worker_shutdown_at,
                "Abandoned job exceeded the retry limit after worker shutdown"
            );
        }
    }

    if recovered_jobs > 0 || abandoned_forever > 0 {
        tracing::warn!(
            recovered_jobs,
            abandoned_forever,
            "Processed abandoned jobs left behind by shut-down workers"
        );
    }

    Ok(())
}

pub(super) async fn run_leader_duties(
    state: &State,
    schedules: &[ScheduleDefinition],
) -> Result<(), QueueRunnerError> {
    let clock = state.clock();
    let mut rng = state.rng();

    let mut conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;

    let lock_key = advisory_lock_key("leader-duties");
    let lock_result: AdvisoryLockResult = sql_query(format!(
        "SELECT pg_try_advisory_lock({lock_key}) AS acquired"
    ))
    .get_result(&mut *conn)
    .await
    .map_err(DatabaseError::from)?;

    if !lock_result.acquired {
        tracing::error!("Another worker has the leader lock, aborting");
        return Ok(());
    }

    let mut repo = PgRepository::new(conn);
    recover_abandoned_jobs(&mut repo, &mut rng, clock).await?;

    let mut schedules_status = repo.queue_schedule().list().await?;
    let mut missing = missing_schedule_names(schedules, &schedules_status);
    if !missing.is_empty() {
        tracing::warn!(
            schedules = ?missing,
            "Queue schedule definitions are missing from the database, repairing them",
        );
        repo.queue_schedule().setup(&missing).await?;
        schedules_status = repo.queue_schedule().list().await?;
        missing = missing_schedule_names(schedules, &schedules_status);
        if !missing.is_empty() {
            tracing::error!(
                schedules = ?missing,
                "Queue schedule definitions are still missing after repair",
            );
        }
    }

    let now = clock.now();
    for schedule in schedules {
        let Some(status) = schedules_status
            .iter()
            .find(|s| s.schedule_name == schedule.schedule_name)
        else {
            continue;
        };

        if let Some(next_time) = status.last_scheduled_at {
            if next_time > now {
                continue;
            }

            if status.last_scheduled_job_completed == Some(false) {
                continue;
            }
        }

        let next_tick = schedule.expression.after(&now).next().unwrap();

        tracing::info!(
            "Scheduling job for {}, next run at {}",
            schedule.schedule_name,
            next_tick
        );

        repo.queue_job()
            .schedule_later(
                &mut rng,
                clock,
                schedule.queue_name,
                schedule.payload.clone(),
                serde_json::json!({}),
                next_tick,
                Some(schedule.schedule_name),
            )
            .await?;
    }

    let scheduled = repo.queue_job().schedule_available_jobs(clock).await?;
    match scheduled {
        0 => {}
        1 => tracing::info!("One scheduled job marked as available"),
        n => tracing::info!("{n} scheduled jobs marked as available"),
    }

    let mut conn = repo.into_inner();
    let _ = sql_query(format!("SELECT pg_advisory_unlock({lock_key})"))
        .execute(&mut *conn)
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use coauth_data::queue::ScheduleStatus;

    use super::{ScheduleDefinition, missing_schedule_names};

    fn schedule(name: &'static str) -> ScheduleDefinition {
        ScheduleDefinition {
            schedule_name: name,
            expression: "* * * * * *".parse().expect("valid cron"),
            queue_name: "queue",
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn detects_missing_schedule_names() {
        let schedules = vec![schedule("alpha"), schedule("beta"), schedule("gamma")];
        let statuses = vec![
            ScheduleStatus {
                schedule_name: "alpha".to_string(),
                last_scheduled_at: Some(Utc::now()),
                last_scheduled_job_completed: Some(true),
            },
            ScheduleStatus {
                schedule_name: "gamma".to_string(),
                last_scheduled_at: None,
                last_scheduled_job_completed: None,
            },
        ];

        assert_eq!(missing_schedule_names(&schedules, &statuses), vec!["beta"]);
    }
}
