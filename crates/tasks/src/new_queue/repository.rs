use chrono::{DateTime, Utc};
use coauth_data::{PgRepository, RepositoryAccess, queue::Worker};
use tokio_util::sync::CancellationToken;

use super::{
    QueueRunnerError,
    leader::ScheduleDefinition,
    runtime,
    shared::{MAX_CONCURRENT_JOBS, MAX_JOBS_TO_FETCH},
    tracker::JobTracker,
};
use crate::State;

fn jobs_to_fetch_capacity(running_jobs: usize) -> usize {
    MAX_CONCURRENT_JOBS
        .saturating_sub(running_jobs)
        .min(MAX_JOBS_TO_FETCH)
}

pub(super) async fn register_worker(
    state: &State,
) -> Result<(Worker, DateTime<Utc>), QueueRunnerError> {
    let mut rng = state.rng();
    let clock = state.clock();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    let registration = repo.queue_worker().register(&mut rng, clock).await?;
    Ok((registration, clock.now()))
}

pub(super) async fn setup_schedules(
    state: &State,
    schedules: &[ScheduleDefinition],
) -> Result<(), QueueRunnerError> {
    let schedule_names: Vec<_> = schedules
        .iter()
        .map(|schedule| schedule.schedule_name)
        .collect();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;

    let mut repo = PgRepository::new(conn);
    repo.queue_schedule().setup(&schedule_names).await?;
    Ok(())
}

pub(super) async fn shutdown_worker(
    state: &State,
    registration: &Worker,
    tracker: &mut JobTracker,
) -> Result<(), QueueRunnerError> {
    let clock = state.clock();
    let mut rng = state.rng();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    match tracker.running_jobs() {
        0 => {}
        1 => tracing::warn!("There is one job still running, waiting for it to finish"),
        count => tracing::warn!("There are {count} jobs still running, waiting for them to finish"),
    }

    tracker
        .process_jobs(&mut rng, clock, &mut repo, true)
        .await?;
    repo.queue_worker().shutdown(clock, registration).await?;
    Ok(())
}

pub(super) async fn tick_worker(
    state: &State,
    registration: &Worker,
    last_heartbeat: &mut DateTime<Utc>,
    tracker: &mut JobTracker,
    cancellation_token: &CancellationToken,
) -> Result<bool, QueueRunnerError> {
    let clock = state.clock();
    let mut rng = state.rng();
    let now = clock.now();
    let heartbeat_age = now - *last_heartbeat;

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    if heartbeat_age >= chrono::Duration::seconds(90) {
        tracing::warn!(
            worker.id = %registration.id,
            heartbeat.age_secs = heartbeat_age.num_seconds(),
            running_jobs = tracker.running_jobs(),
            "Worker heartbeat is overdue"
        );
    }

    if heartbeat_age >= chrono::Duration::minutes(1) {
        tracing::info!(
            worker.id = %registration.id,
            heartbeat.age_secs = heartbeat_age.num_seconds(),
            running_jobs = tracker.running_jobs(),
            "Sending heartbeat"
        );
        repo.queue_worker().heartbeat(clock, registration).await?;
        *last_heartbeat = now;
    }

    repo.queue_worker()
        .remove_leader_lease_if_expired(clock)
        .await?;

    let leader = repo
        .queue_worker()
        .try_get_leader_lease(clock, registration)
        .await?;

    tracker
        .process_jobs(&mut rng, clock, &mut repo, false)
        .await?;

    let running_jobs = tracker.running_jobs();
    let max_jobs_to_fetch = jobs_to_fetch_capacity(running_jobs);

    if max_jobs_to_fetch == 0 {
        tracing::warn!(
            worker.id = %registration.id,
            running_jobs,
            max_concurrent_jobs = MAX_CONCURRENT_JOBS,
            "Internal job queue is full, not fetching any new jobs"
        );
    } else {
        let queues = tracker.queues();
        let jobs = repo
            .queue_job()
            .reserve(clock, registration, &queues, max_jobs_to_fetch)
            .await?;

        if !jobs.is_empty() {
            tracing::info!(
                worker.id = %registration.id,
                running_jobs,
                reserved_jobs = jobs.len(),
                max_jobs_to_fetch,
                "Reserved jobs from the queue"
            );
        }

        runtime::spawn_reserved_jobs(tracker, state, cancellation_token, jobs);
    }

    Ok(leader)
}

#[cfg(test)]
mod tests {
    use super::jobs_to_fetch_capacity;

    #[test]
    fn limits_fetch_to_remaining_capacity() {
        assert_eq!(jobs_to_fetch_capacity(0), 5);
        assert_eq!(jobs_to_fetch_capacity(4), 5);
        assert_eq!(jobs_to_fetch_capacity(7), 3);
        assert_eq!(jobs_to_fetch_capacity(10), 0);
        assert_eq!(jobs_to_fetch_capacity(12), 0);
    }
}

pub(super) async fn process_all_jobs_in_tests(
    state: &State,
    registration: &Worker,
    tracker: &mut JobTracker,
    cancellation_token: &CancellationToken,
) -> Result<(), QueueRunnerError> {
    let clock = state.clock();
    let mut rng = state.rng();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    let queues = tracker.queues();
    let jobs = repo
        .queue_job()
        .reserve(clock, registration, &queues, 10_000)
        .await?;

    runtime::spawn_reserved_jobs(tracker, state, cancellation_token, jobs);
    tracker
        .process_jobs(&mut rng, clock, &mut repo, true)
        .await?;
    Ok(())
}
