use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::{
    BoxRepository, Clock,
    oauth2::OAuth2SessionFilter,
    queue::{
        ExpireInactiveOAuthSessionsJob, ExpireInactiveSessionsJob, ExpireInactiveUserSessionsJob,
        InsertableJob, QueueJobRepositoryExt, SyncDevicesJob,
    },
    user::BrowserSessionFilter,
};
use rand_chacha::ChaChaRng;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

const SESSION_BATCH_SIZE: usize = 100;
const INITIAL_DEVICE_SYNC_DELAY: Duration = Duration::minutes(1);
const DEVICE_SYNC_SPACING: Duration = Duration::seconds(10);

async fn schedule_job_now<J: InsertableJob>(
    repo: &mut BoxRepository,
    rng: &mut ChaChaRng,
    clock: &dyn Clock,
    job: J,
) -> Result<(), JobError> {
    repo.queue_job()
        .schedule_job(rng, clock, job)
        .await
        .map_err(JobError::retry)
}

async fn schedule_job_if_present<J: InsertableJob>(
    repo: &mut BoxRepository,
    rng: &mut ChaChaRng,
    clock: &dyn Clock,
    label: &'static str,
    job: Option<J>,
) -> Result<(), JobError> {
    if let Some(job) = job {
        tracing::info!(
            job.kind = label,
            "Scheduling another session maintenance batch"
        );
        schedule_job_now(repo, rng, clock, job).await?;
    }

    Ok(())
}

async fn schedule_job_later<J: InsertableJob>(
    repo: &mut BoxRepository,
    rng: &mut ChaChaRng,
    clock: &dyn Clock,
    when: DateTime<Utc>,
    job: J,
) -> Result<(), JobError> {
    repo.queue_job()
        .schedule_job_later(rng, clock, job, when)
        .await
        .map_err(JobError::retry)
}

async fn enqueue_expiration_children(
    state: &State,
    repo: &mut BoxRepository,
    rng: &mut ChaChaRng,
    now: DateTime<Utc>,
) -> Result<bool, JobError> {
    let Some(config) = state.site_config().session_expiration.as_ref() else {
        return Ok(false);
    };

    let clock = state.clock();
    let mut scheduled_any = false;

    if let Some(ttl) = config.oauth_session_inactivity_ttl {
        schedule_job_now(
            repo,
            rng,
            clock,
            ExpireInactiveOAuthSessionsJob::new(now - ttl),
        )
        .await?;
        scheduled_any = true;
    }

    if let Some(ttl) = config.user_session_inactivity_ttl {
        schedule_job_now(
            repo,
            rng,
            clock,
            ExpireInactiveUserSessionsJob::new(now - ttl),
        )
        .await?;
        scheduled_any = true;
    }

    Ok(scheduled_any)
}

fn oauth_inactivity_filter(threshold: DateTime<Utc>) -> OAuth2SessionFilter<'static> {
    OAuth2SessionFilter::new()
        .with_last_active_before(threshold)
        .for_any_user()
        .only_dynamic_clients()
        .active_only()
}

fn browser_inactivity_filter(threshold: DateTime<Utc>) -> BrowserSessionFilter<'static> {
    BrowserSessionFilter::new()
        .with_last_active_before(threshold)
        .active_only()
}

#[async_trait]
impl RunnableJob for ExpireInactiveSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        if state.site_config().session_expiration.is_none() {
            return Ok(());
        }

        let clock = state.clock();
        let now = clock.now();
        let mut rng = state.rng();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        if enqueue_expiration_children(state, &mut repo, &mut rng, now).await? {
            repo.save().await.map_err(JobError::retry)?;
        }

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveOAuthSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mut rng = state.rng();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let page = repo
            .oauth2_session()
            .list(
                oauth_inactivity_filter(self.threshold()),
                self.pagination(SESSION_BATCH_SIZE),
            )
            .await
            .map_err(JobError::retry)?;

        schedule_job_if_present(
            &mut repo,
            &mut rng,
            clock,
            "expire-inactive-oauth-sessions",
            self.next(&page),
        )
        .await?;

        let mut seen_users = HashSet::new();
        let mut next_sync_at = clock.now() + INITIAL_DEVICE_SYNC_DELAY;

        for edge in page.edges {
            if let Some(user_id) = edge.node.user_id {
                if seen_users.insert(user_id) {
                    tracing::info!(user.id = %user_id, "Scheduling device sync after session expiry");
                    schedule_job_later(
                        &mut repo,
                        &mut rng,
                        clock,
                        next_sync_at,
                        SyncDevicesJob::new_for_id(user_id),
                    )
                    .await?;
                    next_sync_at += DEVICE_SYNC_SPACING;
                }
            }

            repo.oauth2_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveUserSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mut rng = state.rng();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let page = repo
            .browser_session()
            .list(
                browser_inactivity_filter(self.threshold()),
                self.pagination(SESSION_BATCH_SIZE),
            )
            .await
            .map_err(JobError::retry)?;

        schedule_job_if_present(
            &mut repo,
            &mut rng,
            clock,
            "expire-inactive-user-sessions",
            self.next(&page),
        )
        .await?;

        for edge in page.edges {
            repo.browser_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}
