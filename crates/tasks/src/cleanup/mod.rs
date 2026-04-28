//! Database cleanup tasks
//!
//! Periodic jobs that remove stale rows from the database. Each submodule
//! targets a particular domain:
//!
//! - [`tokens`]: Revoked / expired OAuth access and refresh tokens
//! - [`sessions`]: Finished OAuth2 and browser sessions, plus inactive session
//!   IPs
//! - [`oauth`]: Authorization grants, device-code grants, upstream OAuth
//!   sessions and links
//! - [`user`]: Abandoned registrations, recovery sessions, email authentication
//!   codes
//! - [`misc`]: Completed queue jobs and stale policy data

use chrono::{DateTime, Utc};
use ulid::Ulid;

pub(crate) const BATCH_SIZE: usize = 1000;

pub(crate) fn log_cleanup_result(processed: usize, empty: &'static str, done: &'static str) {
    if processed == 0 {
        tracing::debug!("{empty}");
    } else {
        tracing::info!(count = processed, "{done}");
    }
}

pub(crate) fn ulid_upper_bound(cutoff: DateTime<Utc>) -> Ulid {
    Ulid::from_parts(
        u64::try_from(cutoff.timestamp_millis()).unwrap_or(u64::MIN),
        u128::MAX,
    )
}

macro_rules! cleanup_time_cursor_job {
    (
		job = $job:ty,
		span = $span:literal,
		repo = $repo:ident,
		method = $method:ident,
		cutoff = $cutoff:expr,
		timeout_secs = $timeout_secs:expr,
		empty = $empty:literal,
		done = $done:literal $(,)?
	) => {
        #[async_trait::async_trait]
        impl crate::new_queue::RunnableJob for $job {
            #[tracing::instrument(name = $span, skip_all)]
            async fn run(
                &self,
                state: &crate::State,
                context: crate::new_queue::JobContext,
            ) -> Result<(), crate::new_queue::JobError> {
                let cutoff = ($cutoff)(state);
                let mut processed = 0usize;
                let mut cursor = None;

                while !context.cancellation_token.is_cancelled() {
                    let mut repo = state
                        .repository()
                        .await
                        .map_err(crate::new_queue::JobError::retry)?;
                    let (batch_size, next_cursor) = {
                        let mut store = repo.$repo();
                        store.$method(cursor, cutoff, super::BATCH_SIZE).await
                    }
                    .map_err(crate::new_queue::JobError::retry)?;

                    repo.save()
                        .await
                        .map_err(crate::new_queue::JobError::retry)?;
                    processed += batch_size;
                    cursor = next_cursor;

                    if batch_size < super::BATCH_SIZE {
                        break;
                    }
                }

                super::log_cleanup_result(processed, $empty, $done);
                Ok(())
            }

            fn timeout(&self) -> Option<std::time::Duration> {
                Some(std::time::Duration::from_secs($timeout_secs))
            }
        }
    };
}

macro_rules! cleanup_ulid_cursor_job {
    (
		job = $job:ty,
		span = $span:literal,
		repo = $repo:ident,
		method = $method:ident,
		cutoff = $cutoff:expr,
		timeout_secs = $timeout_secs:expr,
		empty = $empty:literal,
		done = $done:literal $(,)?
	) => {
        #[async_trait::async_trait]
        impl crate::new_queue::RunnableJob for $job {
            #[tracing::instrument(name = $span, skip_all)]
            async fn run(
                &self,
                state: &crate::State,
                context: crate::new_queue::JobContext,
            ) -> Result<(), crate::new_queue::JobError> {
                let cutoff = ($cutoff)(state);
                let upper_bound = super::ulid_upper_bound(cutoff);
                let mut processed = 0usize;
                let mut cursor = None;

                while !context.cancellation_token.is_cancelled() {
                    let mut repo = state
                        .repository()
                        .await
                        .map_err(crate::new_queue::JobError::retry)?;
                    let (batch_size, next_cursor) = {
                        let mut store = repo.$repo();
                        store.$method(cursor, upper_bound, super::BATCH_SIZE).await
                    }
                    .map_err(crate::new_queue::JobError::retry)?;

                    repo.save()
                        .await
                        .map_err(crate::new_queue::JobError::retry)?;
                    processed += batch_size;
                    cursor = next_cursor;

                    if batch_size < super::BATCH_SIZE {
                        break;
                    }
                }

                super::log_cleanup_result(processed, $empty, $done);
                Ok(())
            }

            fn timeout(&self) -> Option<std::time::Duration> {
                Some(std::time::Duration::from_secs($timeout_secs))
            }
        }
    };
}

mod misc;
mod oauth;
mod sessions;
mod tokens;
mod user;
