//! User-related cleanup tasks

use coauth_data::queue::{
    CleanupUserEmailAuthenticationsJob, CleanupUserRecoverySessionsJob, CleanupUserRegistrationsJob,
};

cleanup_ulid_cursor_job!(
    job = CleanupUserRegistrationsJob,
    span = "job.cleanup_user_registrations",
    repo = user_registration,
    method = cleanup,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no user registrations to clean up",
    done = "cleaned up user registrations",
);

cleanup_ulid_cursor_job!(
    job = CleanupUserRecoverySessionsJob,
    span = "job.cleanup_user_recovery_sessions",
    repo = user_recovery,
    method = cleanup,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(7),
    timeout_secs = 10 * 60,
    empty = "no user recovery sessions to clean up",
    done = "cleaned up user recovery sessions",
);

cleanup_ulid_cursor_job!(
    job = CleanupUserEmailAuthenticationsJob,
    span = "job.cleanup_user_email_authentications",
    repo = user_email,
    method = cleanup_authentications,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(7),
    timeout_secs = 10 * 60,
    empty = "no user email authentications to clean up",
    done = "cleaned up user email authentications",
);
