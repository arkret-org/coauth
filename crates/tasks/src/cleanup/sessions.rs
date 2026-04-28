//! Session cleanup tasks

use coauth_data::queue::{
    CleanupFinishedOAuth2SessionsJob, CleanupFinishedUserSessionsJob,
    CleanupInactiveOAuth2SessionIpsJob, CleanupInactiveUserSessionIpsJob,
};

cleanup_time_cursor_job!(
    job = CleanupFinishedOAuth2SessionsJob,
    span = "job.cleanup_finished_oauth2_sessions",
    repo = oauth2_session,
    method = cleanup_finished,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no finished OAuth2 sessions to clean up",
    done = "cleaned up finished OAuth2 sessions",
);

cleanup_time_cursor_job!(
    job = CleanupFinishedUserSessionsJob,
    span = "job.cleanup_finished_user_sessions",
    repo = browser_session,
    method = cleanup_finished,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no finished user sessions to clean up",
    done = "cleaned up finished user sessions",
);

cleanup_time_cursor_job!(
    job = CleanupInactiveOAuth2SessionIpsJob,
    span = "job.cleanup_inactive_oauth2_session_ips",
    repo = oauth2_session,
    method = cleanup_inactive_ips,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no OAuth2 session IPs to clean up",
    done = "cleaned up inactive OAuth2 session IPs",
);

cleanup_time_cursor_job!(
    job = CleanupInactiveUserSessionIpsJob,
    span = "job.cleanup_inactive_user_session_ips",
    repo = browser_session,
    method = cleanup_inactive_ips,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no user session IPs to clean up",
    done = "cleaned up inactive user session IPs",
);
