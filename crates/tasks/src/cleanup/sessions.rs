//! Session cleanup tasks

use coauth_data::queue::{
    CleanupExpiredSessionGrantsJob, CleanupFinishedOAuthSessionsJob,
    CleanupFinishedUserSessionsJob, CleanupInactiveOAuthSessionIpsJob,
    CleanupInactiveUserSessionIpsJob,
};

cleanup_time_cursor_job!(
    job = CleanupFinishedOAuthSessionsJob,
    span = "job.cleanup_finished_oauth_sessions",
    repo = oauth_session,
    method = cleanup_finished,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no finished OAuth sessions to clean up",
    done = "cleaned up finished OAuth sessions",
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
    job = CleanupInactiveOAuthSessionIpsJob,
    span = "job.cleanup_inactive_oauth_session_ips",
    repo = oauth_session,
    method = cleanup_inactive_ips,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no OAuth session IPs to clean up",
    done = "cleaned up inactive OAuth session IPs",
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

// Arkret session grants have a short TTL (5 min in
// `handlers::arkret::SESSION_GRANT_TTL_MINUTES`) and are revoked on
// successful introspection — but invalid-proof / unexchanged grants
// still accumulate. Drop anything that's been expired for more than
// an hour so introspection-side replay/audit windows still work but
// the table doesn't grow unbounded.
cleanup_time_cursor_job!(
    job = CleanupExpiredSessionGrantsJob,
    span = "job.cleanup_expired_session_grants",
    repo = oauth_session_grant,
    method = cleanup_expired,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::hours(1),
    timeout_secs = 10 * 60,
    empty = "no expired session grants to clean up",
    done = "cleaned up expired session grants",
);
