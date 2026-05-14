//! OAuth grants and upstream OAuth cleanup tasks

use coauth_data::queue::{
    CleanupOAuthAuthorizationGrantsJob, CleanupOAuthDeviceCodeGrantsJob,
    CleanupUpstreamOAuthLinksJob, CleanupUpstreamOAuthSessionsJob,
};

cleanup_ulid_cursor_job!(
    job = CleanupOAuthAuthorizationGrantsJob,
    span = "job.cleanup_oauth_authorization_grants",
    repo = oauth2_authorization_grant,
    method = cleanup,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(7),
    timeout_secs = 10 * 60,
    empty = "no authorization grants to clean up",
    done = "cleaned up authorization grants",
);

cleanup_ulid_cursor_job!(
    job = CleanupOAuthDeviceCodeGrantsJob,
    span = "job.cleanup_oauth_device_code_grants",
    repo = oauth_device_code_grant,
    method = cleanup,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(7),
    timeout_secs = 10 * 60,
    empty = "no device code grants to clean up",
    done = "cleaned up device code grants",
);

cleanup_ulid_cursor_job!(
    job = CleanupUpstreamOAuthSessionsJob,
    span = "job.cleanup_upstream_oauth_sessions",
    repo = upstream_oauth_session,
    method = cleanup_orphaned,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(7),
    timeout_secs = 10 * 60,
    empty = "no pending upstream OAuth sessions to clean up",
    done = "cleaned up pending upstream OAuth sessions",
);

cleanup_ulid_cursor_job!(
    job = CleanupUpstreamOAuthLinksJob,
    span = "job.cleanup_upstream_oauth_links",
    repo = upstream_oauth_link,
    method = cleanup_orphaned,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(7),
    timeout_secs = 10 * 60,
    empty = "no orphaned upstream OAuth links to clean up",
    done = "cleaned up orphaned upstream OAuth links",
);
