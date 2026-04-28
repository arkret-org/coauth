//! OAuth token cleanup tasks

use coauth_data::queue::{
    CleanupConsumedOAuthRefreshTokensJob, CleanupExpiredOAuthAccessTokensJob,
    CleanupRevokedOAuthAccessTokensJob, CleanupRevokedOAuthRefreshTokensJob,
};

cleanup_time_cursor_job!(
    job = CleanupRevokedOAuthAccessTokensJob,
    span = "job.cleanup_revoked_oauth_access_tokens",
    repo = oauth2_access_token,
    method = cleanup_revoked,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::hours(1),
    timeout_secs = 10 * 60,
    empty = "no revoked access tokens to clean up",
    done = "cleaned up revoked access tokens",
);

cleanup_time_cursor_job!(
    job = CleanupExpiredOAuthAccessTokensJob,
    span = "job.cleanup_expired_oauth_access_tokens",
    repo = oauth2_access_token,
    method = cleanup_expired,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 60,
    empty = "no expired access tokens to clean up",
    done = "cleaned up expired access tokens",
);

cleanup_time_cursor_job!(
    job = CleanupRevokedOAuthRefreshTokensJob,
    span = "job.cleanup_revoked_oauth_refresh_tokens",
    repo = oauth2_refresh_token,
    method = cleanup_revoked,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::hours(1),
    timeout_secs = 10 * 60,
    empty = "no revoked refresh tokens to clean up",
    done = "cleaned up revoked refresh tokens",
);

cleanup_time_cursor_job!(
    job = CleanupConsumedOAuthRefreshTokensJob,
    span = "job.cleanup_consumed_oauth_refresh_tokens",
    repo = oauth2_refresh_token,
    method = cleanup_consumed,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::hours(1),
    timeout_secs = 10 * 60,
    empty = "no consumed refresh tokens to clean up",
    done = "cleaned up consumed refresh tokens",
);
