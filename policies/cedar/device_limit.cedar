// Limit the number of active sessions per user.
// Forbid new authorizations when session count exceeds the limit.
forbid(principal, action == Action::"authorize", resource)
when { context.session_counts.total > 10 };
