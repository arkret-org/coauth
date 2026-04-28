// Restrict access to specific hours (UTC).
// Only allow access between 8:00 and 22:00 UTC.
forbid(principal, action, resource)
when { context.current_hour < 8 || context.current_hour >= 22 };
