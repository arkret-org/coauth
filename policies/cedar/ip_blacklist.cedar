// Block requests from specific IP addresses.
// Configure blocked_ips in the policy data.
forbid(principal, action, resource)
when { context.requester.ip_address in context.data.blocked_ips };
