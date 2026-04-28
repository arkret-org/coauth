// Only allow requests from specific IP addresses.
// Configure allowed_ips in the policy data.
forbid(principal, action, resource)
when { !(context.requester.ip_address in context.data.allowed_ips) };
