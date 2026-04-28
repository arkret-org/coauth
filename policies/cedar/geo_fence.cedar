// Restrict access by country code (ISO 3166-1 alpha-2).
// Configure allowed_countries in the policy data.
forbid(principal, action, resource)
when { context.requester has country_code }
when { !(context.requester.country_code in context.data.allowed_countries) };
