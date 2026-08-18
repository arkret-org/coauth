# Deployment Hardening

This chapter covers the deployment-time posture decisions that affect how
strictly coauth enforces auditability and outbound-network policy.

## Signed admin audit rows

Signed admin audit rows use transcript schema
`org.arkret.coauth.audit.admin_operation.v1`. The detached signature binds the
repository row id, `created_at`, `admin_user_id`, operation, resource type,
resource id, details, IP address, user agent, and schema version. Admin audit
read/export surfaces return `signature_status`:

- `verified` — the row verifies against the current service JWKS.
- `unsigned` — the row was allowed during rollout fail-open mode.
- `invalid` — the signature is present but no longer matches the row.
- `key_unavailable` — the row references a service DID/kid that this process
  cannot verify.

Keep `arkret.audit_signature_fail_closed: false` while rolling out signing
keys. For production regulated workloads, publish the service JWKS, verify the
audit feed reports `verified` for new rows, then set
`arkret.audit_signature_fail_closed: true` so sensitive admin mutations fail
closed when coauth cannot produce a signed audit row.

During key rotation, keep retired public keys in the deployment JWKS until the
audit retention window has elapsed; otherwise historical rows will move from
`verified` to `key_unavailable`. Treat `invalid` as a tamper or corruption
signal: preserve the database snapshot, compare the exported row JSON with the
operator system of record, and do not delete the row to silence the alert.
Exports should carry the same `signature_status` field as the admin audit feed
so offline auditors can distinguish unsigned rows from failed verification.

## Outbound HTTP and SSRF guardrails

coauth production code must use the shared `outbound_http::reqwest_client`
factory. The factory installs:

- rustls platform certificate verification;
- no redirects and no proxy inheritance;
- a DNS resolver that rejects localhost, private, link-local, multicast,
  documentation, and cloud metadata targets;
- request and connect timeouts;
- OpenTelemetry client spans and metrics.

New outbound HTTP call sites should use this factory so the same SSRF,
timeout, TLS, and telemetry policy applies consistently.

OIDC discovery and JWKS fetches use this shared client and reject response
bodies above 1 MiB. This prevents a malicious or misconfigured upstream from
turning metadata refresh into an unbounded memory sink.

Private-network egress is denied in all builds. The shared client intentionally
has no process-wide private-network escape hatch because a hostname-only allow
list cannot express the purpose, service identity, CIDR, port, expiry, and audit
requirements of a controlled-network exception.

Prefer public, routable service endpoints for upstream OIDC, the configured
`identity_registry` resolver, soland webvh registration, and policy frontier
calls. If a deployment truly needs
private service URLs, route them through a dedicated egress proxy whose policy
binds the target service identity, trust domain, CIDR, port, expiry, and audit
record.
