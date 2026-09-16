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

`ak.session.grant` credentials are signed with the key whose kid is
`coauth-session-grant-v1`, also selected by name. A keyring that does not
carry that kid issues no grants at all: selecting by algorithm order instead
would move the signing key - and the kid clients read out of a grant -
whenever another key is added or reordered. Configure the designated key
before serving traffic, and keep a retired public key in the JWKS until every
grant it signed has expired.

Audit rows are signed with the Ed25519 key whose kid is
`coauth-audit-signing-v1` in the durable runtime key bundle. It is selected by name, never by
algorithm: an algorithm lookup returns the *last* matching key, so selecting
by algorithm would let the audit signer change silently whenever an Ed25519
key is added or reordered, and the kid recorded in every row's signature would
change with it. Without this key, rows are written `unsigned` under the
fail-open rule (or rejected when `fail_closed: true`).

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
`identity_registry` resolver, soland webvh registration, and policy decision
calls. If a deployment truly needs
private service URLs, route them through a dedicated egress proxy whose policy
binds the target service identity, trust domain, CIDR, port, expiry, and audit
record.
