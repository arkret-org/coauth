# Deployment Hardening

This chapter covers the deployment-time posture decisions that affect how
**strictly** coauth enforces accountability and revocation. The single most
important toggle is the `cx.profile.accountable_to.strict_reject.v1`
profile, which converts soft warnings into hard rejects across the
`accountable_to` chain.

## `accountable_to.strict_reject` profile

By default, coauth runs a **lenient** accountability posture: stale or
unknown links in the `accountable_to` chain log a structured warning but
do not block session-grant decisions. This is the safe default for
multi-tenant deployments where some peers haven't yet upgraded their
accountability shape and a hard reject would cascade into user-visible
outages.

The strict-reject profile inverts that posture: any unknown, stale, or
mismatched link in the chain produces a hard reject at session-grant time.

### When to declare

Declare strict-reject when **any** of the following hold:

1. **Regulated workloads.** Auditors require evidence that
   accountability-chain anomalies cause hard failures (not soft logs).
2. **Audit log consumption.** A downstream auditor or compliance system
   is reading the accountability stream and silently-dropped claims would
   cause audit gaps.
3. **Accountability drift investigation.** You're investigating why
   accountability claims are arriving stale; turning on strict-reject
   converts the noise into hard signal that ops dashboards already alert
   on.
4. **High-assurance enterprise tenant.** Tenant SLA mandates strict
   accountability enforcement.

Do NOT declare strict-reject when:

- You haven't audited the last 24h of accountability claims to understand
  the stale-vs-fresh baseline.
- A federation peer you depend on hasn't upgraded yet.
- You're in a release window — the toggle can produce a temporary 4xx
  spike that masquerades as a regression.

### Expected fallout

Once you flip the profile on:

1. **Spike in 4xx rejects.** Stale claims that previously logged a warning
   now reject. Alerting that watches 4xx ratio MUST be informed; preferably
   silence the noisy alert for the flip window.
2. **Federation peer rejects.** Federated events from peers that haven't
   upgraded their accountability shape will start to fail. Coordinate the
   flip with federation partners and document the cutover instant.
3. **Increased upstream traffic to soland.** Strict-reject typically pins
   the revocation-freshness window to `<= 30s`, which means coauth refreshes
   mirrored state more often. Expect ~2× the baseline upstream RPC rate
   to soland for the agent-state and accountability-grant endpoints.
4. **Hard rejects on agent-runtime calls.** `agent_paused`,
   `agent_deactivated`, and `accountability_grant_missing` go from
   "logged + reject" to "logged + reject + alert" — make sure ops is
   ready.

### Pre-flip checklist

1. Snapshot 24h of accountability-claim arrivals; categorize stale vs.
   fresh. The stale ratio should be <2% before flipping; >5% means the
   flip will produce too much noise to be safely auditable.
2. Decide the cutover instant; pre-notify federation peers in writing.
3. Pre-silence the 4xx-ratio alert for a 60-minute window centered on the
   flip.
4. Flip the profile via the realm operator's admin path (the operator
   issues a `cx.realm.profile.update` with the strict-reject profile
   declared).
5. Watch for 30 minutes:
   - `coauth_accountable_to_reject_total{profile="strict"}` — should rise
     from zero, level off within the staleness baseline +20%.
   - `coauth_session_grant_failure_total{reason="agent_paused" | "agent_deactivated" | "accountability_grant_missing"}` — should remain at the
     pre-flip baseline.
6. If reject counts exceed threshold: rollback (toggle off), file a bug
   against the noisiest peer, retry the flip after the peer upgrades.

### Audit log expectations

Strict-reject is an auditable posture change. Both the flip-on and
flip-off events MUST appear in the audit log under the kind
`profile.accountable_to.strict_reject.flip`. The audit row carries:

- `realm_id`
- `direction` (`on` or `off`)
- `actor_id` of the operator
- `timestamp`
- `prior_state_digest` and `new_state_digest` of the realm profile set
- `justification` free-form string (operator-supplied)

While strict-reject is active, every reject also produces an audit row
under `accountable_to.strict_reject.reject`:

- `realm_id`
- `chain_anchor` (the offending principal)
- `reason` (one of: `stale`, `unknown`, `mismatch`, `chain_break`)
- `requested_operation` (e.g. `cx.account.issue_session_grant`)
- `timestamp`

These rows are consumed by the compliance pipeline. Do NOT prune them
within the audit retention window (default 90 days; check your tenant
SLA).

### Rollback

To rollback strict-reject:

1. Operator issues another `cx.realm.profile.update` removing the
   `cx.profile.accountable_to.strict_reject.v1` profile from the realm's
   declared profile set.
2. In-flight rejects already audited remain audited; no further reject
   decisions fire.
3. coauth restores the default lenient posture on the next mirror refresh
   (within `revocation_freshness_window`).
4. Audit a `profile.accountable_to.strict_reject.flip` row with
   `direction = off`.

The toggle is **realm-scoped**, not deployment-global. A single coauth
deployment may simultaneously serve some realms in strict-reject and
others in the default posture.
