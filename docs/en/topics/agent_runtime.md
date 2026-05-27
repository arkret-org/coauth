# Agent Runtime

The agent runtime is the surface coauth exposes for **agent principals** — a
distinct principal kind from human principals. Agent principals carry their
own DIDs, their own key pairs, and a finite-state lifecycle (Active → Paused
→ Deactivated) that gates every session-grant decision.

This chapter covers the two coauth-side wire operations agent runtime drives
through, and the error matrix you will encounter when an integration is
mis-paired or stale.

## `cx.account.agent_key_pair`

Pairs an agent's DID with a freshly generated key pair under the human
principal's umbrella account. The pairing flow:

```text
[human principal]                  [coauth]                       [agent client]
   |                                  |                                |
   |  POST agent_key_pair (proof)     |                                |
   |--------------------------------->|                                |
   |                                  | resolve agent DID              |
   |                                  | verify proof bytes (JCS)       |
   |                                  | check verification_method      |
   |                                  | open pairing window (10 min)   |
   |                                  |                                |
   |                                  |  pairing token                 |
   |                                  |------------------------------->|
   |                                  |                                |
   |                                  |  agent signs over key_pair     |
   |                                  |<-------------------------------|
   |                                  |                                |
   |                                  | bind key_pair to agent DID     |
   |                                  | emit cx.account.agent_key_pair |
```

Wire failure modes:

- **`pairing_request_expired`** — the 10-minute pairing window elapsed. The
  human principal must re-issue. Common root cause: agent client clock skew
  >5 minutes. Confirm NTP on both ends.
- **`proof_invalid`** — canonical-digest mismatch between submitted proof
  and the bytes coauth re-derives. Usually a JSON serializer drift on the
  client — capture the raw payload and diff JCS bytes.
- **`verification_method_principal_mismatch`** — the `verification_method`
  in the proof resolves to a different DID than the agent's claimed
  principal. Either a DID-doc misconfiguration, a key rotation that didn't
  finish, or a malicious caller. Reject and audit; do not retry blindly.

Successful pairings emit a `cx.account.agent_key_pair` event whose payload
includes the agent's DID, the issued key pair fingerprint, and the
canonical proof digest. Downstream services (soland) trust this event as
the only attestation that this agent is bound to this human principal.

## `cx.account.issue_session_grant` — agent branch

When an agent presents itself for a session grant, coauth runs an
additional gate beyond the human-session checks:

1. Resolve the agent principal's FSM state from soland's `agent_state` cell
   (mirrored locally for freshness).
2. If state == `Paused`, reject with `agent_paused`. The grant is NOT
   issued; the caller MUST resume the agent before retrying.
3. If state == `Deactivated`, reject with `agent_deactivated`. Terminal —
   do not retry without rebinding under a new agent DID.
4. If no `accountability_grant` is on file linking the human principal to
   the agent at session-issue time, reject with
   `accountability_grant_missing`. Common cause: human principal's
   accountability grant was revoked while a stale agent token was in
   flight.

### Error matrix

| Error | When | Recovery |
|---|---|---|
| `agent_paused` | Agent FSM = Paused | Operator resumes the agent (POST /agents/{id}/resume in soland), then retry |
| `agent_deactivated` | Agent FSM = Deactivated (terminal) | Bind a new agent under a new DID; old agent cannot recover |
| `accountability_grant_missing` | No matching `accountable_to` chain at grant time | Re-issue the accountability grant from the human principal; retry session |
| `pairing_request_expired` | 10-min pairing window elapsed | Re-issue `cx.account.agent_key_pair` |
| `proof_invalid` | Pairing proof canonical-bytes mismatch | Inspect client serializer; resubmit |
| `verification_method_principal_mismatch` | Pairing `verification_method` resolves to a different DID | Fix DID document; resubmit |

## Revocation freshness window

The agent FSM and the accountability grant chain live in soland but are
mirrored into coauth so that session-grant decisions don't make a synchronous
upstream call per request. The mirror has a **freshness window** of 60s by
default (configurable via
`auth.agent.revocation_freshness_window`).

If a state change (pause / deactivate / accountability-grant revoke) is
issued at soland at `t = 0`, coauth MUST refuse to issue a session grant
based on stale data older than `t - freshness_window`.

Mechanics:

- Each mirror record carries a `mirrored_at` timestamp from coauth's local
  clock when it was last refreshed.
- Session-grant evaluation reads the record AND verifies
  `now - mirrored_at <= freshness_window`. If stale, coauth synchronously
  refreshes the mirror before deciding.
- Synchronous refresh failures within the freshness window behave fail-closed
  — the session grant is rejected with the corresponding `agent_*` or
  `accountability_grant_missing` error and the failure is logged for ops
  triage.

When tuning the freshness window:

- Smaller window → tighter revocation propagation, more upstream traffic.
- Larger window → looser propagation guarantee, lower upstream load.
- The strict-reject deployment posture (see
  [Deployment hardening](./deployment_hardening.md)) typically pins the
  freshness window <= 30s.
