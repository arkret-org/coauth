# Agent Runtime Status

coauth currently exposes only the internal accountability-grant issuance
surface for agent principals. It does not expose
`ck.gate.account.command.pair_agent_key` or the agent branch of
`ck.gate.account.command.issue_session_grant`.

Until those routes are wired, clients and sodmin must not present them as
available coauth operations. The rejection helpers and error-code matrix remain
in `handlers/account/agents.rs` so future wiring has a single source of truth,
but they are reserved implementation details rather than a callable public API.

## Exposed Surface

### `POST /_coauth/self/agents/{id}/accountability-grant`

This internal CKP-0008 endpoint issues an accountability grant linking a human
controller DID to an agent principal id and a canonical set of `ck.agent.*`
capabilities.

The endpoint is server-to-server only:

- it accepts the soland/sodmin static bearer configured under
  `cokret.principal_servers[].session_grant_introspection_bearer`;
- browser sessions and end-user OAuth tokens are rejected;
- the path `{id}` must be the agent principal DID, percent-encoded as a single
  URL path segment;
- the `controller_did` is normalized before use;
- each requested capability must be registered in the local `ck.agent.*`
  capability registry.

On success coauth persists the accountability grant, writes a signed admin audit
row, and schedules a soland fan-out job. Duplicate active grants for the same
controller, agent, and capability fingerprint are rejected. Previously revoked
controller DIDs or agent principals are also rejected.

## Deferred Surface

### `ck.gate.account.command.pair_agent_key`

This operation is not routed in coauth. No pairing token is created, no key pair
is bound to an agent DID, and no `ck.gate.account.command.pair_agent_key` event is emitted by
the current coauth service.

Reserved failure codes such as `pairing_request_expired`, `proof_invalid`, and
`verification_method_principal_mismatch` describe the future wire contract only.
They are not evidence that a production pairing route exists.

### `ck.gate.account.command.issue_session_grant` agent branch

The agent-principal branch of session-grant issuance is not routed in coauth.
Existing session-grant endpoints do not accept agent-principal issuance
requests, and coauth does not currently evaluate agent FSM state or
accountability-grant freshness for such an issuance path.

Reserved failure codes such as `agent_paused`, `agent_deactivated`, and
`accountability_grant_missing` remain unavailable to external clients until the
agent branch is implemented.

## Wiring Requirements

Before the deferred surface can be exposed, the implementation must add routed
handlers and focused tests for:

- explicit agent DID to verification-method binding before proof validation;
- pairing token lifetime and replay handling;
- agent FSM fail-closed gates for paused and deactivated agents;
- durable accountability-grant freshness checks;
- discovery and documentation updates that publish the new routes only after
  the handlers are live.
