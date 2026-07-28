# Regression review

## 2026-07-28 — recovery enrollment omitted device possession proof

- Surface: `POST /_arkret/gate/account/device-enroll`, B-model recovery replacement.
- Regression: the recovery request did not carry the new device's possession signature, so Coauth signed an `ak.device.authorize` payload without the recovery-required `device_signature`; Soland's schema gate correctly rejected the atomic recovery batch.
- Detection: real Cotest all-devices-lost browser flow after the recovery proof, DID rotation, and account-authority enrollment request had all succeeded.
- Correction: add a recovery-only possession signature to the canonical request, verify it against the requested device key before Coauth signs the Event, and preserve it in the authority-signed payload.
- Prevention dimension: every authority-authored recovery authorization must be validated against the registered Event payload schema before it is returned and covered by a live cross-service test.
- Status: the overloaded recovery enrollment branch has been removed; the future dedicated
  operation must enforce possession as part of its closed request transcript.

## 2026-07-28 — recovery enrollment trusted an unverified session identifier

- Surface: `POST /_arkret/gate/account/device-enroll`, B-model recovery replacement.
- Regression: after adding the recovery branch, an ordinary authenticated account session could
  supply a `recovery_session_id`; Coauth verified device possession but had no cryptographic or
  S2S evidence that the Principal Server session was verified and bound to the same principal,
  device, policy, generation, plan, and authority audience.
- Detection: cross-service security-boundary self-review against `device-lifecycle.md` §5.4 and
  §15 after the live flow reached authority signing.
- Required correction: replace this overloaded recovery branch with a dedicated recovery
  authorization operation that requires a Principal Server-signed, audience-bound, one-time
  recovery ticket and a fixed idempotent recovery plan. A normal session grant and a bare session
  identifier must never authorize the authority signature.
- Prevention dimension: cross-service security facts must be carried by verifiable, audience-bound
  artifacts; an identifier naming remote state is not evidence of that state.
- Status: the overloaded recovery enrollment branch has been removed. The dedicated ticket-bound
  operation is now specified by the merged P0 protocol contract; its Coauth implementation remains
  pending and must not restore the former `device-enroll` recovery union.
