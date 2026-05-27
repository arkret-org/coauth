# Password Reset

The password-reset flow lets an authenticated **owner** of a `coauth`
account regain interactive access when the existing credential
(password or passkey) is lost. It is intentionally narrow: the path
exists for account recovery, not for routine credential rotation, and
all transitions are auditable.

For the high-level sequence diagram see
[Auth flows / Account recovery](../auth-flows.md#account-recovery-passwordless-reset).

## Threat model

The reset path crosses an unauthenticated trust boundary (anyone with
the handle can request a reset). The design assumes:

- The attacker can submit `/recovery/start` requests for arbitrary
  handles.
- The attacker may control the network between the user and `coauth`
  but cannot read the user's primary email.
- The attacker may attempt to replay or steal a leaked reset link.

The reset link alone is therefore **not** sufficient to change a
credential — it is one factor in a multi-factor binding.

## Reset token

When `/recovery/start` succeeds, `coauth` mints a single-use reset
token with the following properties:

| Property              | Value                                  |
| --------------------- | -------------------------------------- |
| Length                | ≥ 256 bits, base64url-unpadded         |
| Stored form           | SHA-256 hash; the token itself is never persisted |
| Expiry                | 15 minutes (configurable, hard cap 60 min) |
| Single-use            | Marked `consumed_at` on first valid POST |
| Bound to issuance IP / UA hash | Verified on consume, soft-fail with audit if mismatched |
| Bound to device fingerprint (passkey reset only) | Hard-fail on mismatch |
| Bound to account `recovery_generation` | Invalidated on credential change, lock, or device-quorum reset |

Tokens are emailed (or sent via the configured 3PID verification
service) as part of a URL that contains the token as a path or query
parameter. The token is **never** logged in plaintext; only the SHA-256
prefix appears in audit records.

## Expiry

- Soft expiry: the relative `expires_in` returned in the response.
- Hard expiry: absolute timestamp persisted in `recovery_tokens.expires_at`.
- On consume, `coauth` rejects tokens past `expires_at` with
  `reset_token_expired` (HTTP 410).

After expiry, the row is retained for 24 hours for audit, then
zeroized.

## Binding to device

For accounts where the only authenticator is a passkey, the reset
**must** be completed on a device that can produce a fresh WebAuthn
assertion against the new credential challenge. This binds the reset
to physical possession of the recovery device and prevents a remote
attacker who phished the email link from completing the reset alone.

For password accounts (legacy / bootstrapping), the binding falls back
to:

1. A device-fingerprint hash captured at `/recovery/start`.
2. A confirmation step that requires the user to authenticate the
   *new* password on the same device before activation.

## Replay protection

| Vector                              | Mitigation                                       |
| ----------------------------------- | ------------------------------------------------ |
| Reuse of consumed token             | `consumed_at` is checked under DB row lock; second POST returns `reset_token_consumed` (409). |
| Reuse of leaked-but-unconsumed token after credential change | `recovery_generation` mismatch on consume; returns `reset_token_invalidated` (409). |
| Reset link harvested from email cache | 15-minute expiry; consume-bound IP/UA delta logged. |
| Concurrent reset requests           | Latest issuance invalidates all prior unconsumed tokens for that account; only one outstanding reset at a time. |
| Race on consume                     | `UPDATE … WHERE consumed_at IS NULL RETURNING …` — only one writer wins. |

## Audit

Every reset transition emits a signed audit row (see
[refresh token rotation](./access-token.md) for the signing model):

- `recovery.requested` — `/recovery/start` accepted; payload omits the
  token, includes hashed handle and issuance IP.
- `recovery.consumed` — token consumed successfully.
- `recovery.failed` — consume rejected; includes reason code.
- `recovery.invalidated` — outstanding token superseded by a newer
  one, a credential change, an account lock, or a device-quorum
  reset.

All four event types are append-only and counted in the Prometheus
`coauth_recovery_events_total{outcome=…}` counter.

## Post-reset side effects

A successful reset:

1. Bumps `recovery_generation`, invalidating any other outstanding
   reset tokens.
2. Revokes every active refresh token chain for the account (forces
   re-login on all devices).
3. Schedules a "your password was reset" notification on the
   configured channels.
4. Records the source device in the audit log for the user's
   self-service activity feed.

## Operator knobs

| Setting                           | Default | Notes                          |
| --------------------------------- | ------- | ------------------------------ |
| `recovery.token_ttl`              | 15m     | Hard cap 60m enforced.         |
| `recovery.fingerprint_required`   | `true`  | Set `false` only for legacy migrations. |
| `recovery.notify_on_request`      | `true`  | Email "we received a reset request" even if no token is sent. |
| `recovery.max_concurrent_tokens`  | 1       | Older tokens are invalidated on new request. |

These map to the `recovery:` block in `config.yaml`.
