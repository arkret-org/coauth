# Account Lifecycle

`coauth` separates local account status from invitation state. Local
account status controls whether an authenticated account may continue
using the service. Third-party invite state controls whether an
out-of-band invite may still be claimed.

## Local account status

Admin APIs expose account status as one of:

- `active`: the account may sign in and use enabled account features.
- `locked`: the account exists, but interactive access is blocked until
  an administrator or recovery workflow unlocks it.
- `disabled`: the account is deactivated and should not be treated as
  a usable login subject.

These states are surfaced on the admin account record and are intended
for operator action, audit views, and UI gating.

## Third-party invite claim flow

Invite claims use the `ak.schema.invite.v1` `third_party_invite`
shape. Plaintext 3PID values, such as email addresses and phone
numbers, are not carried on the wire.

The invite starts in `pending` and then moves to exactly one of five
terminal outcomes:

```text
pending
  -> claimed
  -> send_failed
  -> revoked_by_capability_loss
  -> revoked_by_inviter_left
  -> invalidated_by_rate_limit
```

All five terminal outcomes are final. Once an invite is terminal,
`coauth` schedules the local salt or pepper for zeroization within
24 hours so the invite cannot be replayed.

## Invite wire modes

`offline_token` mode carries a high-entropy token commitment:

- `token_commitment`: SHA-256 commitment of the plaintext token and
  salt.
- `token_salt_id`: opaque local salt identifier.
- `token_entropy_bits`: at least 128 bits.

`lookup` mode carries an opaque lookup reference:

- `lookup_table_ref`: local lookup table reference.
- `pepper_id`: opaque server-side pepper identifier.

In `lookup` mode, three failed lookup attempts move the invite to
`invalidated_by_rate_limit`.

## Claim proof chain

A successful `ak.invite.claim` requires two linked proofs:

1. **Verification-service proof**: a signed JWT from the trusted 3PID
   verification service. `coauth` verifies issuer, audience, subject,
   expiry, not-before, nonce, signature, and replayed `jti`.
2. **Subject proof**: a signed JWS from the inviter actor key. It binds
   the verification proof `jti`, the 3PID hash, the invitee promise DID,
   and expiry. The inviter DID must match the actor presenting the
   claim.

Accepted verification proof `jti` values are remembered until expiry.
A second claim with the same live `jti` is rejected as replay.

## Rejection codes

Invite claim failures map to stable machine-readable codes:

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `verification_proof_invalid` | 401 | Verification-service proof is malformed, unverifiable, has wrong claims, or reuses a live `jti`. |
| `subject_proof_invalid` | 401 | Subject proof is malformed, unverifiable, or not linked to the verification proof. |
| `proof_expired` | 410 | One of the proofs has expired. |
| `subject_did_mismatch` | 403 | The inviter DID in the subject proof differs from the actor presenting the claim. |
