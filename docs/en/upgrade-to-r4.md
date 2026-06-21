# Upgrade to Round R4

Round R4 closes the 2026-05-20 protocol review work in `coauth` and
the Cokret protocol. It is wire-breaking for clients or downstream
services that consume Cokret account, identity, invite, or policy
surfaces directly. OIDC/OAuth endpoints remain on their normal
compatibility track.

Read this page before enabling a build that includes the R4 changes.

## Breaking surfaces

- **3PID OOB invites** no longer carry plaintext email addresses or
  phone numbers. The wire form is either `offline_token`
  (`token_commitment`, `token_salt_id`, `token_entropy_bits`) or
  `lookup` (`lookup_table_ref`, `pepper_id`).
- **Invite claims** use a two-proof chain: a verification-service
  proof for the verified 3PID and a subject proof signed by the
  inviter actor key.
- **`ck.cross_signing.publish`** is now compare-and-swap. Publishers
  must read the current generation and submit
  `expected_previous_generation`; accepted generations advance by
  exactly one.
- **`/policy/check` v2** uses `PolicyCheckRequestBody` and returns a
  `PolicyCheckOutcome` with `bound_to`, frontier digests, and a
  DID-keyed signature envelope.
- **`identity_link`** payloads are bound to both `realm_id` and
  `trust_domain`.
- **DID parsing** rejects method names outside the tightened
  `^did:[a-z0-9]+:[^\s]+$` shape.

Use the release notes attached to the build and the matching
`cokret-spec/spec/v1/` revision for the complete R4 change list.

## Trust domain rotation

`cokret.trust_domain` is part of the canonical transcript for every
`ck.cross_signing.reset` proof. Changing it invalidates reset proofs
that were issued under the previous trust domain.

Before rotating:

1. Record the current configured value and confirm it matches
   `/_cokret/describe`.
2. Pause or reject in-flight cross-signing reset approvals minted under
   the old value.
3. Snapshot the database and keep the previous config alongside the
   snapshot.
4. Coordinate with Principal Server operators so they reject stale
   reset proofs after the cutover.

During rotation:

1. Set the new value in `cokret.trust_domain`.
2. Restart one `coauth` replica and verify `/_cokret/describe`
   advertises the new value.
3. Roll the remaining replicas.
4. Reissue reset proofs through the device recovery strand. The affected
   proof families are `principal_signing`, `recovery_unlock`,
   `device_quorum`, and `trusted_recovery_service`.
5. Publish fresh cross-signing generations after the new proofs are
   available.

Do not replay old reset proofs into the new trust domain. They must fail
because their canonical transcript was signed for a different
deployment scope.

## Invite claim migration

Clients that claim 3PID invites must send both:

- the verification-service proof, signed by the configured 3PID
  verification service; and
- the subject proof, signed by the inviter actor key and linked to the
  verification proof `jti`.

Expired proofs return `proof_expired`. Reused verification proof `jti`
values are rejected as replay attempts. A subject proof presented by a
different actor is rejected as `subject_did_mismatch`.

## Rollback

R4 schema migrations are forward-only. If the rollout must be reversed,
restore the pre-upgrade database snapshot and the matching pre-upgrade
configuration. Do not assume that toggling `trust_domain` back and forth
will safely revive proofs produced during the failed rollout.
