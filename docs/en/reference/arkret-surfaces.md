# Arkret surface rules

Constraints that apply across the `/_arkret/*` surfaces. The full
operation catalogue lives in the matching `arkret-spec/spec/v1/`
revision; this page records the rules `coauth` enforces locally.

## Third-party invites

Public Realm Events for 3PID invitations never carry plaintext email addresses
or phone numbers. The wire form is either `offline_token` (`token_commitment`,
`token_salt_id`, `token_entropy_bits`) or `lookup` (`lookup_table_ref`,
`pepper_id`). See [Account lifecycle](../account-lifecycle.md) for the
claim flow and its rejection codes.

An explicitly configured owning Station may delegate its verification service
to Coauth. Set `arkret.third_party_invite_provider.governance_database_url` to
that Station's Coland database, and enable the matching Station provider
binding. This connection is separate from Coauth's private database. The
Station DID remains the verification identity; this deployment does not offer
an independent cross-Station provider. A configured email transport and the
managed worker are required. A blackhole transport cannot enable the provider.

The four registered POST routes are `/_arkret/open/third-party-invites/provision`,
`activate`, `status`, and `present`. Their bodies and proofs use the SDK's
registered DTOs and signing transcripts. Provision authentication holds the
current accepted PCR Device authority across the private mint transaction.
It does not use a Principal root key or manufacture a Principal verification
method. Activation verifies the Station's current service identity and the
signed acceptance attestation, then binds the original public material and
delivery intent in one transaction. An exact activation retry returns the first
`activated_at`, including after restart.

Token, per-invitation salt, lookup pepper, temporary signing seed and recipient
URI remain encrypted in Coauth's private durable record. Public outcomes contain
only the frozen invite material and the opaque provisioning credential.
Status never returns a recipient digest or an opening signal. Delivery and
present separately hold the owning Station's current governing invite gate;
withdrawal, allowlist removal or loss of the inviter's authority stops them even
while an earlier activation attestation remains within its signed validity.

Offline codes have at least 128 bits of entropy. Lookup namespaces use a private
HMAC index and become unusable after three wrong suffix attempts. Present is
limited to five requests per minute and fifty per day for each source, subject
and known inviter. URL query/path credentials are rejected before parsing the
body or selecting an operation, and a recognized credential presented directly
to Coauth is invalidated. Failure responses conceal token existence. Successful
present consumes the code once and removes its private redemption material;
this implementation provides no recovery window for a lost proof. The provider
proof uses the frozen per-invitation key, while the subsequent Claim subject
proof keeps the separate, existing native identity control purpose.

The managed worker restores the same encrypted material and delivery intent
after a process restart. It deletes redemption secrets on expiry, withdrawal,
delivery failure or consumption. External transport acknowledgements are not
atomic with the private database, so a crash may cause the same valid code to
be delivered again; it never creates another redeemable code. The canonical
`integration-third-party-invites.sh` suite checks both modes through the standard
HTTP operations, actual delivery, Claim acceptance and controlled process death.

## DID parsing

`Did` rejects any identifier whose method-name segment falls
outside `^did:[a-z0-9]+:[^\s]+$`. The same shape is enforced as a
database `CHECK` constraint on every stored DID column, so a value that
bypasses the handler still cannot land in storage.
