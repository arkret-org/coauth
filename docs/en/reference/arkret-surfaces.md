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

Coauth and Coland are independently deployed services. Coauth must never
connect to Coland's database, load its configuration or keys, or link its
business and storage implementation. The previous delegated provider violated
this boundary and has been withdrawn. Its four POST routes (`provision`,
`activate`, `status`, and `present`) return `501 unsupported_feature` until a
separately reviewed network authority closure exists. No authority checks are
removed to continue minting, delivery, or redemption.

Existing encrypted private custody remains in Coauth's own database. The
managed worker only expires locally held material; it neither sends invitation
codes nor queries a foreign authority. Disabling workers also disables this
expiry worker. URL-credential rejection may scrub known local custody without
contacting Coland. Normal account registration, session introspection, logout,
and receipt discovery continue over their existing HTTP channels.

The former governance database configuration is rejected. The test runner no
longer injects a foreign database URL, and old provider results are not accepted
as current native coverage. Shared private HTTP carriers belong to
`arkret-deployment-contracts` in the SDK; they do not register canonical
operations, schemas, or authority evidence.

## DID parsing

`Did` rejects any identifier whose method-name segment falls
outside `^did:[a-z0-9]+:[^\s]+$`. The same shape is enforced as a
database `CHECK` constraint on every stored DID column, so a value that
bypasses the handler still cannot land in storage.
