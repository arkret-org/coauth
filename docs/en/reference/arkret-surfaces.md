# Arkret surface rules

Constraints that apply across the `/_arkret/*` surfaces. The full
operation catalogue lives in the matching `arkret-spec/spec/v1/`
revision; this page records the rules `coauth` enforces locally.

## Third-party invites

3PID out-of-band invites never carry plaintext email addresses or phone
numbers. The wire form is either `offline_token` (`token_commitment`,
`token_salt_id`, `token_entropy_bits`) or `lookup` (`lookup_table_ref`,
`pepper_id`). See [Account lifecycle](../account-lifecycle.md) for the
claim strand and its rejection codes.

## DID parsing

`Did` rejects any identifier whose method-name segment falls
outside `^did:[a-z0-9]+:[^\s]+$`. The same shape is enforced as a
database `CHECK` constraint on every stored DID column, so a value that
bypasses the handler still cannot land in storage.
