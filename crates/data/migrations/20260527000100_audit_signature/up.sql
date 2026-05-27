-- P5.3 Audit log signing
--
-- Add a detached signature column to `admin_operation_logs` so each
-- audit row can carry a coauth-signed receipt over its canonical
-- transcript. The column is nullable for now because:
--   * existing rows have no signature, and back-filling requires
--     the operator to re-sign offline (out of scope for this
--     migration);
--   * the write path is rolled out gradually — handlers begin
--     signing one resource_type at a time, and unsigned rows during
--     the rollout window must still INSERT successfully.
--
-- Verification is done by the reader (audit-feed handler), not the
-- database. The column is intentionally `TEXT` (base64url-unpadded
-- of the detached signature bytes) rather than `BYTEA` so it can be
-- emitted directly in JSON without an extra encode step.

ALTER TABLE admin_operation_logs
    ADD COLUMN IF NOT EXISTS audit_signature TEXT NULL;

COMMENT ON COLUMN admin_operation_logs.audit_signature IS
    'Detached signature (base64url-unpadded) over canonical JSON of the row, '
    'signed with the coauth service key. NULL during rollout.';
