-- Rollback of P5.3 audit-signature column.
ALTER TABLE admin_operation_logs
    DROP COLUMN IF EXISTS audit_signature;
