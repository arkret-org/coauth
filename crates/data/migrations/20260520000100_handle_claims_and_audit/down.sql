DROP TRIGGER IF EXISTS handle_audit_log_no_delete ON handle_audit_log;
DROP TRIGGER IF EXISTS handle_audit_log_no_update ON handle_audit_log;
DROP FUNCTION IF EXISTS handle_audit_log_block_mutation();
DROP TABLE IF EXISTS handle_audit_log;
ALTER TABLE users DROP COLUMN IF EXISTS handle_aliases;
