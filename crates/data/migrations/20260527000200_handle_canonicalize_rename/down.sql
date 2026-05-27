-- Revert R3.1 handle wire rename — restore legacy column name.
ALTER TABLE handle_audit_log
    RENAME COLUMN handle TO canonical_handle_uri;
