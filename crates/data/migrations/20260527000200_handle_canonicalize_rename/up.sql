-- R3.1 Handle wire rename (HDLREN-1) — cokret-spec @ 7157ee8 (2026-05-27).
--
-- Spec change: the canonical Cokret handle form is now
-- `<localpart>:<domain>` (e.g. `alice:acme.example`), replacing the
-- legacy URI form `cokret://<domain>/users/<localpart>` that was used
-- when the `handle_audit_log` table was introduced in migration
-- `20260520000100_handle_claims_and_audit`.
--
-- This migration RENAMES the column rather than dropping and
-- recreating it so existing audit rows are preserved verbatim. Any URI
-- strings still stored in pre-existing rows will be left as-is;
-- application code MUST emit the new canonical form for all rows
-- written after this migration applies. Backfilling historical rows
-- into the new shape is out of scope here — `handle_audit_log` is
-- append-only by design and rewriting historical rows would violate
-- the no-UPDATE trigger.

ALTER TABLE handle_audit_log
    RENAME COLUMN canonical_handle_uri TO handle;
