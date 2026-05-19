-- T3.2 Handle claim issuance + handle audit log
--
-- Two changes:
--   1. `users.handle_aliases` — interop aliases such as `acct:<local>@<host>`
--      kept alongside the canonical contrix:// handle URI. Canonical form is
--      derived at read time from `users.handle` (localpart) + the public
--      host name, never persisted directly.
--   2. `handle_audit_log` — append-only history of handle reassignments,
--      revocations, TTL expirations, and detected DID Document
--      `alsoKnownAs` divergence. UPDATE / DELETE blocked by trigger.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS handle_aliases TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

CREATE TABLE IF NOT EXISTS handle_audit_log (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    canonical_handle_uri TEXT,
    handle_aliases TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    old_did TEXT,
    new_did TEXT,
    issuer_service_did TEXT,
    audience TEXT,
    claim_digest TEXT,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    actor_id UUID,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS handle_audit_log_user_idx
    ON handle_audit_log (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS handle_audit_log_event_idx
    ON handle_audit_log (event_type, created_at DESC);

-- Append-only enforcement: no UPDATE / DELETE on the audit table. Inserts
-- are the only operation allowed so the history cannot be rewritten.
CREATE OR REPLACE FUNCTION handle_audit_log_block_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'handle_audit_log is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS handle_audit_log_no_update ON handle_audit_log;
CREATE TRIGGER handle_audit_log_no_update
BEFORE UPDATE ON handle_audit_log
FOR EACH ROW EXECUTE FUNCTION handle_audit_log_block_mutation();

DROP TRIGGER IF EXISTS handle_audit_log_no_delete ON handle_audit_log;
CREATE TRIGGER handle_audit_log_no_delete
BEFORE DELETE ON handle_audit_log
FOR EACH ROW EXECUTE FUNCTION handle_audit_log_block_mutation();
