-- Outbox queue for batch_invite consent-gate `Quarantined` outcomes.
-- Persisted from `crates/backend/src/services/invite_quarantine.rs` and
-- consumed by `crates/backend/src/handlers/admin/v1/invite_quarantine.rs`.
--
-- See coauth/_todos.md `TODO(c10e-quarantine-outbox)`.
CREATE TABLE IF NOT EXISTS invite_quarantine_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    peer_did TEXT NOT NULL,
    target_holder_did TEXT NOT NULL,
    consent_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    requesting_admin_did TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_at TIMESTAMPTZ,
    resolution_note TEXT,
    CONSTRAINT invite_quarantine_queue_peer_did_non_empty CHECK (btrim(peer_did) <> ''),
    CONSTRAINT invite_quarantine_queue_target_holder_did_non_empty CHECK (btrim(target_holder_did) <> ''),
    CONSTRAINT invite_quarantine_queue_consent_id_non_empty CHECK (btrim(consent_id) <> ''),
    CONSTRAINT invite_quarantine_queue_scope_non_empty CHECK (btrim(scope) <> ''),
    CONSTRAINT invite_quarantine_queue_status_known CHECK (status IN ('pending', 'approved', 'rejected'))
);

CREATE INDEX IF NOT EXISTS invite_quarantine_queue_status_created_idx
    ON invite_quarantine_queue(status, created_at DESC);

CREATE INDEX IF NOT EXISTS invite_quarantine_queue_holder_did_idx
    ON invite_quarantine_queue(target_holder_did);

CREATE INDEX IF NOT EXISTS invite_quarantine_queue_consent_id_idx
    ON invite_quarantine_queue(consent_id);
