CREATE TABLE accountability_grants (
    id UUID PRIMARY KEY,
    accountability_grant_id TEXT NOT NULL UNIQUE,
    agent_principal_id TEXT NOT NULL,
    controller_did TEXT NOT NULL,
    capabilities TEXT[] NOT NULL,
    capabilities_digest TEXT NOT NULL,
    reason TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    raw_payload_digest TEXT NOT NULL,
    soland_fanout_state TEXT NOT NULL,
    soland_fanout_idempotency_key TEXT NOT NULL UNIQUE,
    soland_fanout_payload JSONB NOT NULL,
    soland_fanout_attempt INT NOT NULL DEFAULT 0,
    soland_fanout_next_retry_at TIMESTAMPTZ,
    soland_fanout_dead_letter_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX accountability_grants_active_fingerprint_idx
    ON accountability_grants (agent_principal_id, controller_did, capabilities_digest)
    WHERE revoked_at IS NULL;

CREATE INDEX accountability_grants_controller_active_idx
    ON accountability_grants (controller_did, issued_at)
    WHERE revoked_at IS NULL;

CREATE INDEX accountability_grants_agent_active_idx
    ON accountability_grants (agent_principal_id, issued_at)
    WHERE revoked_at IS NULL;

CREATE INDEX accountability_grants_revoked_idx
    ON accountability_grants (revoked_at)
    WHERE revoked_at IS NOT NULL;

CREATE TABLE accountability_subject_revocations (
    id UUID PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (subject_kind, subject_id)
);

CREATE INDEX accountability_subject_revocations_subject_idx
    ON accountability_subject_revocations (subject_kind, subject_id, revoked_at);
