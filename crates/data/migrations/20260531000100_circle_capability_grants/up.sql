CREATE TABLE circle_capability_grants (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    action TEXT NOT NULL,
    allowed_circle_ids TEXT[] NOT NULL DEFAULT '{}',
    granted_by TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX circle_capability_grants_active_fingerprint_idx
    ON circle_capability_grants (subject, realm_id, action, allowed_circle_ids)
    WHERE revoked_at IS NULL;

CREATE INDEX circle_capability_grants_active_realm_subject_idx
    ON circle_capability_grants (realm_id, subject, granted_at)
    WHERE revoked_at IS NULL;

CREATE INDEX circle_capability_grants_revoked_idx
    ON circle_capability_grants (revoked_at)
    WHERE revoked_at IS NOT NULL;
