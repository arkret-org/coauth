-- DID metadata.primary_handle holder preference history.
--
-- A holder preference is versioned instead of stored on `users` so DID
-- resolution can answer "what was preferred at this time?" once the webvh
-- as-of resolver path is wired.

CREATE TABLE IF NOT EXISTS user_primary_handle_preferences (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    handle TEXT,
    effective_at TIMESTAMPTZ NOT NULL,
    replaced_at TIMESTAMPTZ,
    source_claim_id UUID REFERENCES handle_audit_log(id) ON DELETE SET NULL,
    source_claim_digest TEXT,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (replaced_at IS NULL OR replaced_at > effective_at),
    CHECK (
        handle IS NULL
        OR (
            position(':' in handle) > 1
            AND handle = lower(handle)
            AND handle NOT LIKE 'acct:%'
            AND handle NOT LIKE 'cokret://%'
        )
    ),
    CHECK (
        handle IS NULL
        OR (source_claim_id IS NOT NULL AND source_claim_digest IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS user_primary_handle_preferences_current_idx
    ON user_primary_handle_preferences (user_id)
    WHERE replaced_at IS NULL;

CREATE INDEX IF NOT EXISTS user_primary_handle_preferences_as_of_idx
    ON user_primary_handle_preferences (user_id, effective_at DESC);

CREATE INDEX IF NOT EXISTS user_primary_handle_preferences_handle_idx
    ON user_primary_handle_preferences (handle)
    WHERE handle IS NOT NULL;
