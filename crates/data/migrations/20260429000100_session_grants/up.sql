CREATE TABLE IF NOT EXISTS oauth2_session_grants (
    id UUID PRIMARY KEY,
    user_session_id UUID NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    device_id TEXT,
    audience TEXT NOT NULL,
    scope_list TEXT[] NOT NULL,
    grant_jwt TEXT NOT NULL,
    session_public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth2_session_grants_user_session_idx
    ON oauth2_session_grants(user_session_id);

CREATE INDEX IF NOT EXISTS oauth2_session_grants_subject_idx
    ON oauth2_session_grants(subject);

CREATE UNIQUE INDEX IF NOT EXISTS oauth2_session_grants_grant_jwt_idx
    ON oauth2_session_grants(grant_jwt);

CREATE INDEX IF NOT EXISTS oauth2_session_grants_device_id_idx
    ON oauth2_session_grants(device_id)
    WHERE device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS oauth2_session_grants_active_idx
    ON oauth2_session_grants(expires_at)
    WHERE revoked_at IS NULL;
