CREATE TABLE IF NOT EXISTS user_totp_configs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA1',
    digits INTEGER NOT NULL DEFAULT 6,
    period INTEGER NOT NULL DEFAULT 30,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT user_totp_configs_user_id_unique UNIQUE (user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_totp_configs_user_id ON user_totp_configs(user_id);
