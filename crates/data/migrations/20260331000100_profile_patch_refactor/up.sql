ALTER TABLE users
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS display_name TEXT NULL,
    ADD COLUMN IF NOT EXISTS avatar_url TEXT NULL,
    ADD COLUMN IF NOT EXISTS preferred_locale TEXT NULL;

UPDATE users
SET updated_at = created_at
WHERE updated_at IS NULL OR updated_at = NOW();

ALTER TABLE user_emails
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE user_emails
SET
    updated_at = created_at,
    confirmed_at = COALESCE(confirmed_at, created_at)
WHERE updated_at IS NULL OR updated_at = NOW() OR confirmed_at IS NULL;

WITH ranked_emails AS (
    SELECT
        id,
        ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at ASC, id ASC) AS rn
    FROM user_emails
)
UPDATE user_emails
SET is_primary = ranked_emails.rn = 1
FROM ranked_emails
WHERE user_emails.id = ranked_emails.id;

ALTER TABLE upstream_oauth_links
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE upstream_oauth_links
SET updated_at = created_at
WHERE updated_at IS NULL OR updated_at = NOW();

CREATE TABLE IF NOT EXISTS notification_preferences (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS notification_preferences_user_channel_idx
    ON notification_preferences (user_id, channel);
