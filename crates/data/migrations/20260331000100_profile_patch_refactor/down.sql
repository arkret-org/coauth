DROP TABLE IF EXISTS notification_preferences;

ALTER TABLE upstream_oauth_links
    DROP COLUMN IF EXISTS updated_at;

ALTER TABLE user_emails
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS confirmed_at,
    DROP COLUMN IF EXISTS is_primary;

ALTER TABLE users
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS display_name,
    DROP COLUMN IF EXISTS avatar_url,
    DROP COLUMN IF EXISTS preferred_locale;
