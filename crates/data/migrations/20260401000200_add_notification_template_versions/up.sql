CREATE TABLE IF NOT EXISTS notification_template_versions (
    id UUID PRIMARY KEY,
    template_key TEXT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    channel TEXT NOT NULL,
    locale TEXT NOT NULL DEFAULT 'en',
    subject_template TEXT,
    body_template TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS notification_template_versions_key_version_channel_idx
    ON notification_template_versions (template_key, version, channel);

CREATE INDEX IF NOT EXISTS notification_template_versions_key_channel_idx
    ON notification_template_versions (template_key, channel);
