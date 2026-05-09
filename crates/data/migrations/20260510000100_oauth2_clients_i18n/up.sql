-- OAuth2 client display-name + description, indexed by BCP-47 locale tag.
--
-- This is a separate concern from `oauth2_client_localized_metadata`: that
-- table backs the OIDC `*#<locale>` metadata fields (client_name, logo_uri,
-- client_uri, policy_uri, tos_uri) which are restricted to the published
-- spec. The new `i18n` column carries free-form admin-curated translations
-- of the client's display name and a longer description, surfaced on the
-- consent screen for end-users.
--
-- Shape:
--   {"<locale>": {"display_name": "...", "description": "..."}, ...}
--
-- The default `'{}'::jsonb` keeps existing rows valid — the consent screen
-- falls back to `oauth2_clients.client_name` when no entry exists for the
-- requested locale.

ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS i18n JSONB NOT NULL DEFAULT '{}'::jsonb;
