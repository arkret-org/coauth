-- Track the origin of an upstream OAuth provider row so the admin REST API
-- and the configuration-file sync can co-exist without overwriting each other.
--
-- Allowed values:
--   'config' -- the row was created/updated by `coauth config sync` from the
--               configuration file. The admin API may disable/enable it but
--               not edit fields or hard-delete it (delete is only possible
--               once it has been removed from the configuration file and
--               soft-disabled by a subsequent sync run).
--   'manual' -- the row was created via the admin REST API. Sync ignores it.
ALTER TABLE upstream_oauth_providers
    ADD COLUMN source TEXT NOT NULL DEFAULT 'config';

-- Existing rows pre-date the admin CRUD endpoints and were necessarily
-- created by config sync, so the default backfill is correct.
