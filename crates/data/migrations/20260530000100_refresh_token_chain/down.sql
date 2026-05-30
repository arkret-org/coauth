DROP INDEX IF EXISTS oauth_refresh_tokens_last_seen_idx;
DROP INDEX IF EXISTS oauth_refresh_tokens_chain_root_idx;

ALTER TABLE oauth_refresh_tokens
    DROP COLUMN IF EXISTS last_seen_at,
    DROP COLUMN IF EXISTS chain_created_at,
    DROP COLUMN IF EXISTS chain_root_oauth_refresh_token_id;
