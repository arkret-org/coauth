-- Durable OAuth refresh-token rotation chains.
--
-- Existing deployments only stored a forward `next_oauth_refresh_token_id`
-- pointer. This migration adds a stable chain root and last-seen timestamp so
-- reuse detection can revoke a whole chain without relying on session fallback.

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN IF NOT EXISTS chain_root_oauth_refresh_token_id UUID,
    ADD COLUMN IF NOT EXISTS chain_created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

WITH RECURSIVE chains AS (
    SELECT
        rt.id,
        rt.id AS root_id,
        rt.created_at AS root_created_at
    FROM oauth_refresh_tokens rt
    WHERE NOT EXISTS (
        SELECT 1
        FROM oauth_refresh_tokens prev
        WHERE prev.next_oauth_refresh_token_id = rt.id
    )

    UNION ALL

    SELECT
        child.id,
        chains.root_id,
        chains.root_created_at
    FROM chains
    JOIN oauth_refresh_tokens current_token ON current_token.id = chains.id
    JOIN oauth_refresh_tokens child ON child.id = current_token.next_oauth_refresh_token_id
)
UPDATE oauth_refresh_tokens rt
SET
    chain_root_oauth_refresh_token_id = chains.root_id,
    chain_created_at = chains.root_created_at,
    last_seen_at = COALESCE(rt.consumed_at, rt.created_at)
FROM chains
WHERE rt.id = chains.id
  AND (
      rt.chain_root_oauth_refresh_token_id IS NULL
      OR rt.chain_created_at IS NULL
      OR rt.last_seen_at IS NULL
  );

UPDATE oauth_refresh_tokens
SET
    chain_root_oauth_refresh_token_id = COALESCE(chain_root_oauth_refresh_token_id, id),
    chain_created_at = COALESCE(chain_created_at, created_at),
    last_seen_at = COALESCE(last_seen_at, consumed_at, created_at)
WHERE chain_root_oauth_refresh_token_id IS NULL
   OR chain_created_at IS NULL
   OR last_seen_at IS NULL;

ALTER TABLE oauth_refresh_tokens
    ALTER COLUMN chain_root_oauth_refresh_token_id SET NOT NULL,
    ALTER COLUMN chain_created_at SET NOT NULL,
    ALTER COLUMN last_seen_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_chain_root_idx
    ON oauth_refresh_tokens(chain_root_oauth_refresh_token_id);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_last_seen_idx
    ON oauth_refresh_tokens(last_seen_at);
