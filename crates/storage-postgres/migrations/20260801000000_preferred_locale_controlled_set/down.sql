-- Drop the constraint and restore the values this migration cleared.
--
-- The normalisation of `zh-CN` → `zh` is deliberately NOT reversed: the two
-- selected the same catalogue, so restoring the region suffix would only
-- reintroduce the ambiguity without changing any user's experience.

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_preferred_locale_shipped;

UPDATE users u
SET preferred_locale = a.old_value
FROM (
    SELECT DISTINCT ON (user_id) user_id, old_value
    FROM users_preferred_locale_migration_audit
    ORDER BY user_id, recorded_at DESC
) a
WHERE u.id = a.user_id
  AND u.preferred_locale IS NULL;

DROP TABLE IF EXISTS users_preferred_locale_migration_audit;
