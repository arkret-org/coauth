-- Constrain `users.preferred_locale` to the set the product can actually
-- render.
--
-- The column has always been plain TEXT and every write path passed the
-- client's string through untouched, so rows exist holding region variants
-- (`zh-CN`, `zh-Hans`) and, in principle, languages no catalogue covers. That
-- made the column unusable as the source of truth for a user's language: a
-- reader could not tell whether a value would resolve to a real dictionary.
--
-- Normalise first, then constrain, in one transaction. Diesel runs each
-- migration in a transaction, so the CHECK can never see the pre-normalised
-- rows.

-- 1. Fold region and script variants onto the base language. `zh-CN`,
--    `zh_TW` and `zh-Hans` all select the same Simplified Chinese catalogue,
--    which is the behaviour every client already had.
UPDATE users
SET preferred_locale = 'zh'
WHERE preferred_locale IS NOT NULL
  AND lower(preferred_locale) ~ '^zh([-_].*)?$';

UPDATE users
SET preferred_locale = 'en'
WHERE preferred_locale IS NOT NULL
  AND lower(preferred_locale) ~ '^en([-_].*)?$';

-- 2. Anything left names a language this deployment does not ship, or is
--    blank. Clear it rather than guess: NULL means "no stated preference", so
--    the user falls back to their browser's language — the same experience
--    they had, since no catalogue could satisfy the old value either.
--
--    Preserve what was there. A stored preference is a statement the user
--    made, and dropping it with no record would make an operator's "why did
--    my language reset?" unanswerable. This table is small and the column is
--    written rarely, so keeping the originals costs almost nothing.
CREATE TABLE IF NOT EXISTS users_preferred_locale_migration_audit (
    user_id     UUID        NOT NULL,
    old_value   TEXT        NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, recorded_at)
);

COMMENT ON TABLE users_preferred_locale_migration_audit IS
    'Values cleared from users.preferred_locale when the column was constrained to the shipped locale set (migration 20260801000000). Retained so a reset preference can be explained; safe to drop once reviewed.';

INSERT INTO users_preferred_locale_migration_audit (user_id, old_value)
SELECT id, preferred_locale
FROM users
WHERE preferred_locale IS NOT NULL
  AND preferred_locale NOT IN ('en', 'zh');

UPDATE users
SET preferred_locale = NULL
WHERE preferred_locale IS NOT NULL
  AND preferred_locale NOT IN ('en', 'zh');

-- 3. From here the column is a controlled set. A future writer that bypasses
--    the application's parser fails loudly instead of quietly reintroducing a
--    value nothing can render.
ALTER TABLE users
    ADD CONSTRAINT users_preferred_locale_shipped
    CHECK (preferred_locale IS NULL OR preferred_locale IN ('en', 'zh'));
