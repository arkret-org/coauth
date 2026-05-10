-- Mark which accounts have a managed `did:webvh` minted by `starid` as
-- their primary principal DID. Historical accounts default to `false`
-- so they keep resolving via the local `did:web:coauth.invalid:…`
-- derivation in `services::did_resolver::DefaultDidResolverService`.
-- Onboarding flips this flag to `true` after `StaridRegistry::create_principal_did`
-- succeeds (see `handlers::flow::stages::user_write`).
--
-- The `DEFAULT FALSE` on the new column is the actual backfill: every
-- pre-existing row gets `false`, which is exactly what we want — no
-- account that pre-dates this migration ever talked to starid, so they
-- all stay on the local DID derivation. New accounts created after this
-- migration ride the boolean: onboarding writes `true` only after
-- `StaridRegistry::create_principal_did` has succeeded.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS starid_backend BOOLEAN NOT NULL DEFAULT FALSE;
