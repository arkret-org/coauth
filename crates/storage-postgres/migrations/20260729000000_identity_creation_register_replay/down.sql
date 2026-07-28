ALTER TABLE public.identity_creation_leases
    DROP CONSTRAINT IF EXISTS identity_creation_leases_register_ledger_complete,
    DROP CONSTRAINT IF EXISTS identity_creation_leases_register_outcome_object,
    DROP CONSTRAINT IF EXISTS identity_creation_leases_register_request_digest_valid,
    DROP CONSTRAINT IF EXISTS identity_creation_leases_register_challenge_id_valid,
    DROP COLUMN IF EXISTS register_outcome,
    DROP COLUMN IF EXISTS register_request_digest,
    DROP COLUMN IF EXISTS register_challenge_id,
    DROP COLUMN IF EXISTS register_handoff_grant_id,
    DROP COLUMN IF EXISTS register_ledger_legacy;
