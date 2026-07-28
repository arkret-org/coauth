ALTER TABLE public.identity_creation_leases
    ADD COLUMN register_handoff_grant_id uuid,
    ADD COLUMN register_challenge_id text,
    ADD COLUMN register_request_digest text,
    ADD COLUMN register_outcome jsonb,
    ADD COLUMN register_ledger_legacy boolean NOT NULL DEFAULT false;

-- Bound rows that predate this migration cannot reconstruct the exact
-- register request or outcome. Mark only those existing rows as legacy so
-- future writers cannot create a new Bound row without a replay ledger.
UPDATE public.identity_creation_leases
SET register_ledger_legacy = true
WHERE state = 'bound';

ALTER TABLE public.identity_creation_leases
    ADD CONSTRAINT identity_creation_leases_register_challenge_id_valid
        CHECK (
            register_challenge_id IS NULL
            OR register_challenge_id ~ '^[A-Za-z0-9_-]{22,128}$'
        ),
    ADD CONSTRAINT identity_creation_leases_register_request_digest_valid
        CHECK (
            register_request_digest IS NULL
            OR register_request_digest ~ '^sha256:[0-9a-f]{64}$'
        ),
    ADD CONSTRAINT identity_creation_leases_register_outcome_object
        CHECK (
            register_outcome IS NULL
            OR jsonb_typeof(register_outcome) = 'object'
        ),
    ADD CONSTRAINT identity_creation_leases_register_ledger_complete
        CHECK (
            (
                register_ledger_legacy
                AND state = 'bound'
                AND register_handoff_grant_id IS NULL
                AND register_challenge_id IS NULL
                AND register_request_digest IS NULL
                AND register_outcome IS NULL
            )
            OR (
                NOT register_ledger_legacy
                AND (
                    (
                        state <> 'bound'
                        AND register_handoff_grant_id IS NULL
                        AND register_challenge_id IS NULL
                        AND register_request_digest IS NULL
                        AND register_outcome IS NULL
                    )
                    OR (
                        state = 'bound'
                        AND register_handoff_grant_id IS NOT NULL
                        AND register_challenge_id IS NOT NULL
                        AND register_request_digest IS NOT NULL
                        AND register_outcome IS NOT NULL
                    )
                )
            )
        );
