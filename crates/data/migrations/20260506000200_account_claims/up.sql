CREATE TABLE IF NOT EXISTS account_claims (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES users(id) ON DELETE SET NULL,
    claim_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    verifier_did TEXT NOT NULL,
    represented_org TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_claims_claim_type_non_empty CHECK (btrim(claim_type) <> ''),
    CONSTRAINT account_claims_subject_non_empty CHECK (btrim(subject) <> ''),
    CONSTRAINT account_claims_issuer_non_empty CHECK (btrim(issuer) <> ''),
    CONSTRAINT account_claims_verifier_did_non_empty CHECK (btrim(verifier_did) <> ''),
    CONSTRAINT account_claims_represented_org_non_empty CHECK (btrim(represented_org) <> '')
);

CREATE INDEX IF NOT EXISTS account_claims_account_id_issued_idx
    ON account_claims(account_id, issued_at DESC)
    WHERE account_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS account_claims_subject_idx
    ON account_claims(subject);

CREATE INDEX IF NOT EXISTS account_claims_lifecycle_idx
    ON account_claims(revoked_at, expires_at);

CREATE INDEX IF NOT EXISTS account_claims_verifier_did_idx
    ON account_claims(verifier_did);

CREATE INDEX IF NOT EXISTS account_claims_represented_org_idx
    ON account_claims(represented_org);
