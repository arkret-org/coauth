-- Passkey / WebAuthn credentials registered to a coauth account.
--
-- Scaffold migration: schema only. The matching service / handler is
-- tracked in the cross-project _todos.md (see `coauth: Passkey/WebAuthn`)
-- and will land once the `webauthn-rs` integration is finalised.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key JSONB NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    aaguid UUID,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    label TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS webauthn_credentials_credential_idx
    ON webauthn_credentials(credential_id);

CREATE INDEX IF NOT EXISTS webauthn_credentials_account_idx
    ON webauthn_credentials(account_id, created_at DESC)
    WHERE revoked_at IS NULL;
