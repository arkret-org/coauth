CREATE TABLE IF NOT EXISTS recovery_principal_cache (
    cache_key TEXT PRIMARY KEY,
    principal_base_url TEXT,
    audience TEXT,
    cache_state JSONB NOT NULL,
    etag TEXT,
    contract_digest TEXT,
    last_refresh_at TIMESTAMPTZ,
    last_invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS recovery_principal_cache_principal_base_url_idx
    ON recovery_principal_cache(principal_base_url)
    WHERE principal_base_url IS NOT NULL;

CREATE INDEX IF NOT EXISTS recovery_principal_cache_contract_digest_idx
    ON recovery_principal_cache(contract_digest)
    WHERE contract_digest IS NOT NULL;

CREATE TABLE IF NOT EXISTS recovery_principal_cache_failure (
    id UUID PRIMARY KEY,
    cache_key TEXT NOT NULL REFERENCES recovery_principal_cache(cache_key) ON DELETE CASCADE,
    failure_code TEXT NOT NULL,
    reason TEXT,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS recovery_principal_cache_failure_cache_key_idx
    ON recovery_principal_cache_failure(cache_key);

CREATE INDEX IF NOT EXISTS recovery_principal_cache_failure_failed_at_idx
    ON recovery_principal_cache_failure(failed_at DESC);

CREATE INDEX IF NOT EXISTS recovery_principal_cache_failure_code_idx
    ON recovery_principal_cache_failure(failure_code);
