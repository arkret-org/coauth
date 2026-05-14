-- Initial consolidated schema for coauth
-- This migration creates all tables from scratch for a fresh installation.

-- ── Users ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    locked_at TIMESTAMPTZ,
    can_request_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_guest BOOLEAN NOT NULL DEFAULT FALSE,
    deactivated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_passwords (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    hashed_password TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    version INTEGER NOT NULL,
    upgraded_from_id UUID REFERENCES user_passwords(id)
);

CREATE TABLE IF NOT EXISTS user_emails (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    user_agent TEXT,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET
);

CREATE TABLE IF NOT EXISTS user_registration_tokens (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    usage_limit INTEGER,
    times_used INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- ── Upstream OAuth ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS upstream_oauth_providers (
    id UUID PRIMARY KEY,
    issuer TEXT,
    scope TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret TEXT,
    token_endpoint_signing_alg TEXT,
    token_endpoint_auth_method TEXT NOT NULL,
    jwks_uri_override TEXT,
    authorization_endpoint_override TEXT,
    token_endpoint_override TEXT,
    discovery_mode TEXT NOT NULL DEFAULT 'oidc',
    pkce_mode TEXT NOT NULL DEFAULT 'auto',
    human_name TEXT,
    brand_name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    claims_imports JSONB,
    disabled_at TIMESTAMPTZ,
    additional_parameters JSONB,
    fetch_userinfo BOOLEAN NOT NULL DEFAULT FALSE,
    userinfo_endpoint_override TEXT,
    response_mode TEXT,
    extra_callback_parameters JSONB,
    ui_order INTEGER NOT NULL DEFAULT 0,
    id_token_signed_response_alg TEXT NOT NULL DEFAULT 'RS256',
    userinfo_signed_response_alg TEXT,
    on_backchannel_logout TEXT,
    forward_login_hint BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS upstream_oauth_links (
    id UUID PRIMARY KEY,
    upstream_oauth_provider_id UUID NOT NULL REFERENCES upstream_oauth_providers(id),
    user_id UUID REFERENCES users(id),
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    human_account_name TEXT,
    unlinked_at TIMESTAMPTZ,
    UNIQUE (upstream_oauth_provider_id, subject)
);

CREATE TABLE IF NOT EXISTS upstream_oauth_authorization_sessions (
    id UUID PRIMARY KEY,
    upstream_oauth_provider_id UUID NOT NULL REFERENCES upstream_oauth_providers(id),
    upstream_oauth_link_id UUID REFERENCES upstream_oauth_links(id),
    id_token TEXT,
    state TEXT NOT NULL UNIQUE,
    code_challenge_verifier TEXT,
    nonce TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    id_token_claims JSONB,
    userinfo JSONB,
    extra_callback_parameters JSONB,
    unlinked_at TIMESTAMPTZ,
    user_session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL
);

-- ── Email / Phone authentication ────────────────────────────────

CREATE TABLE IF NOT EXISTS user_email_authentications (
    id UUID PRIMARY KEY,
    user_session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    user_registration_id UUID, -- FK added after user_registrations created
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_email_authentication_codes (
    id UUID PRIMARY KEY,
    user_email_authentication_id UUID NOT NULL REFERENCES user_email_authentications(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_email_authentication_id, code)
);

CREATE TABLE IF NOT EXISTS user_phone_authentications (
    id UUID PRIMARY KEY,
    user_registration_id UUID, -- FK added after user_registrations created
    phone TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_phone_authentication_codes (
    id UUID PRIMARY KEY,
    user_phone_authentication_id UUID NOT NULL REFERENCES user_phone_authentications(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- ── User registrations ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_registrations (
    id UUID PRIMARY KEY,
    ip_address INET,
    user_agent TEXT,
    post_auth_action JSONB,
    handle TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    terms_url TEXT,
    email_authentication_id UUID REFERENCES user_email_authentications(id) ON DELETE SET NULL,
    hashed_password TEXT,
    hashed_password_version INTEGER,
    user_registration_token_id UUID REFERENCES user_registration_tokens(id) ON DELETE SET NULL,
    upstream_oauth_authorization_session_id UUID REFERENCES upstream_oauth_authorization_sessions(id) ON DELETE SET NULL,
    phone_authentication_id UUID REFERENCES user_phone_authentications(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

-- Add FK from email/phone auth to registrations
ALTER TABLE user_email_authentications
    ADD CONSTRAINT fk_email_auth_registration
    FOREIGN KEY (user_registration_id) REFERENCES user_registrations(id) ON DELETE CASCADE;

ALTER TABLE user_phone_authentications
    ADD CONSTRAINT fk_phone_auth_registration
    FOREIGN KEY (user_registration_id) REFERENCES user_registrations(id) ON DELETE CASCADE;

-- ── Session authentication ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_session_authentications (
    id UUID PRIMARY KEY,
    user_session_id UUID NOT NULL REFERENCES user_sessions(id),
    user_password_id UUID REFERENCES user_passwords(id),
    upstream_oauth_authorization_session_id UUID REFERENCES upstream_oauth_authorization_sessions(id),
    created_at TIMESTAMPTZ NOT NULL,
    authentication_source TEXT
);

-- ── Recovery ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_recovery_sessions (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address INET,
    locale TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_recovery_tickets (
    id UUID PRIMARY KEY,
    user_recovery_session_id UUID NOT NULL REFERENCES user_recovery_sessions(id) ON DELETE CASCADE,
    user_email_id UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
    ticket TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- ── Terms / Phones / Third-party IDs ────────────────────────────

CREATE TABLE IF NOT EXISTS user_terms (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    terms_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, terms_url)
);

CREATE TABLE IF NOT EXISTS user_phones (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS user_unsupported_third_party_ids (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, medium, address)
);

-- ── OAuth ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY,
    encrypted_client_secret TEXT,
    grant_type_authorization_code BOOLEAN NOT NULL,
    grant_type_refresh_token BOOLEAN NOT NULL,
    grant_type_client_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    grant_type_device_code BOOLEAN,
    client_name TEXT,
    logo_uri TEXT,
    client_uri TEXT,
    policy_uri TEXT,
    tos_uri TEXT,
    jwks_uri TEXT,
    jwks JSONB,
    id_token_signed_response_alg TEXT,
    token_endpoint_auth_method TEXT,
    token_endpoint_auth_signing_alg TEXT,
    initiate_login_uri TEXT,
    userinfo_signed_response_alg TEXT,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    application_type TEXT,
    contacts TEXT[] NOT NULL DEFAULT '{}',
    is_static BOOLEAN,
    created_at TIMESTAMPTZ,
    metadata_digest TEXT UNIQUE
);

-- Localised counterparts for the OIDC `*#<locale>` metadata fields. The
-- non-localised columns on `oauth_clients` (above) carry the default value;
-- this table holds variants keyed by BCP-47 locale tag.
--
-- Field names match the JSON keys defined in OIDC Core 1.0 §2 / Dynamic
-- Client Registration §2 and are limited to a small allow-list to keep the
-- schema simple. Adding more is a one-line check constraint change.
CREATE TABLE IF NOT EXISTS oauth_client_localized_metadata (
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    locale TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (client_id, locale, field),
    CONSTRAINT oauth_client_localized_metadata_field_check
        CHECK (field IN ('client_name', 'logo_uri', 'client_uri', 'policy_uri', 'tos_uri'))
);

CREATE INDEX IF NOT EXISTS oauth_client_localized_metadata_client_idx
    ON oauth_client_localized_metadata (client_id);

CREATE TABLE IF NOT EXISTS oauth_sessions (
    id UUID PRIMARY KEY,
    user_session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    oauth_client_id UUID NOT NULL REFERENCES oauth_clients(id),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_list TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    user_agent TEXT,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET,
    human_name TEXT
);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id UUID PRIMARY KEY,
    oauth_session_id UUID NOT NULL REFERENCES oauth_sessions(id),
    access_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    first_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id UUID PRIMARY KEY,
    oauth_session_id UUID NOT NULL REFERENCES oauth_sessions(id),
    oauth_access_token_id UUID REFERENCES oauth_access_tokens(id) ON DELETE SET NULL,
    refresh_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    next_oauth_refresh_token_id UUID REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS oauth_authorization_grants (
    id UUID PRIMARY KEY,
    oauth_client_id UUID NOT NULL REFERENCES oauth_clients(id),
    oauth_session_id UUID REFERENCES oauth_sessions(id),
    authorization_code TEXT UNIQUE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT,
    nonce TEXT,
    response_mode TEXT NOT NULL DEFAULT 'query',
    code_challenge_method TEXT,
    code_challenge TEXT,
    response_type_code BOOLEAN NOT NULL,
    response_type_id_token BOOLEAN NOT NULL,
    requires_consent BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    fulfilled_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    exchanged_at TIMESTAMPTZ,
    login_hint TEXT,
    locale TEXT
);

CREATE TABLE IF NOT EXISTS oauth_device_code_grant (
    id UUID PRIMARY KEY,
    oauth_client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    device_code TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    fulfilled_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    exchanged_at TIMESTAMPTZ,
    oauth_session_id UUID REFERENCES oauth_sessions(id) ON DELETE CASCADE,
    user_session_id UUID REFERENCES user_sessions(id),
    ip_address INET,
    user_agent TEXT
);

-- ── Queue system ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS queue_workers (
    id UUID PRIMARY KEY,
    registered_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    shutdown_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS queue_schedules (
    schedule_name TEXT PRIMARY KEY,
    last_scheduled_at TIMESTAMPTZ,
    last_scheduled_job_id UUID
);

CREATE TABLE IF NOT EXISTS queue_jobs (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'available',
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    started_by UUID REFERENCES queue_workers(id),
    completed_at TIMESTAMPTZ,
    queue_name TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    failed_at TIMESTAMPTZ,
    failed_reason TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    next_attempt_id UUID REFERENCES queue_jobs(id),
    scheduled_at TIMESTAMPTZ,
    schedule_name TEXT REFERENCES queue_schedules(schedule_name)
);

-- FK from schedules back to jobs
ALTER TABLE queue_schedules
    ADD CONSTRAINT fk_schedule_last_job
    FOREIGN KEY (last_scheduled_job_id) REFERENCES queue_jobs(id);

CREATE UNLOGGED TABLE IF NOT EXISTS queue_leader (
    active BOOLEAN NOT NULL DEFAULT TRUE UNIQUE,
    elected_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    queue_worker_id UUID NOT NULL REFERENCES queue_workers(id)
);

-- ── Personal sessions ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS personal_sessions (
    id UUID PRIMARY KEY,
    owner_user_id UUID REFERENCES users(id),
    owner_oauth_client_id UUID REFERENCES oauth_clients(id),
    actor_user_id UUID NOT NULL REFERENCES users(id),
    human_name TEXT NOT NULL,
    scope_list TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET
);

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id UUID PRIMARY KEY,
    personal_session_id UUID NOT NULL REFERENCES personal_sessions(id),
    access_token_sha256 BYTEA NOT NULL UNIQUE CHECK (length(access_token_sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- ── Policy data ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_data (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
);

-- ── Notification persistence ───────────────────────────────────

CREATE TABLE IF NOT EXISTS notification_requests (
    id UUID PRIMARY KEY,
    template_key TEXT NOT NULL,
    locale TEXT NOT NULL,
    source JSONB NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    dedupe_key TEXT NULL,
    correlation_key TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    scheduled_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL
);

CREATE INDEX notification_requests_status_scheduled_idx
    ON notification_requests (status, scheduled_at, id);

CREATE UNIQUE INDEX notification_requests_dedupe_key_idx
    ON notification_requests (dedupe_key)
    WHERE dedupe_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id UUID PRIMARY KEY,
    notification_request_id UUID NOT NULL REFERENCES notification_requests (id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    destination JSONB NOT NULL,
    provider_binding_key TEXT NULL,
    provider_message_id TEXT NULL,
    attempt_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_failure JSONB NULL,
    created_at TIMESTAMPTZ NOT NULL,
    reserved_at TIMESTAMPTZ NULL,
    sent_at TIMESTAMPTZ NULL,
    delivered_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,
    next_retry_at TIMESTAMPTZ NULL
);

CREATE INDEX notification_deliveries_request_idx
    ON notification_deliveries (notification_request_id, id);

CREATE INDEX notification_deliveries_status_retry_idx
    ON notification_deliveries (status, next_retry_at, created_at, id);

CREATE INDEX notification_deliveries_provider_binding_idx
    ON notification_deliveries (provider_binding_key)
    WHERE provider_binding_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS notification_event_logs (
    id UUID PRIMARY KEY,
    notification_request_id UUID NOT NULL REFERENCES notification_requests (id) ON DELETE CASCADE,
    notification_delivery_id UUID NULL REFERENCES notification_deliveries (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor JSONB NOT NULL,
    summary TEXT NULL,
    metadata JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX notification_event_logs_request_idx
    ON notification_event_logs (notification_request_id, id);

CREATE INDEX notification_event_logs_delivery_idx
    ON notification_event_logs (notification_delivery_id, id)
    WHERE notification_delivery_id IS NOT NULL;

-- ── Workflow engine ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS workflow_instances (
    id UUID PRIMARY KEY,
    workflow_key TEXT NOT NULL,
    subject JSONB NOT NULL,
    trigger JSONB NOT NULL,
    status TEXT NOT NULL,
    current_step_key TEXT NULL,
    input JSONB NOT NULL,
    context JSONB NOT NULL DEFAULT '{}',
    correlation_key TEXT NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_instances_key_status_idx
    ON workflow_instances (workflow_key, status);

CREATE INDEX workflow_instances_correlation_key_idx
    ON workflow_instances (correlation_key)
    WHERE correlation_key IS NOT NULL;

CREATE INDEX workflow_instances_status_expires_idx
    ON workflow_instances (status, expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS workflow_steps (
    id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (id) ON DELETE CASCADE,
    step_key TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    status TEXT NOT NULL,
    assignee JSONB NULL,
    input JSONB NOT NULL,
    output JSONB NULL,
    attempt_count INTEGER NOT NULL,
    last_error_code TEXT NULL,
    last_error_message TEXT NULL,
    scheduled_at TIMESTAMPTZ NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_steps_instance_sequence_idx
    ON workflow_steps (workflow_instance_id, sequence);

CREATE TABLE IF NOT EXISTS workflow_events (
    id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (id) ON DELETE CASCADE,
    workflow_step_id UUID NULL REFERENCES workflow_steps (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor JSONB NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_events_instance_idx
    ON workflow_events (workflow_instance_id, id);

CREATE TABLE IF NOT EXISTS workflow_deadlines (
    id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (id) ON DELETE CASCADE,
    workflow_step_id UUID NULL REFERENCES workflow_steps (id) ON DELETE CASCADE,
    deadline_key TEXT NOT NULL,
    status TEXT NOT NULL,
    payload JSONB NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    satisfied_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_deadlines_status_due_idx
    ON workflow_deadlines (status, due_at);

CREATE TABLE IF NOT EXISTS workflow_audit_logs (
    id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (id) ON DELETE CASCADE,
    workflow_step_id UUID NULL REFERENCES workflow_steps (id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor JSONB NOT NULL,
    summary TEXT NULL,
    metadata JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_audit_logs_instance_idx
    ON workflow_audit_logs (workflow_instance_id, id);

-- ── Audit ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin_operation_logs (
    id UUID PRIMARY KEY,
    admin_user_id UUID NOT NULL,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NULL,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX admin_operation_logs_user_created_idx
    ON admin_operation_logs (admin_user_id, created_at);

CREATE INDEX admin_operation_logs_resource_idx
    ON admin_operation_logs (resource_type, resource_id)
    WHERE resource_id IS NOT NULL;

CREATE INDEX admin_operation_logs_created_idx
    ON admin_operation_logs (created_at);

CREATE TABLE IF NOT EXISTS account_security_events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    ip_address INET NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX account_security_events_user_created_idx
    ON account_security_events (user_id, created_at);

CREATE INDEX account_security_events_type_created_idx
    ON account_security_events (event_type, created_at);

-- Consolidated from 20260331000100_profile_patch_refactor/up.sql
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS display_name TEXT NULL,
    ADD COLUMN IF NOT EXISTS avatar_url TEXT NULL,
    ADD COLUMN IF NOT EXISTS preferred_locale TEXT NULL;

UPDATE users
SET updated_at = created_at
WHERE updated_at IS NULL OR updated_at = NOW();

ALTER TABLE user_emails
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE user_emails
SET
    updated_at = created_at,
    confirmed_at = COALESCE(confirmed_at, created_at)
WHERE updated_at IS NULL OR updated_at = NOW() OR confirmed_at IS NULL;

WITH ranked_emails AS (
    SELECT
        id,
        ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at ASC, id ASC) AS rn
    FROM user_emails
)
UPDATE user_emails
SET is_primary = ranked_emails.rn = 1
FROM ranked_emails
WHERE user_emails.id = ranked_emails.id;

ALTER TABLE upstream_oauth_links
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE upstream_oauth_links
SET updated_at = created_at
WHERE updated_at IS NULL OR updated_at = NOW();

CREATE TABLE IF NOT EXISTS notification_preferences (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS notification_preferences_user_channel_idx
    ON notification_preferences (user_id, channel);

-- Consolidated from 20260401000100_add_user_totp/up.sql
CREATE TABLE IF NOT EXISTS user_totp_configs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA1',
    digits INTEGER NOT NULL DEFAULT 6,
    period INTEGER NOT NULL DEFAULT 30,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT user_totp_configs_user_id_unique UNIQUE (user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_totp_configs_user_id ON user_totp_configs(user_id);

-- Consolidated from 20260401000200_add_notification_template_versions/up.sql
CREATE TABLE IF NOT EXISTS notification_template_versions (
    id UUID PRIMARY KEY,
    template_key TEXT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    channel TEXT NOT NULL,
    locale TEXT NOT NULL DEFAULT 'en',
    subject_template TEXT,
    body_template TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS notification_template_versions_key_version_channel_idx
    ON notification_template_versions (template_key, version, channel);

CREATE INDEX IF NOT EXISTS notification_template_versions_key_channel_idx
    ON notification_template_versions (template_key, channel);

-- Consolidated from 20260407000100_upstream_oauth_provider_source/up.sql
-- Track the origin of an upstream OAuth provider row so the admin REST API
-- and the configuration-file sync can co-exist without overwriting each other.
--
-- Allowed values:
--   'config' -- the row was created/updated by `coauth config sync` from the
--               configuration file. The admin API may disable/enable it but
--               not edit fields or hard-delete it (delete is only possible
--               once it has been removed from the configuration file and
--               soft-disabled by a subsequent sync run).
--   'manual' -- the row was created via the admin REST API. Sync ignores it.
ALTER TABLE upstream_oauth_providers
    ADD COLUMN source TEXT NOT NULL DEFAULT 'config';

-- Existing rows pre-date the admin CRUD endpoints and were necessarily
-- created by config sync, so the default backfill is correct.

-- Consolidated from 20260420000100_notification_delivery_provider_lookup/up.sql
CREATE UNIQUE INDEX notification_deliveries_provider_message_lookup
    ON notification_deliveries (provider_binding_key, provider_message_id)
    WHERE provider_binding_key IS NOT NULL
      AND provider_message_id IS NOT NULL;

-- Consolidated from 20260429000100_session_grants/up.sql
CREATE TABLE IF NOT EXISTS oauth_session_grants (
    id UUID PRIMARY KEY,
    user_session_id UUID NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    device_id TEXT,
    audience TEXT NOT NULL,
    scope_list TEXT[] NOT NULL,
    grant_jwt TEXT NOT NULL,
    session_public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth_session_grants_user_session_idx
    ON oauth_session_grants(user_session_id);

CREATE INDEX IF NOT EXISTS oauth_session_grants_subject_idx
    ON oauth_session_grants(subject);

CREATE UNIQUE INDEX IF NOT EXISTS oauth_session_grants_grant_jwt_idx
    ON oauth_session_grants(grant_jwt);

CREATE INDEX IF NOT EXISTS oauth_session_grants_device_id_idx
    ON oauth_session_grants(device_id)
    WHERE device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS oauth_session_grants_active_idx
    ON oauth_session_grants(expires_at)
    WHERE revoked_at IS NULL;

-- Consolidated from 20260506000200_account_claims/up.sql
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

-- Consolidated from 20260509000100_invite_quarantine_queue/up.sql
-- Outbox queue for batch_invite consent-gate `Quarantined` outcomes.
-- Persisted from `crates/backend/src/services/invite_quarantine.rs` and
-- consumed by `crates/backend/src/handlers/admin/v1/invite_quarantine.rs`.
--
-- See coauth/_todos.md `TODO(c10e-quarantine-outbox)`.
CREATE TABLE IF NOT EXISTS invite_quarantine_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    peer_did TEXT NOT NULL,
    target_holder_did TEXT NOT NULL,
    consent_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    requesting_admin_did TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_at TIMESTAMPTZ,
    resolution_note TEXT,
    CONSTRAINT invite_quarantine_queue_peer_did_non_empty CHECK (btrim(peer_did) <> ''),
    CONSTRAINT invite_quarantine_queue_target_holder_did_non_empty CHECK (btrim(target_holder_did) <> ''),
    CONSTRAINT invite_quarantine_queue_consent_id_non_empty CHECK (btrim(consent_id) <> ''),
    CONSTRAINT invite_quarantine_queue_scope_non_empty CHECK (btrim(scope) <> ''),
    CONSTRAINT invite_quarantine_queue_status_known CHECK (status IN ('pending', 'approved', 'rejected'))
);

CREATE INDEX IF NOT EXISTS invite_quarantine_queue_status_created_idx
    ON invite_quarantine_queue(status, created_at DESC);

CREATE INDEX IF NOT EXISTS invite_quarantine_queue_holder_did_idx
    ON invite_quarantine_queue(target_holder_did);

CREATE INDEX IF NOT EXISTS invite_quarantine_queue_consent_id_idx
    ON invite_quarantine_queue(consent_id);

-- Consolidated from 20260509000200_risk_action_proposals/up.sql
CREATE TABLE IF NOT EXISTS risk_action_proposals (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    proposer_did TEXT NOT NULL,
    reason TEXT NOT NULL,
    ticket TEXT,
    state TEXT NOT NULL DEFAULT 'draft',
    approval_proofs JSONB NOT NULL DEFAULT '[]'::JSONB,
    required_approvals INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    CONSTRAINT risk_action_proposals_action_non_empty
        CHECK (btrim(action) <> ''),
    CONSTRAINT risk_action_proposals_proposer_did_non_empty
        CHECK (btrim(proposer_did) <> ''),
    CONSTRAINT risk_action_proposals_reason_non_empty
        CHECK (btrim(reason) <> ''),
    CONSTRAINT risk_action_proposals_state_valid
        CHECK (state IN ('draft', 'approved', 'executed', 'cancelled', 'rejected')),
    CONSTRAINT risk_action_proposals_required_approvals_positive
        CHECK (required_approvals >= 1)
);

CREATE INDEX IF NOT EXISTS risk_action_proposals_account_idx
    ON risk_action_proposals(account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS risk_action_proposals_state_idx
    ON risk_action_proposals(state);

-- Consolidated from 20260509000300_webauthn_credentials/up.sql
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

-- Consolidated from 20260510000100_oauth_clients_i18n/up.sql
-- OAuth client display-name + description, indexed by BCP-47 locale tag.
--
-- This is a separate concern from `oauth_client_localized_metadata`: that
-- table backs the OIDC `*#<locale>` metadata fields (client_name, logo_uri,
-- client_uri, policy_uri, tos_uri) which are restricted to the published
-- spec. The new `i18n` column carries free-form admin-curated translations
-- of the client's display name and a longer description, surfaced on the
-- consent screen for end-users.
--
-- Shape:
--   {"<locale>": {"display_name": "...", "description": "..."}, ...}
--
-- The default `'{}'::jsonb` keeps existing rows valid — the consent screen
-- falls back to `oauth_clients.client_name` when no entry exists for the
-- requested locale.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS i18n JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Consolidated from 20260510000200_account_starid_backend_marker/up.sql
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
