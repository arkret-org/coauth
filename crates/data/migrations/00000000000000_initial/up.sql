-- Initial consolidated schema for Pasion
-- This migration creates all tables from scratch for a fresh installation.

-- ── Users ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
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
    username TEXT NOT NULL,
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

-- ── OAuth2 ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS oauth2_clients (
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
-- non-localised columns on `oauth2_clients` (above) carry the default value;
-- this table holds variants keyed by BCP-47 locale tag.
--
-- Field names match the JSON keys defined in OIDC Core 1.0 §2 / Dynamic
-- Client Registration §2 and are limited to a small allow-list to keep the
-- schema simple. Adding more is a one-line check constraint change.
CREATE TABLE IF NOT EXISTS oauth2_client_localized_metadata (
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    locale TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (client_id, locale, field),
    CONSTRAINT oauth2_client_localized_metadata_field_check
        CHECK (field IN ('client_name', 'logo_uri', 'client_uri', 'policy_uri', 'tos_uri'))
);

CREATE INDEX IF NOT EXISTS oauth2_client_localized_metadata_client_idx
    ON oauth2_client_localized_metadata (client_id);

CREATE TABLE IF NOT EXISTS oauth2_sessions (
    id UUID PRIMARY KEY,
    user_session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    oauth2_client_id UUID NOT NULL REFERENCES oauth2_clients(id),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_list TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    user_agent TEXT,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET,
    human_name TEXT
);

CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
    id UUID PRIMARY KEY,
    oauth2_session_id UUID NOT NULL REFERENCES oauth2_sessions(id),
    access_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    first_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
    id UUID PRIMARY KEY,
    oauth2_session_id UUID NOT NULL REFERENCES oauth2_sessions(id),
    oauth2_access_token_id UUID REFERENCES oauth2_access_tokens(id) ON DELETE SET NULL,
    refresh_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    next_oauth2_refresh_token_id UUID REFERENCES oauth2_refresh_tokens(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS oauth2_authorization_grants (
    id UUID PRIMARY KEY,
    oauth2_client_id UUID NOT NULL REFERENCES oauth2_clients(id),
    oauth2_session_id UUID REFERENCES oauth2_sessions(id),
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

CREATE TABLE IF NOT EXISTS oauth2_device_code_grant (
    id UUID PRIMARY KEY,
    oauth2_client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    device_code TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    fulfilled_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    exchanged_at TIMESTAMPTZ,
    oauth2_session_id UUID REFERENCES oauth2_sessions(id) ON DELETE CASCADE,
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
    owner_oauth2_client_id UUID REFERENCES oauth2_clients(id),
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
