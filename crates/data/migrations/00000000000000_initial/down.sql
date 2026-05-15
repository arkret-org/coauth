-- Consolidated from 20260515000001_add_principal_did_update_keys/down.sql
DROP TABLE IF EXISTS principal_did_update_keys;

-- Consolidated from 20260510000200_account_starid_backend_marker/down.sql
ALTER TABLE users
    DROP COLUMN IF EXISTS starid_backend;

-- Consolidated from 20260510000100_oauth_clients_i18n/down.sql
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS i18n;

-- Consolidated from 20260509000300_webauthn_credentials/down.sql
DROP TABLE IF EXISTS webauthn_credentials;

-- Consolidated from 20260509000200_risk_action_proposals/down.sql
DROP TABLE IF EXISTS risk_action_proposals;

-- Consolidated from 20260509000100_invite_quarantine_queue/down.sql
DROP TABLE IF EXISTS invite_quarantine_queue;

-- Consolidated from 20260506000200_account_claims/down.sql
DROP TABLE IF EXISTS account_claims;

-- Consolidated from 20260429000100_session_grants/down.sql
DROP TABLE IF EXISTS oauth_session_grants;

-- Consolidated from 20260420000100_notification_delivery_provider_lookup/down.sql
DROP INDEX IF EXISTS notification_deliveries_provider_message_lookup;

-- Consolidated from 20260407000100_upstream_oauth_provider_source/down.sql
ALTER TABLE upstream_oauth_providers DROP COLUMN source;

-- Consolidated from 20260401000200_add_notification_template_versions/down.sql
DROP TABLE IF EXISTS notification_template_versions;

-- Consolidated from 20260401000100_add_user_totp/down.sql
DROP TABLE IF EXISTS user_totp_configs;

-- Consolidated from 20260331000100_profile_patch_refactor/down.sql
DROP TABLE IF EXISTS notification_preferences;

ALTER TABLE upstream_oauth_links
    DROP COLUMN IF EXISTS updated_at;

ALTER TABLE user_emails
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS confirmed_at,
    DROP COLUMN IF EXISTS is_primary;

ALTER TABLE users
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS display_name,
    DROP COLUMN IF EXISTS avatar_url,
    DROP COLUMN IF EXISTS preferred_locale;

-- This migration drops all tables. Only use in development.
DROP TABLE IF EXISTS account_security_events CASCADE;
DROP TABLE IF EXISTS admin_operation_logs CASCADE;
DROP TABLE IF EXISTS workflow_audit_logs CASCADE;
DROP TABLE IF EXISTS workflow_deadlines CASCADE;
DROP TABLE IF EXISTS workflow_events CASCADE;
DROP TABLE IF EXISTS workflow_steps CASCADE;
DROP TABLE IF EXISTS workflow_instances CASCADE;
DROP TABLE IF EXISTS notification_event_logs CASCADE;
DROP TABLE IF EXISTS notification_deliveries CASCADE;
DROP TABLE IF EXISTS notification_requests CASCADE;
DROP TABLE IF EXISTS personal_access_tokens CASCADE;
DROP TABLE IF EXISTS personal_sessions CASCADE;
DROP TABLE IF EXISTS queue_leader CASCADE;
DROP TABLE IF EXISTS queue_jobs CASCADE;
DROP TABLE IF EXISTS queue_schedules CASCADE;
DROP TABLE IF EXISTS queue_workers CASCADE;
DROP TABLE IF EXISTS policy_data CASCADE;
DROP TABLE IF EXISTS oauth_device_code_grant CASCADE;
DROP TABLE IF EXISTS oauth_authorization_grants CASCADE;
DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS oauth_access_tokens CASCADE;
DROP TABLE IF EXISTS oauth_sessions CASCADE;
DROP TABLE IF EXISTS oauth_client_localized_metadata CASCADE;
DROP TABLE IF EXISTS oauth_clients CASCADE;
DROP TABLE IF EXISTS user_unsupported_third_party_ids CASCADE;
DROP TABLE IF EXISTS user_phones CASCADE;
DROP TABLE IF EXISTS user_terms CASCADE;
DROP TABLE IF EXISTS user_recovery_tickets CASCADE;
DROP TABLE IF EXISTS user_recovery_sessions CASCADE;
DROP TABLE IF EXISTS user_session_authentications CASCADE;
DROP TABLE IF EXISTS user_registrations CASCADE;
DROP TABLE IF EXISTS user_phone_authentication_codes CASCADE;
DROP TABLE IF EXISTS user_phone_authentications CASCADE;
DROP TABLE IF EXISTS user_email_authentication_codes CASCADE;
DROP TABLE IF EXISTS user_email_authentications CASCADE;
DROP TABLE IF EXISTS upstream_oauth_authorization_sessions CASCADE;
DROP TABLE IF EXISTS upstream_oauth_links CASCADE;
DROP TABLE IF EXISTS upstream_oauth_providers CASCADE;
DROP TABLE IF EXISTS user_registration_tokens CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS user_emails CASCADE;
DROP TABLE IF EXISTS user_passwords CASCADE;
DROP TABLE IF EXISTS users CASCADE;
