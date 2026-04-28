// @generated automatically by Diesel CLI.
// This file represents the current database schema used by Diesel's query
// builder.
#![allow(missing_docs)]

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        locked_at -> Nullable<Timestamptz>,
        can_request_admin -> Bool,
        is_guest -> Bool,
        deactivated_at -> Nullable<Timestamptz>,
        display_name -> Nullable<Text>,
        avatar_url -> Nullable<Text>,
        preferred_locale -> Nullable<Text>,
    }
}

diesel::table! {
    user_passwords (id) {
        id -> Uuid,
        user_id -> Uuid,
        hashed_password -> Text,
        created_at -> Timestamptz,
        version -> Int4,
        upgraded_from_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    user_emails (id) {
        id -> Uuid,
        user_id -> Uuid,
        email -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        confirmed_at -> Nullable<Timestamptz>,
        is_primary -> Bool,
    }
}

diesel::table! {
    user_email_authentications (id) {
        id -> Uuid,
        user_session_id -> Nullable<Uuid>,
        user_registration_id -> Nullable<Uuid>,
        email -> Text,
        created_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_email_authentication_codes (id) {
        id -> Uuid,
        user_email_authentication_id -> Uuid,
        code -> Text,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    user_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        created_at -> Timestamptz,
        finished_at -> Nullable<Timestamptz>,
        user_agent -> Nullable<Text>,
        last_active_at -> Nullable<Timestamptz>,
        last_active_ip -> Nullable<Inet>,
    }
}

diesel::table! {
    user_session_authentications (id) {
        id -> Uuid,
        user_session_id -> Uuid,
        user_password_id -> Nullable<Uuid>,
        upstream_oauth_authorization_session_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
        authentication_source -> Nullable<Text>,
    }
}

diesel::table! {
    user_recovery_sessions (id) {
        id -> Uuid,
        email -> Text,
        user_agent -> Text,
        ip_address -> Nullable<Inet>,
        locale -> Text,
        created_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_recovery_tickets (id) {
        id -> Uuid,
        user_recovery_session_id -> Uuid,
        user_email_id -> Uuid,
        ticket -> Text,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    user_terms (id) {
        id -> Uuid,
        user_id -> Uuid,
        terms_url -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_registrations (id) {
        id -> Uuid,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
        post_auth_action -> Nullable<Jsonb>,
        username -> Text,
        display_name -> Nullable<Text>,
        avatar_url -> Nullable<Text>,
        terms_url -> Nullable<Text>,
        email_authentication_id -> Nullable<Uuid>,
        hashed_password -> Nullable<Text>,
        hashed_password_version -> Nullable<Int4>,
        user_registration_token_id -> Nullable<Uuid>,
        upstream_oauth_authorization_session_id -> Nullable<Uuid>,
        phone_authentication_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_registration_tokens (id) {
        id -> Uuid,
        token -> Text,
        usage_limit -> Nullable<Int4>,
        times_used -> Int4,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_phones (id) {
        id -> Uuid,
        user_id -> Uuid,
        phone -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_phone_authentications (id) {
        id -> Uuid,
        user_registration_id -> Nullable<Uuid>,
        phone -> Text,
        created_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_phone_authentication_codes (id) {
        id -> Uuid,
        user_phone_authentication_id -> Uuid,
        code -> Text,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    user_unsupported_third_party_ids (user_id, medium, address) {
        user_id -> Uuid,
        medium -> Text,
        address -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth2_clients (id) {
        id -> Uuid,
        encrypted_client_secret -> Nullable<Text>,
        grant_type_authorization_code -> Bool,
        grant_type_refresh_token -> Bool,
        grant_type_client_credentials -> Bool,
        grant_type_device_code -> Nullable<Bool>,
        client_name -> Nullable<Text>,
        logo_uri -> Nullable<Text>,
        client_uri -> Nullable<Text>,
        policy_uri -> Nullable<Text>,
        tos_uri -> Nullable<Text>,
        jwks_uri -> Nullable<Text>,
        jwks -> Nullable<Jsonb>,
        id_token_signed_response_alg -> Nullable<Text>,
        token_endpoint_auth_method -> Nullable<Text>,
        token_endpoint_auth_signing_alg -> Nullable<Text>,
        initiate_login_uri -> Nullable<Text>,
        userinfo_signed_response_alg -> Nullable<Text>,
        redirect_uris -> Array<Text>,
        application_type -> Nullable<Text>,
        contacts -> Array<Text>,
        is_static -> Nullable<Bool>,
        created_at -> Nullable<Timestamptz>,
        metadata_digest -> Nullable<Text>,
    }
}

diesel::table! {
    oauth2_client_localized_metadata (client_id, locale, field) {
        client_id -> Uuid,
        locale -> Text,
        field -> Text,
        value -> Text,
    }
}

diesel::table! {
    oauth2_sessions (id) {
        id -> Uuid,
        user_session_id -> Nullable<Uuid>,
        oauth2_client_id -> Uuid,
        user_id -> Nullable<Uuid>,
        scope_list -> Array<Text>,
        created_at -> Timestamptz,
        finished_at -> Nullable<Timestamptz>,
        user_agent -> Nullable<Text>,
        last_active_at -> Nullable<Timestamptz>,
        last_active_ip -> Nullable<Inet>,
        human_name -> Nullable<Text>,
    }
}

diesel::table! {
    oauth2_access_tokens (id) {
        id -> Uuid,
        oauth2_session_id -> Uuid,
        access_token -> Text,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        first_used_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth2_refresh_tokens (id) {
        id -> Uuid,
        oauth2_session_id -> Uuid,
        oauth2_access_token_id -> Nullable<Uuid>,
        refresh_token -> Text,
        created_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        next_oauth2_refresh_token_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    oauth2_authorization_grants (id) {
        id -> Uuid,
        oauth2_client_id -> Uuid,
        oauth2_session_id -> Nullable<Uuid>,
        authorization_code -> Nullable<Text>,
        redirect_uri -> Text,
        scope -> Text,
        state -> Nullable<Text>,
        nonce -> Nullable<Text>,
        response_mode -> Text,
        code_challenge_method -> Nullable<Text>,
        code_challenge -> Nullable<Text>,
        response_type_code -> Bool,
        response_type_id_token -> Bool,
        requires_consent -> Bool,
        created_at -> Timestamptz,
        fulfilled_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
        exchanged_at -> Nullable<Timestamptz>,
        login_hint -> Nullable<Text>,
        locale -> Nullable<Text>,
    }
}

diesel::table! {
    oauth2_device_code_grant (id) {
        id -> Uuid,
        oauth2_client_id -> Uuid,
        scope -> Text,
        user_code -> Text,
        device_code -> Text,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        fulfilled_at -> Nullable<Timestamptz>,
        rejected_at -> Nullable<Timestamptz>,
        exchanged_at -> Nullable<Timestamptz>,
        oauth2_session_id -> Nullable<Uuid>,
        user_session_id -> Nullable<Uuid>,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
    }
}

diesel::table! {
    upstream_oauth_providers (id) {
        id -> Uuid,
        issuer -> Nullable<Text>,
        scope -> Text,
        client_id -> Text,
        encrypted_client_secret -> Nullable<Text>,
        token_endpoint_signing_alg -> Nullable<Text>,
        token_endpoint_auth_method -> Text,
        jwks_uri_override -> Nullable<Text>,
        authorization_endpoint_override -> Nullable<Text>,
        token_endpoint_override -> Nullable<Text>,
        discovery_mode -> Text,
        pkce_mode -> Text,
        human_name -> Nullable<Text>,
        brand_name -> Nullable<Text>,
        created_at -> Timestamptz,
        claims_imports -> Nullable<Jsonb>,
        disabled_at -> Nullable<Timestamptz>,
        additional_parameters -> Nullable<Jsonb>,
        fetch_userinfo -> Bool,
        userinfo_endpoint_override -> Nullable<Text>,
        response_mode -> Nullable<Text>,
        extra_callback_parameters -> Nullable<Jsonb>,
        ui_order -> Int4,
        id_token_signed_response_alg -> Text,
        userinfo_signed_response_alg -> Nullable<Text>,
        on_backchannel_logout -> Nullable<Text>,
        forward_login_hint -> Bool,
        source -> Text,
    }
}

diesel::table! {
    upstream_oauth_links (id) {
        id -> Uuid,
        upstream_oauth_provider_id -> Uuid,
        user_id -> Nullable<Uuid>,
        subject -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        human_account_name -> Nullable<Text>,
        unlinked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    notification_preferences (id) {
        id -> Uuid,
        user_id -> Uuid,
        channel -> Text,
        enabled -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    upstream_oauth_authorization_sessions (id) {
        id -> Uuid,
        upstream_oauth_provider_id -> Uuid,
        upstream_oauth_link_id -> Nullable<Uuid>,
        id_token -> Nullable<Text>,
        state -> Text,
        code_challenge_verifier -> Nullable<Text>,
        nonce -> Nullable<Text>,
        created_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
        consumed_at -> Nullable<Timestamptz>,
        id_token_claims -> Nullable<Jsonb>,
        user_session_id -> Nullable<Uuid>,
        extra_callback_parameters -> Nullable<Jsonb>,
        userinfo -> Nullable<Jsonb>,
        unlinked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    queue_workers (id) {
        id -> Uuid,
        registered_at -> Timestamptz,
        last_seen_at -> Timestamptz,
        shutdown_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    queue_leader (active) {
        active -> Bool,
        elected_at -> Timestamptz,
        expires_at -> Timestamptz,
        queue_worker_id -> Uuid,
    }
}

diesel::table! {
    queue_jobs (id) {
        id -> Uuid,
        status -> Text,
        created_at -> Timestamptz,
        started_at -> Nullable<Timestamptz>,
        started_by -> Nullable<Uuid>,
        completed_at -> Nullable<Timestamptz>,
        queue_name -> Text,
        payload -> Jsonb,
        metadata -> Jsonb,
        failed_at -> Nullable<Timestamptz>,
        failed_reason -> Nullable<Text>,
        attempt -> Int4,
        next_attempt_id -> Nullable<Uuid>,
        scheduled_at -> Nullable<Timestamptz>,
        schedule_name -> Nullable<Text>,
    }
}

diesel::table! {
    queue_schedules (schedule_name) {
        schedule_name -> Text,
        last_scheduled_at -> Nullable<Timestamptz>,
        last_scheduled_job_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    personal_sessions (id) {
        id -> Uuid,
        owner_user_id -> Nullable<Uuid>,
        owner_oauth2_client_id -> Nullable<Uuid>,
        actor_user_id -> Uuid,
        human_name -> Text,
        scope_list -> Array<Text>,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        last_active_at -> Nullable<Timestamptz>,
        last_active_ip -> Nullable<Inet>,
    }
}

diesel::table! {
    personal_access_tokens (id) {
        id -> Uuid,
        personal_session_id -> Uuid,
        access_token_sha256 -> Bytea,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    policy_data (id) {
        id -> Uuid,
        created_at -> Timestamptz,
        data -> Jsonb,
    }
}

diesel::table! {
    notification_requests (id) {
        id -> Uuid,
        template_key -> Text,
        locale -> Text,
        source -> Jsonb,
        payload -> Jsonb,
        status -> Text,
        dedupe_key -> Nullable<Text>,
        correlation_key -> Nullable<Text>,
        created_at -> Timestamptz,
        scheduled_at -> Timestamptz,
        started_at -> Nullable<Timestamptz>,
        completed_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    notification_deliveries (id) {
        id -> Uuid,
        notification_request_id -> Uuid,
        channel -> Text,
        destination -> Jsonb,
        provider_binding_key -> Nullable<Text>,
        provider_message_id -> Nullable<Text>,
        attempt_count -> Int4,
        status -> Text,
        last_failure -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        reserved_at -> Nullable<Timestamptz>,
        sent_at -> Nullable<Timestamptz>,
        delivered_at -> Nullable<Timestamptz>,
        failed_at -> Nullable<Timestamptz>,
        next_retry_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    notification_event_logs (id) {
        id -> Uuid,
        notification_request_id -> Uuid,
        notification_delivery_id -> Nullable<Uuid>,
        kind -> Text,
        actor -> Jsonb,
        summary -> Nullable<Text>,
        metadata -> Jsonb,
        occurred_at -> Timestamptz,
    }
}

diesel::table! {
    workflow_instances (id) {
        id -> Uuid,
        workflow_key -> Text,
        subject -> Jsonb,
        trigger -> Jsonb,
        status -> Text,
        current_step_key -> Nullable<Text>,
        input -> Jsonb,
        context -> Jsonb,
        correlation_key -> Nullable<Text>,
        started_at -> Nullable<Timestamptz>,
        completed_at -> Nullable<Timestamptz>,
        failed_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    workflow_steps (id) {
        id -> Uuid,
        workflow_instance_id -> Uuid,
        step_key -> Text,
        sequence -> Int4,
        status -> Text,
        assignee -> Nullable<Jsonb>,
        input -> Jsonb,
        output -> Nullable<Jsonb>,
        attempt_count -> Int4,
        last_error_code -> Nullable<Text>,
        last_error_message -> Nullable<Text>,
        scheduled_at -> Nullable<Timestamptz>,
        started_at -> Nullable<Timestamptz>,
        completed_at -> Nullable<Timestamptz>,
        failed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    workflow_events (id) {
        id -> Uuid,
        workflow_instance_id -> Uuid,
        workflow_step_id -> Nullable<Uuid>,
        kind -> Text,
        actor -> Jsonb,
        payload -> Jsonb,
        occurred_at -> Timestamptz,
    }
}

diesel::table! {
    workflow_deadlines (id) {
        id -> Uuid,
        workflow_instance_id -> Uuid,
        workflow_step_id -> Nullable<Uuid>,
        deadline_key -> Text,
        status -> Text,
        payload -> Jsonb,
        due_at -> Timestamptz,
        satisfied_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    workflow_audit_logs (id) {
        id -> Uuid,
        workflow_instance_id -> Uuid,
        workflow_step_id -> Nullable<Uuid>,
        action -> Text,
        actor -> Jsonb,
        summary -> Nullable<Text>,
        metadata -> Jsonb,
        occurred_at -> Timestamptz,
    }
}

diesel::table! {
    admin_operation_logs (id) {
        id -> Uuid,
        admin_user_id -> Uuid,
        operation -> Text,
        resource_type -> Text,
        resource_id -> Nullable<Uuid>,
        details -> Jsonb,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    account_security_events (id) {
        id -> Uuid,
        user_id -> Uuid,
        event_type -> Text,
        metadata -> Jsonb,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_totp_configs (id) {
        id -> Uuid,
        user_id -> Uuid,
        secret -> Text,
        algorithm -> Text,
        digits -> Int4,
        period -> Int4,
        confirmed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    notification_template_versions (id) {
        id -> Uuid,
        template_key -> Text,
        version -> Int4,
        channel -> Text,
        locale -> Text,
        subject_template -> Nullable<Text>,
        body_template -> Text,
        created_at -> Timestamptz,
        published_at -> Nullable<Timestamptz>,
    }
}

// Foreign key relationships
diesel::joinable!(user_totp_configs -> users (user_id));
diesel::joinable!(user_passwords -> users (user_id));
diesel::joinable!(user_emails -> users (user_id));
diesel::joinable!(user_sessions -> users (user_id));
diesel::joinable!(user_terms -> users (user_id));
diesel::joinable!(user_phones -> users (user_id));
diesel::joinable!(notification_preferences -> users (user_id));
diesel::joinable!(user_email_authentication_codes -> user_email_authentications (user_email_authentication_id));
diesel::joinable!(user_phone_authentication_codes -> user_phone_authentications (user_phone_authentication_id));
diesel::joinable!(user_recovery_tickets -> user_recovery_sessions (user_recovery_session_id));
diesel::joinable!(user_recovery_tickets -> user_emails (user_email_id));
diesel::joinable!(oauth2_sessions -> oauth2_clients (oauth2_client_id));
diesel::joinable!(oauth2_access_tokens -> oauth2_sessions (oauth2_session_id));
diesel::joinable!(oauth2_authorization_grants -> oauth2_clients (oauth2_client_id));
diesel::joinable!(oauth2_device_code_grant -> oauth2_clients (oauth2_client_id));
diesel::joinable!(oauth2_client_localized_metadata -> oauth2_clients (client_id));
diesel::joinable!(upstream_oauth_links -> upstream_oauth_providers (upstream_oauth_provider_id));
diesel::joinable!(upstream_oauth_authorization_sessions -> upstream_oauth_providers (upstream_oauth_provider_id));
diesel::joinable!(personal_access_tokens -> personal_sessions (personal_session_id));
diesel::joinable!(queue_leader -> queue_workers (queue_worker_id));
diesel::joinable!(notification_deliveries -> notification_requests (notification_request_id));
diesel::joinable!(notification_event_logs -> notification_requests (notification_request_id));
diesel::joinable!(notification_event_logs -> notification_deliveries (notification_delivery_id));
diesel::joinable!(workflow_steps -> workflow_instances (workflow_instance_id));
diesel::joinable!(workflow_events -> workflow_instances (workflow_instance_id));
diesel::joinable!(workflow_events -> workflow_steps (workflow_step_id));
diesel::joinable!(workflow_deadlines -> workflow_instances (workflow_instance_id));
diesel::joinable!(workflow_deadlines -> workflow_steps (workflow_step_id));
diesel::joinable!(workflow_audit_logs -> workflow_instances (workflow_instance_id));
diesel::joinable!(workflow_audit_logs -> workflow_steps (workflow_step_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    user_passwords,
    user_totp_configs,
    user_emails,
    user_email_authentications,
    user_email_authentication_codes,
    user_sessions,
    user_session_authentications,
    user_recovery_sessions,
    user_recovery_tickets,
    user_terms,
    user_registrations,
    user_registration_tokens,
    user_phones,
    user_phone_authentications,
    user_phone_authentication_codes,
    user_unsupported_third_party_ids,
    oauth2_clients,
    oauth2_client_localized_metadata,
    oauth2_sessions,
    oauth2_access_tokens,
    oauth2_refresh_tokens,
    oauth2_authorization_grants,
    oauth2_device_code_grant,
    upstream_oauth_providers,
    upstream_oauth_links,
    upstream_oauth_authorization_sessions,
    queue_workers,
    queue_leader,
    queue_jobs,
    queue_schedules,
    personal_sessions,
    personal_access_tokens,
    policy_data,
    notification_requests,
    notification_deliveries,
    notification_event_logs,
    notification_preferences,
    notification_template_versions,
    admin_operation_logs,
    account_security_events,
    workflow_instances,
    workflow_steps,
    workflow_events,
    workflow_deadlines,
    workflow_audit_logs,
);
