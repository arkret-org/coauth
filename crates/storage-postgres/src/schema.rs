// @generated automatically by Diesel CLI.
// This file represents the current database schema used by Diesel's query
// builder.
#![allow(missing_docs)]

diesel::table! {
    account_status_records (account_authority_id, account_id, status_seq) {
        account_authority_id -> Text,
        account_id -> Text,
        status_seq -> Int8,
        record_id -> Text,
        record -> Jsonb,
        issued_at -> Timestamptz,
    }
}

diesel::table! {
    account_status_ledger_heads (account_authority_id, account_id) {
        account_authority_id -> Text,
        account_id -> Text,
        current_status_seq -> Nullable<Int8>,
        current_record_id -> Nullable<Text>,
    }
}

diesel::table! {
    account_handoff_creation_attempts (request_id) {
        request_id -> Uuid,
        request_digest -> Text,
        canonical_intent_digest -> Text,
        canonical_intent -> Bytea,
        holder_jkt -> Text,
        issuer -> Text,
        client_id -> Text,
        authorization_code_digest -> Text,
        dpop_jti_digest -> Text,
        state -> Text,
        authorization_checkpoint -> Nullable<Jsonb>,
        canonical_outcome -> Nullable<Bytea>,
        outcome_digest -> Nullable<Text>,
        retained_until -> Timestamptz,
        created_at -> Timestamptz,
        authorized_at -> Nullable<Timestamptz>,
        committed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        localpart -> Text,
        status -> Text,
        locked_at -> Nullable<Timestamptz>,
        deactivated_at -> Nullable<Timestamptz>,
        can_request_admin -> Bool,
        display_name -> Nullable<Text>,
        avatar_url -> Nullable<Text>,
        preferred_locale -> Nullable<Text>,
        handle_aliases -> Array<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    handle_audit_log (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        event_type -> Text,
        handle -> Nullable<Text>,
        handle_aliases -> Array<Text>,
        old_did -> Nullable<Text>,
        new_did -> Nullable<Text>,
        issuer_service_id -> Nullable<Text>,
        audience -> Nullable<Text>,
        claim_digest -> Nullable<Text>,
        details -> Jsonb,
        actor_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_primary_handle_preferences (id) {
        id -> Uuid,
        user_id -> Uuid,
        handle -> Nullable<Text>,
        effective_at -> Timestamptz,
        replaced_at -> Nullable<Timestamptz>,
        source_claim_id -> Nullable<Uuid>,
        source_claim_digest -> Nullable<Text>,
        actor_user_id -> Nullable<Uuid>,
        source -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    accountability_grants (id) {
        id -> Uuid,
        accountability_grant_id -> Text,
        agent_id -> Text,
        controller_id -> Text,
        capabilities -> Array<Text>,
        capabilities_digest -> Text,
        reason -> Nullable<Text>,
        issued_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        revoked_reason -> Nullable<Text>,
        raw_payload_digest -> Text,
        soland_fanout_state -> Text,
        soland_fanout_idempotency_key -> Text,
        soland_fanout_payload -> Jsonb,
        soland_fanout_attempt -> Int4,
        soland_fanout_next_retry_at -> Nullable<Timestamptz>,
        soland_fanout_dead_letter_reason -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_key_authorization_collision_variants (id) {
        id -> Uuid,
        authorized_event_id -> Text,
        canonical_preimage -> Bytea,
        envelope -> Jsonb,
        observed_at -> Timestamptz,
    }
}

diesel::table! {
    accountability_subject_revocations (id) {
        id -> Uuid,
        subject_kind -> Text,
        subject_id -> Text,
        reason -> Text,
        revoked_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_key_authorizations (id) {
        id -> Uuid,
        authorized_event_id -> Text,
        agent_id -> Text,
        key_id -> Text,
        verification_method -> Text,
        public_key -> Jsonb,
        accountable_principal_id -> Text,
        agent_key_scope -> Text,
        audience -> Array<Text>,
        issued_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        pairing_request_id -> Text,
        request_canonical_digest -> Text,
        revoked_at -> Nullable<Timestamptz>,
        revoked_reason -> Nullable<Text>,
        quarantined_at -> Nullable<Timestamptz>,
        quarantine_reason -> Nullable<Text>,
        raw_payload_digest -> Text,
        soland_fanout_state -> Text,
        soland_fanout_idempotency_key -> Text,
        soland_fanout_payload -> Jsonb,
        soland_fanout_attempt -> Int4,
        soland_fanout_next_retry_at -> Nullable<Timestamptz>,
        soland_fanout_dead_letter_reason -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_session_proof_replay (id) {
        id -> Uuid,
        agent_id -> Text,
        verification_method -> Text,
        challenge -> Text,
        nonce -> Text,
        request_canonical_digest -> Text,
        audience -> Text,
        consumed_at -> Timestamptz,
        proof_expires_at -> Timestamptz,
        prune_after -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    dpop_jti_replay (jti_digest) {
        jti_digest -> Text,
        seen_at -> Timestamptz,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    verified_did_bindings (did, trust_domain, purpose, policy_digest, verification_method) {
        did -> Text,
        trust_domain -> Text,
        purpose -> Text,
        policy_digest -> Text,
        verification_method -> Text,
        history_head -> Nullable<Text>,
        expires_at -> Nullable<Timestamptz>,
        accepted -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    recovery_completion_grant_issuances (transaction_id) {
        transaction_id -> Text,
        transaction_request_digest -> Text,
        service_account_id -> Uuid,
        principal_id -> Text,
        device_id -> Text,
        device_authorization_event_id -> Text,
        result_model_generation_ref -> Jsonb,
        canonical_request_digest -> Text,
        canonical_request -> Bytea,
        session_grant_operation_id -> Uuid,
        canonical_outcome -> Bytea,
        issued_at -> Timestamptz,
    }
}

diesel::table! {
    circle_capability_grants (id) {
        id -> Uuid,
        subject -> Text,
        realm_id -> Text,
        action -> Text,
        allowed_circle_ids -> Array<Text>,
        granted_by -> Text,
        granted_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    organization_principal_controls (id) {
        id -> Uuid,
        organization_did -> Text,
        principal_control_realm_id -> Text,
        control_stream_ref -> Text,
        pcr_frontier_digest -> Nullable<Text>,
        bootstrap_authorization -> Text,
        bootstrap_delegation_ref -> Nullable<Text>,
        executed_by -> Nullable<Text>,
        bootstrap_proof_digest -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    organization_delegations (id) {
        id -> Uuid,
        delegation_ref -> Text,
        organization_did -> Text,
        delegate_did -> Text,
        issuer_role -> Text,
        purposes -> Array<Text>,
        covered_relationships -> Array<Text>,
        covered_control_scopes -> Array<Text>,
        status -> Text,
        valid_from -> Timestamptz,
        valid_until -> Nullable<Timestamptz>,
        created_by -> Text,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    collaboration_capability_grants (id) {
        id -> Uuid,
        capability_grant_id -> Text,
        grant_event_id -> Text,
        revoke_event_id -> Nullable<Text>,
        subject -> Text,
        realm_id -> Text,
        action -> Text,
        expires_at -> Nullable<Timestamptz>,
        approval_evidence_ref -> Nullable<Text>,
        granted_by -> Text,
        granted_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        grant_raw_payload_digest -> Text,
        grant_fanout_idempotency_key -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_claims (id) {
        id -> Uuid,
        account_id -> Nullable<Uuid>,
        claim_kind -> Text,
        subject -> Text,
        issuer -> Text,
        verifier_did -> Text,
        represented_org -> Text,
        payload -> Jsonb,
        issued_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        revoked_reason -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    webauthn_ceremonies (id) {
        id -> Uuid,
        account_id -> Uuid,
        kind -> Text,
        binding_id -> Text,
        state -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    webauthn_credentials (id) {
        id -> Uuid,
        account_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Jsonb,
        sign_count -> Int8,
        transports -> Array<Text>,
        aaguid -> Nullable<Uuid>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        user_verified -> Bool,
        label -> Nullable<Text>,
        last_used_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    risk_action_proposals (id) {
        id -> Uuid,
        account_id -> Uuid,
        action -> Text,
        proposer_did -> Text,
        reason -> Text,
        ticket -> Nullable<Text>,
        state -> Text,
        approval_proofs -> Jsonb,
        required_approvals -> Int4,
        approved_at -> Nullable<Timestamptz>,
        executed_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    invite_quarantine_queue (id) {
        id -> Uuid,
        peer_did -> Text,
        target_holder_did -> Text,
        consent_id -> Text,
        scope -> Text,
        requesting_admin_did -> Nullable<Text>,
        payload -> Jsonb,
        status -> Text,
        resolved_at -> Nullable<Timestamptz>,
        resolution_note -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_passwords (id) {
        id -> Uuid,
        user_id -> Uuid,
        hashed_password -> Text,
        version -> Int4,
        upgraded_from_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_emails (id) {
        id -> Uuid,
        user_id -> Uuid,
        email -> Text,
        confirmed_at -> Nullable<Timestamptz>,
        is_primary -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_email_authentications (id) {
        id -> Uuid,
        user_session_id -> Nullable<Uuid>,
        user_registration_id -> Nullable<Uuid>,
        email -> Text,
        completed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_email_authentication_codes (id) {
        id -> Uuid,
        user_email_authentication_id -> Uuid,
        code -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        finished_at -> Nullable<Timestamptz>,
        user_agent -> Nullable<Text>,
        last_active_at -> Nullable<Timestamptz>,
        last_active_ip -> Nullable<Inet>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_session_authentications (id) {
        id -> Uuid,
        user_session_id -> Uuid,
        user_password_id -> Nullable<Uuid>,
        upstream_oauth_authorization_session_id -> Nullable<Uuid>,
        webauthn_credential_id -> Nullable<Uuid>,
        authentication_source -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_recovery_sessions (id) {
        id -> Uuid,
        email -> Text,
        user_agent -> Text,
        ip_address -> Nullable<Inet>,
        locale -> Text,
        consumed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_recovery_tickets (id) {
        id -> Uuid,
        user_recovery_session_id -> Uuid,
        user_email_id -> Uuid,
        ticket -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
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
        localpart -> Text,
        display_name -> Nullable<Text>,
        avatar_url -> Nullable<Text>,
        terms_url -> Nullable<Text>,
        email_authentication_id -> Nullable<Uuid>,
        hashed_password -> Nullable<Text>,
        hashed_password_version -> Nullable<Int4>,
        user_registration_token_id -> Nullable<Uuid>,
        upstream_oauth_authorization_session_id -> Nullable<Uuid>,
        phone_authentication_id -> Nullable<Uuid>,
        completed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_registration_tokens (id) {
        id -> Uuid,
        token -> Text,
        usage_limit -> Nullable<Int4>,
        times_used -> Int4,
        last_used_at -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
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
        completed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_phone_authentication_codes (id) {
        id -> Uuid,
        user_phone_authentication_id -> Uuid,
        code -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_clients (id) {
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
        metadata_digest -> Nullable<Text>,
        i18n -> Jsonb,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth_client_localized_metadata (client_id, locale, field) {
        client_id -> Uuid,
        locale -> Text,
        field -> Text,
        value -> Text,
    }
}

diesel::table! {
    oauth_sessions (id) {
        id -> Uuid,
        user_session_id -> Nullable<Uuid>,
        oauth_client_id -> Uuid,
        user_id -> Nullable<Uuid>,
        scope_list -> Array<Text>,
        finished_at -> Nullable<Timestamptz>,
        user_agent -> Nullable<Text>,
        last_active_at -> Nullable<Timestamptz>,
        last_active_ip -> Nullable<Inet>,
        human_name -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_access_tokens (id) {
        id -> Uuid,
        oauth_session_id -> Uuid,
        access_token -> Text,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        first_used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_refresh_tokens (id) {
        id -> Uuid,
        oauth_session_id -> Uuid,
        oauth_access_token_id -> Nullable<Uuid>,
        refresh_token -> Text,
        consumed_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        next_oauth_refresh_token_id -> Nullable<Uuid>,
        chain_root_oauth_refresh_token_id -> Uuid,
        chain_created_at -> Timestamptz,
        last_seen_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_authorization_grants (id) {
        id -> Uuid,
        oauth_client_id -> Uuid,
        oauth_session_id -> Nullable<Uuid>,
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
        consent_required -> Bool,
        fulfilled_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
        exchanged_at -> Nullable<Timestamptz>,
        login_hint -> Nullable<Text>,
        locale -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_device_code_grant (id) {
        id -> Uuid,
        oauth_client_id -> Uuid,
        scope -> Text,
        user_code -> Text,
        device_code -> Text,
        expires_at -> Timestamptz,
        fulfilled_at -> Nullable<Timestamptz>,
        rejected_at -> Nullable<Timestamptz>,
        exchanged_at -> Nullable<Timestamptz>,
        oauth_session_id -> Nullable<Uuid>,
        user_session_id -> Nullable<Uuid>,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_session_grant_operations (id) {
        id -> Uuid,
        issuer -> Text,
        operation_kind -> Text,
        proof_kind -> Nullable<Text>,
        request_identity -> Text,
        canonical_intent_digest -> Binary,
        canonical_intent -> Nullable<Binary>,
        operation_selector -> Nullable<Jsonb>,
        issuance_nonce -> Nullable<Text>,
        session_id -> Nullable<Text>,
        grant_not_before -> Nullable<Timestamptz>,
        grant_expires_at -> Nullable<Timestamptz>,
        signing_key_id -> Nullable<Text>,
        state -> Text,
        proof_authorization_ref -> Nullable<Text>,
        proof_authorization_checkpoint -> Nullable<Jsonb>,
        proof_expires_at -> Nullable<Timestamptz>,
        outcome_digest -> Nullable<Binary>,
        canonical_outcome -> Nullable<Binary>,
        target_session_grant_id -> Nullable<Binary>,
        result_grant_id -> Nullable<Binary>,
        affected_grant_ids -> Array<Nullable<Binary>>,
        retained_until -> Timestamptz,
        committed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_session_grants (id) {
        id -> Uuid,
        grant_id -> Binary,
        issuance_operation_id -> Uuid,
        user_session_id -> Nullable<Uuid>,
        issuer -> Text,
        subject -> Text,
        device_id -> Nullable<Text>,
        applet_id -> Nullable<Text>,
        effective_scope -> Nullable<Jsonb>,
        registration_epoch -> Nullable<Text>,
        service_id -> Nullable<Text>,
        capability_grant_refs -> Array<Text>,
        audience -> Text,
        scope_list -> Array<Text>,
        grant_jwt -> Text,
        session_id -> Text,
        issuance_nonce -> Text,
        issuance_preimage -> Binary,
        issuance_digest -> Binary,
        signing_key_id -> Text,
        session_public_key -> Text,
        credential_class -> Text,
        expires_at -> Timestamptz,
        lifecycle_state -> Text,
        revoked_at -> Nullable<Timestamptz>,
        superseded_at -> Nullable<Timestamptz>,
        successor_grant_id -> Nullable<Binary>,
        created_at -> Timestamptz,
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
        created_at -> Timestamptz,
    }
}

diesel::table! {
    upstream_oauth_links (id) {
        id -> Uuid,
        upstream_oauth_provider_id -> Uuid,
        user_id -> Nullable<Uuid>,
        subject -> Text,
        human_account_name -> Nullable<Text>,
        unlinked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
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
        completed_at -> Nullable<Timestamptz>,
        consumed_at -> Nullable<Timestamptz>,
        id_token_claims -> Nullable<Jsonb>,
        user_session_id -> Nullable<Uuid>,
        extra_callback_parameters -> Nullable<Jsonb>,
        userinfo -> Nullable<Jsonb>,
        unlinked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
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
        created_at -> Timestamptz,
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
        owner_oauth_client_id -> Nullable<Uuid>,
        actor_user_id -> Uuid,
        human_name -> Text,
        scope_list -> Array<Text>,
        revoked_at -> Nullable<Timestamptz>,
        last_active_at -> Nullable<Timestamptz>,
        last_active_ip -> Nullable<Inet>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    personal_access_tokens (id) {
        id -> Uuid,
        personal_session_id -> Uuid,
        access_token_sha256 -> Bytea,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    policy_data (id) {
        id -> Uuid,
        data -> Jsonb,
        created_at -> Timestamptz,
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
        scheduled_at -> Timestamptz,
        started_at -> Nullable<Timestamptz>,
        completed_at -> Nullable<Timestamptz>,
        cancelled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
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
        reserved_at -> Nullable<Timestamptz>,
        sent_at -> Nullable<Timestamptz>,
        delivered_at -> Nullable<Timestamptz>,
        failed_at -> Nullable<Timestamptz>,
        next_retry_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
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
        audit_context -> Jsonb,
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
        audit_signature -> Nullable<Text>,
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
    principal_did_bindings (id) {
        id -> Uuid,
        principal_did_owner_id -> Uuid,
        user_id -> Uuid,
        audience -> Text,
        verified_full_id -> Text,
        verified_version_id -> Text,
        binding_receipt -> Jsonb,
        accepted_service_id -> Text,
        binding_version -> Int8,
        binding_frontier_digest -> Text,
        principal_authority -> Jsonb,
        principal_control_realm_id -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    principal_did_owners (id) {
        id -> Uuid,
        user_id -> Uuid,
        principal_id -> Text,
        key_log_head -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
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
        published_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

// Foreign key relationships
diesel::joinable!(user_primary_handle_preferences -> users (user_id));
diesel::joinable!(principal_did_bindings -> principal_did_owners (principal_did_owner_id));
diesel::joinable!(principal_did_owners -> users (user_id));
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
diesel::joinable!(oauth_sessions -> oauth_clients (oauth_client_id));
diesel::joinable!(oauth_access_tokens -> oauth_sessions (oauth_session_id));
diesel::joinable!(oauth_authorization_grants -> oauth_clients (oauth_client_id));
diesel::joinable!(oauth_device_code_grant -> oauth_clients (oauth_client_id));
diesel::joinable!(oauth_session_grants -> user_sessions (user_session_id));
diesel::joinable!(oauth_session_grants -> oauth_session_grant_operations (issuance_operation_id));
diesel::joinable!(recovery_completion_grant_issuances -> users (service_account_id));
diesel::joinable!(recovery_completion_grant_issuances -> oauth_session_grant_operations (session_grant_operation_id));
diesel::joinable!(oauth_client_localized_metadata -> oauth_clients (client_id));
diesel::joinable!(upstream_oauth_links -> upstream_oauth_providers (upstream_oauth_provider_id));
diesel::joinable!(upstream_oauth_authorization_sessions -> upstream_oauth_providers (upstream_oauth_provider_id));
diesel::joinable!(personal_access_tokens -> personal_sessions (personal_session_id));
diesel::joinable!(queue_leader -> queue_workers (queue_worker_id));
diesel::joinable!(notification_deliveries -> notification_requests (notification_request_id));
diesel::joinable!(notification_event_logs -> notification_requests (notification_request_id));
diesel::joinable!(notification_event_logs -> notification_deliveries (notification_delivery_id));

diesel::allow_tables_to_appear_in_same_query!(
    account_handoff_creation_attempts,
    users,
    account_claims,
    risk_action_proposals,
    webauthn_credentials,
    webauthn_ceremonies,
    invite_quarantine_queue,
    user_passwords,
    principal_did_bindings,
    principal_did_owners,
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
    oauth_clients,
    oauth_client_localized_metadata,
    oauth_sessions,
    oauth_access_tokens,
    oauth_refresh_tokens,
    oauth_authorization_grants,
    oauth_device_code_grant,
    oauth_session_grants,
    oauth_session_grant_operations,
    recovery_completion_grant_issuances,
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
    handle_audit_log,
    user_primary_handle_preferences,
    accountability_grants,
    accountability_subject_revocations,
    circle_capability_grants,
    collaboration_capability_grants,
    organization_principal_controls,
    organization_delegations,
);
