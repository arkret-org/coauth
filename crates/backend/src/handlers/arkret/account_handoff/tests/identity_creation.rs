use arkret_models_identity::{
    AccountHandoffBinding, AccountHandoffOutcome, IdentityBindingChallengeOutcome,
};
use sha2::Digest as _;

use super::*;

const CHALLENGE_PATH: &str = "/_arkret/gate/account/identity-binding-challenges";
const REGISTER_PATH: &str = "/_arkret/gate/account/register";
const REGISTRATION_STATION_DID: &str = "did:web:example.com";
const REGISTRATION_STATION_ID: &str = "ak:did_core:web:example.com";

fn authenticated_request(
    path: &str,
    token: &str,
    signing: &SigningKey,
    body: &impl serde::Serialize,
) -> hyper::Request<String> {
    let public = PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&signing.verifying_key()));
    let header: JsonWebSignatureHeader = serde_json::from_value(serde_json::json!({
        "alg": JsonWebSignatureAlg::Ed25519, "typ": "dpop+jwt", "jwk": public,
    }))
    .unwrap();
    let claims = arkret_signatures::dpop::VerifiedDpopClaims {
        jti: format!("identity-http-{}", unique_test_nonce()),
        htm: "POST".to_owned(),
        htu: format!("https://example.com{path}"),
        iat: chrono::Utc::now().timestamp(),
        ath: Some(Base64UrlUnpadded::encode_string(&sha2::Sha256::digest(
            token.as_bytes(),
        ))),
        nonce: None,
    };
    let proof = Jwt::sign(
        header,
        claims,
        &AsymmetricSigningKey::ed25519(signing.clone()),
    )
    .unwrap()
    .into_string();
    hyper::Request::post(path)
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .json(body)
}

fn pcr_outcome(
    request: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody,
) -> arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome {
    use arkret_wire::{
        EventBatchReceipt, EventBatchReceiptRow, EventBatchReceiptScope, PcrGenesisReceiptScope,
        PcrGenesisReceiptScopeKind,
    };
    let descriptor: arkret_models_collaboration::events_payloads::realm::FoundingDeviceDescriptor =
        serde_json::from_value(
            request
                .genesis_unit
                .create()
                .payload
                .get("object")
                .and_then(|object| object.get("founding_device_descriptor"))
                .unwrap()
                .clone(),
        )
        .unwrap();
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut receipt = EventBatchReceipt {
        schema: EventBatchReceipt::SCHEMA.to_owned(),
        receipt_id: arkret_wire::ReceiptId::new("ak:receipt:0196419b-0000-7000-8000-000000000003")
            .unwrap(),
        issuer_id: request
            .genesis_unit
            .create()
            .actor_id
            .route_service_id()
            .clone(),
        scope: EventBatchReceiptScope::PcrGenesis(PcrGenesisReceiptScope {
            kind: PcrGenesisReceiptScopeKind::PcrGenesisUnit,
            principal_id: request.principal_id.clone(),
            realm_id: request.pcr_realm_id.clone(),
            did_version_id: request.did_version_id.clone(),
            log_head_digest: request.log_head_digest.clone(),
            control_key_digest: request.control_key_digest.clone(),
            registration_evidence_digest: request
                .registration_did_evidence
                .canonical_digest()
                .unwrap(),
            accepted_device_id: descriptor.device_id.clone(),
            device_key_digest: descriptor.device_key_digest().unwrap(),
            hpke_key_digest: descriptor.hpke_key_digest().unwrap(),
            accepted_at: now,
            audience_id: request.account_authority_id.clone(),
        }),
        events: [
            request.genesis_unit.create(),
            request.genesis_unit.founding_authorize(),
        ]
        .into_iter()
        .map(|event| EventBatchReceiptRow {
            event_id: event.event_id.clone(),
            kind: arkret_wire::NonEmptyString::new(event.kind.as_str()).unwrap(),
        })
        .collect(),
        created_at: now,
        proofs: Vec::new(),
    };
    receipt.canonicalize_events().unwrap();
    let unsigned = arkret_wire::UnsignedPayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(format!("{REGISTRATION_STATION_DID}#notary"))
            .unwrap(),
        payload_digest: receipt.payload_digest().unwrap(),
        created_at: now,
        domain: None,
        audience: None,
        proof_purpose: None,
    };
    let jws = arkret_signatures::sign_ed25519_detached_jws(
        &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[23; 32]),
        &receipt.proof_signing_bytes(&unsigned).unwrap(),
    )
    .unwrap();
    receipt.proofs.push(unsigned.finalize(jws).unwrap());
    receipt.validate().unwrap();
    let outcome = arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome {
        principal_id: request.principal_id.clone(),
        pcr_realm_id: request.pcr_realm_id.clone(),
        accepted_device_id: descriptor.device_id,
        receipt,
    };
    outcome.validate_against(request).unwrap();
    outcome
}

async fn accept_current_registration_station(state: &TestState) {
    use crate::services::did_binding::{
        accept_authority_resolution, controller_freshness, shared_verified_did_binding_store,
        test_resolution,
    };
    use crate::services::did_resolver::DidResolutionSource;
    let public_key = SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
    let method = format!("{REGISTRATION_STATION_DID}#notary");
    let mut resolution = test_resolution(
        REGISTRATION_STATION_DID,
        DidResolutionSource::DidWeb,
        None,
        None,
        serde_json::json!({"resolver":"did:web"}),
    );
    resolution.document = serde_json::from_value(serde_json::json!({
        "id": REGISTRATION_STATION_DID,
        "verificationMethod": [{"id":method,"type":"Multikey","controller":REGISTRATION_STATION_DID,"publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public_key)}],
        "assertionMethod":[method]
    })).unwrap();
    let mut repo = state.repository().await.unwrap();
    accept_authority_resolution(
        &state.url_builder,
        &state.arkret_config,
        &mut repo,
        shared_verified_did_binding_store().as_ref(),
        &resolution,
        REGISTRATION_STATION_DID,
        arkret_identity::DidBindingPurpose::Controller,
        controller_freshness(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .await
    .unwrap();
    repo.save().await.unwrap();
}

fn registration_device_gate_outcome(
    request: &arkret_wire::DeviceRevocationGateCheckRequestBody,
    authorization_event_id: &arkret_wire::EventId,
) -> arkret_wire::DeviceRevocationGateCheckOutcome {
    let unsigned = arkret_wire::UnsignedDeviceRevocationGateDecisionReceipt {
        account_id: request.account_id.clone(),
        device_id: request.device_id.clone(),
        target_device_authorize_event_id: Some(authorization_event_id.clone()),
        target_device_generation_ref: Some(1),
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        accepted_device_possession_proof_digest: None,
        decision: arkret_wire::DeviceRevocationGateDecision::Allow,
        linearization_seq: 1,
        linearized_at: request.requested_at,
        expires_at: request.requested_at + Duration::seconds(30),
        blocking_proposal_digest: None,
        covering_seal_id: None,
        verification_method: arkret_wire::DidUrl::new(format!("{REGISTRATION_STATION_DID}#notary"))
            .unwrap(),
    };
    let metadata = unsigned.proof_metadata().unwrap();
    let jws = arkret_signatures::sign_ed25519_detached_jws(
        &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[23; 32]),
        &unsigned.proof_signing_bytes(&metadata).unwrap(),
    )
    .unwrap();
    let outcome = arkret_wire::DeviceRevocationGateCheckOutcome {
        decision_receipt: unsigned
            .attach_proof(metadata.finalize(jws).unwrap())
            .unwrap(),
    };
    outcome.validate_for_request(request).unwrap();
    outcome
}

#[tokio::test]
async fn identity_registration_http_recovery_keeps_exact_proof_and_does_not_repeat_accepted_effects()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    setup();
    let Some((mut state, _database)) = local_handoff_state().await else {
        return;
    };
    let peer = MockServer::start().await;
    state.arkret_config.stations[0].endpoint = peer.uri().parse().unwrap();
    state.arkret_config.stations[0].service_id = Some(REGISTRATION_STATION_ID.parse().unwrap());
    state.arkret_config.deployment_profile = coauth_config::DeploymentProfileConfig::PersonalNode;
    state.station_admin =
        std::sync::Arc::new(crate::services::principal_facade::DbConnectorAdmin::new(
            state.site_config.server_name.clone(),
            Box::new(state.repository_factory.clone()),
            state.arkret_config.clone(),
            state.http_client.clone(),
        ));
    let seed = seed_local_handoff(&state, "registerhttp").await;
    let signing = SigningKey::generate(&mut OsRng);
    let response = state
        .request(local_handoff_request(
            &state,
            &seed,
            &signing,
            test_request_id(unique_test_nonce()),
            format!("register-handoff-{}", unique_test_nonce()),
            REGISTRATION_STATION_ID,
            None,
            None,
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let handoff: AccountHandoffOutcome = response.json();
    let AccountHandoffBinding::IdentityCreationActive {
        identity_creation_lease: lease,
    } = &handoff.binding
    else {
        panic!("initial lease absent")
    };
    let public_jwk = serde_json::json!({"crv":"Ed25519", "kty":"OKP", "x":Base64UrlUnpadded::encode_string(&signing.verifying_key().to_bytes())}).to_string();
    let fixture = cotest_test_support::wire::principal_registration_fixture(serde_json::json!({
        "station_url":"https://principal.example", "gate_account_base_url":"https://example.com/_arkret/gate/account",
        "handoff_request_id": handoff.request_id, "identity_creation_lease": lease,
        "device_id":"ak:device:0196419b-0000-7000-8000-000000000009", "trust_domain":trust_domain_for(&state.url_builder, &state.arkret_config),
        "initial_session":{"session_public_key":public_jwk,"audience_id":REGISTRATION_STATION_ID},
    })).unwrap();
    let challenge = state
        .request(authenticated_request(
            CHALLENGE_PATH,
            &handoff.account_handoff_grant,
            &signing,
            &fixture["challenge_request"],
        ))
        .await;
    challenge.assert_status(StatusCode::OK);
    let challenge: IdentityBindingChallengeOutcome = challenge.json();
    let body = cotest_test_support::wire::identity_creation_register_request(serde_json::json!({
        "challenge": challenge, "did_operation": fixture["did_operation"],
        "pcr_genesis_unit": fixture["checkpoint"]["pcr_genesis_unit"],
        "initial_session":fixture["checkpoint"]["initial_session"], "recovery_key":fixture["recovery_key"],
    })).unwrap();
    let fresh_authentication =
        seed_local_handoff_for_user(&state, "registeragain", Some("registerhttp")).await;
    let response = state
        .request(local_handoff_request(
            &state,
            &fresh_authentication,
            &signing,
            test_request_id(unique_test_nonce()),
            format!("register-reauthenticated-{}", unique_test_nonce()),
            REGISTRATION_STATION_ID,
            None,
            None,
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let reauthenticated: AccountHandoffOutcome = response.json();
    let AccountHandoffBinding::IdentityCreationActive {
        identity_creation_lease: renewed_lease,
    } = &reauthenticated.binding
    else {
        panic!("same-holder reauthentication lost its lease")
    };
    assert_eq!(
        renewed_lease.identity_creation_lease_id,
        lease.identity_creation_lease_id
    );
    assert_eq!(renewed_lease.fence, lease.fence);
    assert_eq!(reauthenticated.account_subject, handoff.account_subject);
    assert_ne!(
        reauthenticated.account_handoff_grant,
        handoff.account_handoff_grant
    );
    assert_eq!(table_count(&state, "identity_binding_challenges").await, 1);
    // Only current authentication changed. Keep the original challenge and proof bytes.
    let registry_calls = Arc::new(AtomicUsize::new(0));
    let registry_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let accepted_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let registry_calls_for_mock = registry_calls.clone();
    let registry_bodies_for_mock = registry_bodies.clone();
    Mock::given(method("POST"))
        .and(path("/_arkret/root/identity/submit-did-operation"))
        .respond_with(move |request: &wiremock::Request| {
            registry_bodies_for_mock
                .lock()
                .unwrap()
                .push(request.body.clone());
            if registry_calls_for_mock.fetch_add(1, Ordering::SeqCst) < 2 {
                return ResponseTemplate::new(503);
            }
            let operation: arkret_models_identity::DidOperationSubmitRequestBody =
                request.body_json().unwrap();
            let validated =
                arkret_signatures::webvh::validate_principal_inception_operation(&operation)
                    .unwrap();
            ResponseTemplate::new(200).set_body_json(
                arkret_models_identity::DidOperationSubmitOutcome {
                    status: arkret_models_identity::DidOperationSubmitStatus::Accepted,
                    did: operation.did.clone(),
                    accepted_at,
                    seq: Some(1),
                    operation_ref: format!(
                        "{}?versionId={}",
                        operation.did, validated.did_version_id
                    ),
                    receipts: Vec::new(),
                },
            )
        })
        .expect(3)
        .mount(&peer)
        .await;
    let pcr_calls = Arc::new(AtomicUsize::new(0));
    let pcr_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let pcr_calls_for_mock = pcr_calls.clone();
    let pcr_bodies_for_mock = pcr_bodies.clone();
    Mock::given(method("POST"))
        .and(path("/_arkret/peer/principal-genesis"))
        .respond_with(move |request: &wiremock::Request| {
            pcr_bodies_for_mock
                .lock()
                .unwrap()
                .push(request.body.clone());
            if pcr_calls_for_mock.fetch_add(1, Ordering::SeqCst) < 2 {
                return ResponseTemplate::new(503);
            }
            let body = request.body_json().unwrap();
            ResponseTemplate::new(200).set_body_json(pcr_outcome(&body))
        })
        .expect(3)
        .mount(&peer)
        .await;
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    diesel::sql_query("UPDATE identity_creation_leases SET fence = fence + 1")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let rejected = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    rejected.assert_status(StatusCode::CONFLICT);
    assert!(peer.received_requests().await.unwrap().is_empty());
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    diesel::sql_query(
        "UPDATE identity_creation_leases SET fence = fence - 1, expires_at = clock_timestamp()",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let rejected = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    rejected.assert_status(StatusCode::CONFLICT);
    assert!(peer.received_requests().await.unwrap().is_empty());
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    diesel::sql_query("UPDATE identity_creation_leases SET expires_at = $1")
        .bind::<diesel::sql_types::Timestamptz, _>(lease.expires_at)
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query(
        "UPDATE identity_binding_challenges SET expires_at = issued_at + interval '1 microsecond'",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let expired_first_attempt = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    expired_first_attempt.assert_status(StatusCode::CONFLICT);
    assert!(peer.received_requests().await.unwrap().is_empty());
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    let recovery_expires_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(3),
    );
    diesel::sql_query("UPDATE identity_binding_challenges SET expires_at = $1")
        .bind::<diesel::sql_types::Timestamptz, _>(recovery_expires_at)
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let mut recovery_challenge = challenge.clone();
    recovery_challenge.expires_at = recovery_expires_at;
    let body = cotest_test_support::wire::identity_creation_register_request(serde_json::json!({
        "challenge": recovery_challenge, "did_operation": fixture["did_operation"],
        "pcr_genesis_unit": fixture["checkpoint"]["pcr_genesis_unit"],
        "initial_session":fixture["checkpoint"]["initial_session"], "recovery_key":fixture["recovery_key"],
    })).unwrap();
    // The first registry call accepts the exact dispatch in the remote world,
    // but its response is lost. Coauth must retain a durable request fence,
    // remain resumable, and resend byte-identical operation bytes.
    let uncertain = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    uncertain.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    if let Ok(wait) =
        (recovery_expires_at - chrono::Utc::now() + chrono::Duration::milliseconds(100)).to_std()
    {
        tokio::time::sleep(wait).await;
    }
    // The exact registry replay succeeds, then the PCR receiver accepts while
    // its response is lost. The durable phase remains did_published and the
    // next attempt must replay the same PCR request without republishing DID.
    let pcr_uncertain = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    assert!(!pcr_uncertain.status().is_success());
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Phase {
        #[diesel(sql_type = diesel::sql_types::Text)]
        state: String,
    }
    let phase = diesel::sql_query("SELECT state FROM identity_creation_leases")
        .get_result::<Phase>(&mut conn)
        .await
        .unwrap();
    assert_eq!(phase.state, "did_published");
    drop(conn);
    // Deliberately leave the subsequent account projection unavailable. Both
    // native identity effects must remain committed and never be reminted.
    let first = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    assert!(
        !first.status().is_success(),
        "fault after PCR acceptance must be observable"
    );
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    let phase = diesel::sql_query("SELECT state FROM identity_creation_leases")
        .get_result::<Phase>(&mut conn)
        .await
        .unwrap();
    assert!(
        matches!(phase.state.as_str(), "pcr_accepted" | "account_bound"),
        "registration did not reach the injected post-PCR fault: {} / {}",
        phase.state,
        first.body()
    );
    drop(conn);
    // The client retains its confirmed Recovery Key and exact original proof.
    let second = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    assert!(!second.status().is_success());
    assert_eq!(table_count(&state, "identity_binding_challenges").await, 1);

    // Restore the standard downstream dependencies after the durable PCR fault.
    state.arkret_config.stations[0].embedded_webvh_registration_bearer =
        Some("registration-projection-bearer".to_owned());
    accept_current_registration_station(&state).await;
    let register: arkret_models_collaboration::account_lifecycle::AccountRegisterRequestBody =
        serde_json::from_value(body.clone()).unwrap();
    let authorization_event_id = register
        .identity_creation
        .as_ref()
        .unwrap()
        .pcr_genesis_unit
        .founding_authorize()
        .event_id
        .clone();
    let projection_principal = register.principal_id.clone();
    Mock::given(method("POST"))
        .and(path(soland_contracts::ACCOUNT_PROJECTION_PATH))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer registration-projection-bearer",
        ))
        .and(move |request: &wiremock::Request| {
            let projection: soland_contracts::AccountProjectionRequestBody =
                request.body_json().unwrap();
            projection.principal_id == projection_principal
        })
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&peer)
        .await;
    let localparts_path = soland_contracts::account_localparts_endpoint(
        peer.uri().parse().unwrap(),
        &register.principal_id,
    )
    .unwrap()
    .path()
    .to_owned();
    Mock::given(method("POST"))
        .and(path(localparts_path))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer registration-projection-bearer",
        ))
        .and(wiremock::matchers::body_json(
            serde_json::json!({"localpart":"registerhttp", "is_primary":true}),
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&peer)
        .await;
    Mock::given(method("POST"))
        .and(path(arkret_wire::PATH_PEER_DEVICE_REVOCATIONS_CHECK))
        .respond_with(move |request: &wiremock::Request| {
            let check: arkret_wire::DeviceRevocationGateCheckRequestBody =
                request.body_json().unwrap();
            ResponseTemplate::new(200).set_body_json(registration_device_gate_outcome(
                &check,
                &authorization_event_id,
            ))
        })
        .expect(1)
        .mount(&peer)
        .await;
    let completed = state
        .request(authenticated_request(
            REGISTER_PATH,
            &reauthenticated.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    completed.assert_status(StatusCode::OK);
    let outcome: arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome =
        completed.json();
    outcome.validate_against_request(&register).unwrap();
    assert!(outcome.session_grant_outcome.is_some());
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    let phase = diesel::sql_query("SELECT state FROM identity_creation_leases")
        .get_result::<Phase>(&mut conn)
        .await
        .unwrap();
    assert_eq!(phase.state, "completed");
    // A recorded outcome survives later expiry of the proof and live lease.
    diesel::sql_query(
        "UPDATE identity_creation_leases SET expires_at = clock_timestamp() - interval '1 second'",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query("UPDATE identity_binding_challenges SET issued_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second'").execute(&mut conn).await.unwrap();
    drop(conn);
    let original_proof_expiry = register
        .identity_creation
        .as_ref()
        .unwrap()
        .control_proof
        .expires_at;
    let replay_after = original_proof_expiry + Duration::seconds(1);
    let delay = (replay_after - chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    eprintln!(
        "Completed registration; waiting until original signed proof expires at {original_proof_expiry}"
    );
    tokio::time::sleep(delay).await;
    assert!(chrono::Utc::now() > original_proof_expiry);
    assert!(chrono::Utc::now() < reauthenticated.expires_at);
    for _ in 0..2 {
        let replay = state
            .request(authenticated_request(
                REGISTER_PATH,
                &reauthenticated.account_handoff_grant,
                &signing,
                &body,
            ))
            .await;
        replay.assert_status(StatusCode::OK);
        assert_eq!(replay.body(), completed.body());
    }
    assert_eq!(table_count(&state, "identity_binding_challenges").await, 1);
    assert_eq!(table_count(&state, "oauth_session_grants").await, 1);
    let registry_bodies = registry_bodies.lock().unwrap();
    assert_eq!(registry_bodies.len(), 3);
    assert_eq!(registry_bodies[0], registry_bodies[1]);
    assert_eq!(registry_bodies[1], registry_bodies[2]);
    drop(registry_bodies);
    let pcr_bodies = pcr_bodies.lock().unwrap();
    assert_eq!(pcr_bodies.len(), 3);
    assert_eq!(pcr_bodies[0], pcr_bodies[1]);
    assert_eq!(pcr_bodies[1], pcr_bodies[2]);
    drop(pcr_bodies);
    assert_eq!(peer.received_requests().await.unwrap().len(), 9);
    peer.verify().await;
}

#[tokio::test]
async fn identity_challenge_http_uses_live_authority_without_renewal_and_replays_lost_response() {
    setup();
    let Some((state, _database)) = local_handoff_state().await else {
        return;
    };
    let seed = seed_local_handoff(&state, "challengehttp").await;
    let signing = SigningKey::generate(&mut OsRng);
    let response = state
        .request(local_handoff_request(
            &state,
            &seed,
            &signing,
            test_request_id(unique_test_nonce()),
            format!("challenge-handoff-{}", unique_test_nonce()),
            TEST_STATION_AUDIENCE,
            None,
            None,
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let handoff: AccountHandoffOutcome = response.json();
    let AccountHandoffBinding::IdentityCreationActive {
        identity_creation_lease: lease,
    } = &handoff.binding
    else {
        panic!("initial lease absent")
    };
    let endpoint: url::Url = "https://station.example".parse().unwrap();
    let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes(),
    );
    let inception = arkret_signatures::webvh::prepare_principal_inception(
        &arkret_signatures::webvh::PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: "challengehttp",
            also_known_as: &[],
            version_time: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            root_seed: &[21; 32],
            next_root_public_key_multibase: &next,
            witness_policy: None,
        },
    )
    .unwrap();
    let digest = arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let body = IdentityBindingChallengeRequestBody {
        request_id: test_request_id(unique_test_nonce()),
        identity_creation_lease_id: lease.identity_creation_lease_id.clone(),
        lease_fence: lease.fence,
        did: inception.submit_body.did.clone(),
        did_operation: inception.submit_body,
        pcr_realm_id: coauth_storage_postgres::test_utils::principal_control_realm_id(),
        realm_create_payload_digest: digest.clone(),
        founding_authorize_payload_digest: digest.clone(),
        initial_session_request_digest: digest,
    };
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    // The challenge proof can outlive both credentials without extending either.
    diesel::sql_query("UPDATE identity_creation_leases SET expires_at = date_trunc('second', clock_timestamp()) + interval '20 seconds'")
        .execute(&mut conn).await.unwrap();
    diesel::sql_query("UPDATE account_handoff_grants SET expires_at = date_trunc('second', clock_timestamp()) + interval '30 seconds'")
        .execute(&mut conn).await.unwrap();
    drop(conn);
    let first = state
        .request(authenticated_request(
            CHALLENGE_PATH,
            &handoff.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    first.assert_status(StatusCode::OK);
    let challenge: IdentityBindingChallengeOutcome = first.json();
    assert_eq!(
        (challenge.expires_at - challenge.issued_at).num_seconds(),
        300
    );
    assert_eq!(table_count(&state, "identity_binding_challenges").await, 1);
    // Ignore the first outcome and retransmit the actual signed HTTP request body.
    let replay = state
        .request(authenticated_request(
            CHALLENGE_PATH,
            &handoff.account_handoff_grant,
            &signing,
            &body,
        ))
        .await;
    replay.assert_status(StatusCode::OK);
    assert_eq!(first.body(), replay.body());
    assert_eq!(table_count(&state, "identity_binding_challenges").await, 1);
    assert_eq!(
        table_count(&state, "identity_creation_rate_limit_events").await,
        2
    );
    let mut second = body.clone();
    second.request_id = test_request_id(unique_test_nonce());
    let limited = state
        .request(authenticated_request(
            CHALLENGE_PATH,
            &handoff.account_handoff_grant,
            &signing,
            &second,
        ))
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let problem: arkret_wire::problem_details::Problem = limited.json();
    assert_eq!(problem.code(), arkret_wire::ErrorCode::RATE_LIMITED);
    assert!(
        problem
            .extensions
            .get("retry_after_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|v| v > 0 && v <= 60_000)
    );
    assert!(limited.headers().get("retry-after").is_some());
    assert_eq!(table_count(&state, "identity_binding_challenges").await, 1);
    for (mutation, reason) in [
        (
            "consumed_at = clock_timestamp()",
            arkret_wire::ReasonCode::IDENTITY_CREATION_CHALLENGE_ALREADY_CONSUMED,
        ),
        (
            "consumed_at = NULL, issued_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second'",
            arkret_wire::ReasonCode::IDENTITY_CREATION_CHALLENGE_EXPIRED,
        ),
    ] {
        let mut conn = state.repository_factory.pool().get().await.unwrap();
        diesel::sql_query(format!("UPDATE identity_binding_challenges SET {mutation}"))
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        let terminal = state
            .request(authenticated_request(
                CHALLENGE_PATH,
                &handoff.account_handoff_grant,
                &signing,
                &body,
            ))
            .await;
        terminal.assert_status(StatusCode::CONFLICT);
        let problem: arkret_wire::problem_details::Problem = terminal.json();
        assert_eq!(problem.code(), arkret_wire::ErrorCode::FAILED_PRECONDITION);
        assert_eq!(
            problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str),
            Some(reason)
        );
    }
}
