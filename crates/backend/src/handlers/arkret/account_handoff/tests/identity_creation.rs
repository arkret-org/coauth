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
    request: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
) -> arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult {
    use arkret_wire::{
        Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, DidUrl, Hash, RealmCommit, RealmCommitAuthorityRef,
        RealmCommitId,
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
    let commit_id = RealmCommitId::from_digest([2; 32]);
    let signature = |suffix: char| DetachedObjectSignature {
        context: DetachedSignatureContext::RealmCommit,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new(format!("{REGISTRATION_STATION_DID}#notary")).unwrap(),
        signed_digest: Hash::new(format!("sha256:{}", suffix.to_string().repeat(64))).unwrap(),
        created_at: now,
        sig: Base64UrlString::new(suffix.to_string()).unwrap(),
    };
    let mut create_commit = RealmCommit {
        commit_id: commit_id.clone(),
        realm_id: request.pcr_realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: request.pcr_realm_id.clone(),
        },
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: request.genesis_unit.create().event_id.clone(),
        governance_generation: 0,
        producer_signer_fact_digest: None,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
            request.genesis_unit.create().event_id.clone(),
        ),
        committed_at: now,
        signature: signature('a'),
    };
    // Native PCR registration has no ordinary Human fact; seal its exact original bytes.
    let seal = |mut commit: RealmCommit| {
        let identity =
            arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"])
                .unwrap();
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
        ));
        let unsigned =
            arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
        let key = ed25519_dalek_3::SigningKey::from_bytes(&[23; 32]);
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmCommit,
            commit.signature.verification_method.clone(),
            now,
            &key,
        )
        .unwrap();
        commit.validate_content_address().unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &unsigned,
            DetachedSignatureContext::RealmCommit,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        commit
    };
    create_commit = seal(create_commit);
    let mut authorize_commit = RealmCommit {
        commit_id: RealmCommitId::from_digest([3; 32]),
        realm_id: request.pcr_realm_id.clone(),
        stream_ref: create_commit.stream_ref.clone(),
        stream_position: 1,
        previous_commit_ref: Some(create_commit.commit_id.clone()),
        event_ref: request.genesis_unit.founding_authorize().event_id.clone(),
        governance_generation: 0,
        producer_signer_fact_digest: None,
        authority_ref: create_commit.authority_ref.clone(),
        committed_at: now,
        signature: signature('b'),
    };
    authorize_commit = seal(authorize_commit);
    let outcome = arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult {
        principal_id: request.principal_id.clone(),
        pcr_realm_id: request.pcr_realm_id.clone(),
        accepted_device_id: descriptor.device_id,
        resolution: arkret_models_identity::PrincipalResolutionProjection {
            did: request.did.clone(),
            method_history_head: request
                .registration_did_evidence
                .method_history_head
                .clone(),
            version_id: request.registration_did_evidence.version_id.clone(),
            resolution_event_ref: request.genesis_unit.create().event_id.to_string(),
            updated_at: request.registration_did_evidence.accepted_at,
        },
        commits: [create_commit, authorize_commit],
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

/// The owning Station's private current-device response.
fn registration_device_gate_outcome(
    request: &serde_json::Value,
    authorization_event_id: &arkret_wire::EventId,
) -> serde_json::Value {
    let linearized_at = chrono::DateTime::parse_from_rfc3339(
        request["requested_at"].as_str().expect("requested_at"),
    )
    .unwrap()
    .with_timezone(&chrono::Utc);
    serde_json::json!({
        "account_id": request["account_id"].clone(),
        "device_id": request["device_id"].clone(),
        "authorization_event_id": authorization_event_id,
        "device_generation_ref": 1,
        "action_class": request["action_class"].clone(),
        "intent_digest": request["intent_digest"].clone(),
        "decision": "allow",
        "linearization_seq": 1,
        "linearized_at": linearized_at,
        "expires_at": linearized_at + Duration::seconds(30),
        "accepted_commit_id": "ak:realm_commit:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e"
    })
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
    crate::services::station_trust::shared().insert_for_test(
        &state.arkret_config.stations[0].endpoint,
        REGISTRATION_STATION_ID,
    );
    // The device-revocation gate runs on the registered deployment-internal
    // authenticated channel (`service-http-binding.md` §2.2.3); without the
    // configured channel credential the call fails closed instead of falling
    // back to an unauthenticated request.
    state.arkret_config.stations[0].internal_authority_shared_secret =
        Some("registration-internal-channel".to_owned().into());
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
    let wire_challenge = serde_json::to_value(&challenge).unwrap();
    assert_eq!(wire_challenge.as_object().unwrap().len(), 6);
    assert!(wire_challenge.get("account_subject").is_none());
    assert!(wire_challenge.get("log_head_digest").is_none());
    let body = cotest_test_support::wire::identity_creation_register_request(serde_json::json!({
        "challenge": challenge, "challenge_request": fixture["challenge_request"],
        "account_subject": handoff.account_subject,
        "origin":state.url_builder.http_base().origin().ascii_serialization(),
        "trust_domain":trust_domain_for(&state.url_builder, &state.arkret_config),
        "pcr_genesis_unit": fixture["checkpoint"]["pcr_genesis_unit"],
        "initial_session":fixture["checkpoint"]["initial_session"], "recovery_key":fixture["recovery_key"],
    })).unwrap();
    assert_eq!(
        body["identity_creation"]["control_proof"]["account_subject"],
        serde_json::to_value(&handoff.account_subject).unwrap()
    );
    assert!(
        body["identity_creation"]["control_proof"]
            .get("log_head_digest")
            .is_none()
    );
    let mut wrong_challenge = challenge.clone();
    wrong_challenge.request_id = arkret_wire::RequestId::new_v7_at(1_800_000_000_000);
    assert!(cotest_test_support::wire::identity_creation_register_request(serde_json::json!({
        "challenge": wrong_challenge, "challenge_request": fixture["challenge_request"],
        "account_subject":handoff.account_subject,
        "origin":state.url_builder.http_base().origin().ascii_serialization(),
        "trust_domain":trust_domain_for(&state.url_builder, &state.arkret_config),
        "pcr_genesis_unit":fixture["checkpoint"]["pcr_genesis_unit"],
        "initial_session":fixture["checkpoint"]["initial_session"], "recovery_key":fixture["recovery_key"],
    })).is_err());
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
        .and(path("/_soland/account-authority/principal-genesis/admit"))
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
        "challenge": recovery_challenge, "challenge_request": fixture["challenge_request"],
        "account_subject": handoff.account_subject,
        "origin":state.url_builder.http_base().origin().ascii_serialization(),
        "trust_domain":trust_domain_for(&state.url_builder, &state.arkret_config),
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
    let register: arkret_models_collaboration::account_operations::AccountRegisterRequestBody =
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
        .and(path("/_soland/account-authority/current-device/check"))
        .respond_with(move |request: &wiremock::Request| {
            let check: serde_json::Value = request.body_json().unwrap();
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
    let outcome: arkret_models_collaboration::account_operations::AccountRegisterOutcome =
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
    // Scoped rather than `drop`ped: the guards must not be part of this async
    // block's state across the `await` below.
    {
        let registry_bodies = registry_bodies.lock().unwrap();
        assert_eq!(registry_bodies.len(), 3);
        assert_eq!(registry_bodies[0], registry_bodies[1]);
        assert_eq!(registry_bodies[1], registry_bodies[2]);
    }
    {
        let pcr_bodies = pcr_bodies.lock().unwrap();
        assert_eq!(pcr_bodies.len(), 3);
        assert_eq!(pcr_bodies[0], pcr_bodies[1]);
        assert_eq!(pcr_bodies[1], pcr_bodies[2]);
    }
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
    let principal_registration_anchor =
        arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(inception.submit_body.clone()),
            log_entries: vec![serde_json::from_value(inception.log_entry.clone()).unwrap()],
            witness_records: Vec::new(),
            normalized_did_document: serde_json::from_value(inception.log_entry["state"].clone())
                .unwrap(),
        };
    let body = IdentityBindingChallengeRequestBody {
        request_id: test_request_id(unique_test_nonce()),
        identity_creation_lease_id: lease.identity_creation_lease_id.clone(),
        lease_fence: lease.fence,
        did: inception.submit_body.did.clone(),
        principal_registration_anchor,
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
