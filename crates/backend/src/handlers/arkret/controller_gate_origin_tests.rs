//! Actual Account Authority issuance connected to the PostgreSQL Origin pipeline.
use diesel_async::RunQueryDsl as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::handlers::test_utils::{TestState, setup, unique_test_nonce};

async fn origin_cut(pool: &coland_storage_postgres::PgPool) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Cut {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut connection = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('evidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)),'[]') FROM agent_origin_forward_evidence t),'events',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)),'[]') FROM canonical_events t),'commits',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)),'[]') FROM realm_commits t)) AS value")
        .get_result::<Cut>(&mut *connection).await.unwrap().value
}

// This transport adapter delegates every request to the registered real router.
// Only the adversarial response branch substitutes a correctly signed wrong binding.
async fn serve_gate(listener: tokio::net::TcpListener, state: TestState, wrong_binding: bool) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() < 16384);
        if let Some(position) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    assert!(headers.starts_with("POST /_coauth/internal/controller-gate-attestations HTTP/1.1"));
    let header = |name: &str| {
        headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.trim().to_owned())
            })
            .unwrap()
    };
    let length: usize = header("content-length").parse().unwrap();
    assert!(length < 8192);
    while bytes.len() < header_end + length {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
    }
    let body = String::from_utf8(bytes[header_end..header_end + length].to_vec()).unwrap();
    let input: ControllerAccountGateIssuanceInput = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body.as_bytes(),
        arkret_canonical::canonical_json_bytes(&input).unwrap()
    );
    let response = state
        .request(
            hyper::Request::post("/_coauth/internal/controller-gate-attestations")
                .header("Authorization", header("authorization"))
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await;
    let mut body = response.body().clone();
    if wrong_binding {
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let mut outcome: ControllerAccountGateIssuanceOutcome =
            serde_json::from_str(&body).unwrap();
        let gate = &mut outcome.controller_account_gate_attestation;
        gate.principal_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:wrong-controller.example").unwrap();
        gate.basis_digest = gate.expected_basis_digest().unwrap();
        gate.proof.jws = arkret_wire::NonEmptyString::new(
            arkret_signatures::sign_ed25519_detached_jws(
                &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(
                    &state.keyring.account_authority_seed().unwrap(),
                ),
                &gate.signing_bytes().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        body = arkret_canonical::canonical_json_string(&outcome).unwrap();
    }
    let head = format!(
        "HTTP/1.1 {} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status().as_u16(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
}

#[tokio::test]
async fn registered_gate_actual_issuance_origin_same_cut_and_governance_verification() {
    setup();
    let pool = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("actual PostgreSQL is required");
    let mut authority = TestState::from_pool_with_station(pool.clone())
        .await
        .unwrap();
    let endpoint: url::Url = format!("https://connected-origin-{}.example/", unique_test_nonce())
        .parse()
        .unwrap();
    use rand_core_10::SeedableRng as _;
    let mut rng = rand_chacha_10::ChaCha20Rng::from_seed([0x73; 32]);
    let aa_key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(
        &authority.keyring.account_authority_seed().unwrap(),
    );
    let aa_public =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(aa_key.verifying_key().as_bytes());
    let registration = arkret_models_identity::service_identity::ServiceRegistrationKey::new(
        arkret_wire::ServiceKind::Station,
        arkret_models_identity::service_identity::CanonicalServiceUrl::new(endpoint.as_str())
            .unwrap(),
    )
    .unwrap();
    let inception =
        arkret_signatures::webvh::prepare_service_registration_inception_with_assertion_keys(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_time: "2026-01-01T00:00:00Z".parse().unwrap(),
                did_key_fragment: Some("notary-key"),
            },
            &[0x52; 32],
            &[("account-authority", aa_public.as_str())],
        )
        .unwrap();
    authority.configure_status_issuer_original(&inception, endpoint.clone());
    const TOKEN: &str = "public-connected-gate-fixture-token";
    authority.arkret_config.stations[0].internal_authority_shared_secret =
        Some(TOKEN.to_owned().into());
    let fixture =
        coland_test_support::agent_origin::OriginFixture::with_service_inception(inception).await;
    fixture.admit_provision().await;
    fixture.stage(&fixture.genesis).await;
    fixture.admit_genesis().await.unwrap();
    fixture.authorize().await;
    let mut rng = authority.rng();
    let mut repo = authority.repository().await.unwrap();
    let user = repo
        .user()
        .add(
            &mut rng,
            authority.clock.as_ref(),
            format!("connected-controller-{}", unique_test_nonce()),
        )
        .await
        .unwrap();
    repo.save().await.unwrap();
    let genesis: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&fixture.controller.history.events[0].payload).unwrap(),
        )
        .unwrap();
    let resolution = genesis.object.initial_resolution.unwrap();
    let mut binding = coauth_storage_postgres::test_utils::verified_principal_binding_input(
        fixture.station_did.as_str(),
        fixture.station.as_str(),
        fixture.controller.history.account.principal_id.to_string(),
        arkret_wire::Hash::new(&resolution.method_history_head).unwrap(),
    );
    binding.verified_did = fixture.controller.history.did.clone();
    binding.verified_version_id = resolution.version_id.clone();
    binding.principal_control_realm_id = fixture.controller.history.events[0].realm_id.clone();
    binding.binding_receipt.did = binding.verified_did.clone();
    binding.binding_receipt.did_version_id = binding.verified_version_id.clone();
    authority
        .seed_accepted_principal_binding(&user, binding)
        .await;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::RealmProfile.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: fixture.genesis.event.realm_id.clone(),
        },
        arkret_wire::ActorId::account(fixture.agent.clone()),
        arkret_models_collaboration::events_payloads::RealmProfile::new("connected Agent producer")
            .unwrap()
            .to_value()
            .unwrap(),
        at,
    )
    .unwrap();
    let event = coland_test_support::device_authorization_history::sign_event(
        event,
        arkret_wire::DidUrl::new(format!("{}#runtime", fixture.agent_did)).unwrap(),
        [0x61; 32],
    );
    let initial = origin_cut(&fixture.pool).await;
    let mut evidence = None;
    for (credential, wrong_binding) in [
        ("wrong-public-fixture-token", false),
        (TOKEN, true),
        (TOKEN, false),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = coland_http::config::AppConfig {
            seed_demo_data: false,
            development_mode: true,
            public_base_url: endpoint.to_string(),
            account_authority_url: Some(format!("http://{address}")),
            ..coland_http::config::AppConfig::test_default()
        };
        config.register_test_internal_authority_channel(credential);
        let origin = fixture.app_state(config).await;
        let server = tokio::spawn(serve_gate(listener, authority.clone(), wrong_binding));
        let result = coland_http::test_fresh_producer_agent_evidence(&origin, &event).await;
        tokio::time::timeout(std::time::Duration::from_secs(20), server)
            .await
            .unwrap_or_else(|_| {
                panic!("Origin did not complete the registered gate call: {result:?}")
            })
            .unwrap();
        if credential != TOKEN || wrong_binding {
            assert!(
                result.is_err(),
                "refusal or mismatched binding cannot mint evidence"
            );
            assert_eq!(origin_cut(&fixture.pool).await, initial);
        } else {
            evidence = Some(result.unwrap().unwrap());
        }
    }
    let evidence = evidence.unwrap();
    assert_eq!(
        evidence.controller_account_gate_attestation.principal_id,
        fixture.controller.history.account.principal_id
    );
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    arkret_identity::agent_authority_evidence::verify_forwarded_agent_producer(
        &event,
        &evidence,
        &fixture.station,
        at,
        None,
    )
    .unwrap();
    let final_cut = origin_cut(&fixture.pool).await;
    assert_eq!(final_cut["events"], initial["events"]);
    assert_eq!(final_cut["commits"], initial["commits"]);
    assert_eq!(final_cut["evidence"].as_array().unwrap().len(), 1);
    // The governance ingress consumes the exact emitted carrier and rejects a
    // substituted controller before ordinary Realm admission can write anything.
    let (governance, governance_pool) =
        coland_test_support::app_state_with_pool(coland_test_support::app_config());
    let governance_before = origin_cut(&governance_pool).await;
    let peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: fixture.station.clone(),
        replay_receipt: None,
    };
    let request = arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequest {
        branch:
            arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
        event_submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
        mls_genesis_material: None,
        producer_device_evidence: None,
        producer_managed_provenance: None,
        producer_agent_evidence: Some(evidence.clone()),
    };
    let mut tampered = request.clone();
    tampered
        .producer_agent_evidence
        .as_mut()
        .unwrap()
        .controller_account_gate_attestation
        .principal_id = governance.service_core_id();
    let rejected = Box::pin(coland_http::test_admit_authority_forward(
        &governance,
        &peer,
        tampered,
        at,
    ))
    .await
    .expect_err("substituted controller must fail producer verification");
    assert!(
        !matches!(&rejected, coland_services::ServiceError::Conflict(detail) if detail == "Realm authority is unavailable")
    );
    let result = Box::pin(coland_http::test_admit_authority_forward(
        &governance,
        &peer,
        request,
        at,
    ))
    .await;
    assert!(
        matches!(result, Err(coland_services::ServiceError::Conflict(ref detail)) if detail == "Realm authority is unavailable"),
        "valid actual carrier must reach ordinary Realm authorization: {result:?}"
    );
    assert_eq!(origin_cut(&governance_pool).await, governance_before);
    use coland_test_support::AppStateTestExt as _;
    assert!(
        governance
            .test_persistence()
            .events()
            .get(event.event_id.as_str())
            .await
            .unwrap()
            .is_none()
    );
}
