//! Real pending-row waits and the existing authenticated private HTTP adapter.
//! These tests cover the AA boundary; the peer is not a live Station/PCR.
use std::sync::Arc;
use std::time::Duration as WaitDuration;

use coauth_data::RepositoryFactory as _;
use coauth_data::clock::MockClock;
use diesel_async::SimpleAsyncConnection as _;
use horme::RunQueryDsl as _;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

fn authority_fixture() -> (
    arkret_wire::AccountId,
    arkret_models_identity::SessionGrantDeviceBinding,
    arkret_wire::RealmCommitId,
) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../arkret-spec/spec/v1/artifacts/fixtures/security-transaction-resilience-fixture.json"
    )))
    .unwrap();
    let kat = &fixture["single_submit_recovery_kat"];
    let receipt: arkret_models_crypto::RecoveryReceipt =
        serde_json::from_value(kat["receipt"].clone()).unwrap();
    let completion: arkret_wire::RecoveryCompletionAttestation =
        serde_json::from_value(kat["expected_outcome"]["completion_attestation"].clone()).unwrap();
    (
        receipt.account_id,
        arkret_models_identity::SessionGrantDeviceBinding {
            device_id: receipt.new_device_id,
            authorization_event_id: completion.device_authorization_event_ref.event_id,
            model_generation_ref: receipt.new_model_generation_ref,
        },
        completion.device_authorization_event_ref.commit_id,
    )
}

fn fixture_principal_control_realm() -> arkret_wire::RealmId {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../arkret-spec/spec/v1/artifacts/fixtures/security-transaction-resilience-fixture.json"
    )))
    .unwrap();
    serde_json::from_value(value["single_submit_recovery_kat"]["receipt"]["recovery_unit"]["events"][0]["event"]["realm_id"].clone()).unwrap()
}

async fn current_observation(
    peer: &MockServer,
    clock: &MockClock,
    account: &arkret_wire::AccountId,
    binding: &arkret_models_identity::SessionGrantDeviceBinding,
    commit: &arkret_wire::RealmCommitId,
    action: arkret_wire::DeviceRevocationDeniedAction,
) -> CurrentDeviceAdmission {
    crate::handlers::test_utils::setup();
    let endpoint = peer.uri().parse().unwrap();
    crate::services::station_trust::shared()
        .insert_for_test(&endpoint, account.station_id.as_str());
    let mut depot = Depot::new();
    depot.insert(
        "arkret_config",
        coauth_config::ArkretConfig {
            stations: vec![coauth_config::StationConfig {
                name: "pairing-origin".into(),
                endpoint,
                internal_authority_shared_secret: Some(coauth_config::ClientSecret::Value(
                    "pairing-expiry-registered-channel".into(),
                )),
                embedded_webvh_registration_bearer: None,
                trust_domain: Some("ak:trust_domain:station.example".into()),
            }],
            ..coauth_config::ArkretConfig::default()
        },
    );
    depot.insert(
        "http_client",
        crate::outbound_http::reqwest_client_for_tests(),
    );
    let intent = Hash::new(arkret_canonical::sha256_digest(b"exact-pairing-intent")).unwrap();
    let response = serde_json::json!({
        "account_id":account,"device_id":binding.device_id,
        "authorization_event_id":binding.authorization_event_id,
        "device_generation_ref":binding.model_generation_ref,
        "action_class":action,"intent_digest":intent,"decision":"allow",
        "linearization_seq":1,"linearized_at":clock.now(),
        "expires_at":clock.now()+Duration::seconds(30),"accepted_commit_id":commit,
    });
    Mock::given(method("POST"))
        .and(path("/_coland/account-authority/current-device/check"))
        .and(header(
            "authorization",
            "Bearer pairing-expiry-registered-channel",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .up_to_n_times(1)
        .expect(1)
        .mount(peer)
        .await;
    acquire_private_current_device_admission(
        &depot,
        account,
        binding.device_id.clone(),
        action,
        Some(binding),
        None,
        intent,
        clock.now(),
    )
    .await
    .unwrap()
}

fn pending_fixture(
    now: chrono::DateTime<chrono::Utc>,
    ttl: Duration,
    account: &arkret_wire::AccountId,
) -> (NewDevicePairingPendingRecord, DevicePairingTargetProof) {
    use arkret_models_collaboration::device_pairing::UnsignedDevicePairingTargetProof;
    use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
    use arkret_signatures::device_pairing::{
        server_device_pairing_transcript, sign_device_pairing_target_proof,
    };
    use arkret_wire::{Base64UrlString, DeviceId, DidKey, NonEmptyString};

    let key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[47; 32]);
    let device = DeviceId::new("ak:device:01999999-0000-7000-8000-000000000047").unwrap();
    let public_key = PublicKey {
        kty: NonEmptyString::new("OKP").unwrap(),
        kid: NonEmptyString::new(device.as_str()).unwrap(),
        algorithm: NonEmptyString::new("Ed25519").unwrap(),
        key: Base64UrlString::new(arkret_canonical::base64url_encode(
            key.verifying_key().as_bytes(),
        ))
        .unwrap(),
        key_digest: None,
    };
    let request_id = DevicePairingRequestId::new(
        "device_pairing_request:01999999-0000-7000-8000-000000000047".into(),
    )
    .unwrap();
    let stage_request = DevicePairingStageRequestBody {
        new_device_public_key: public_key.clone(),
        client_nonce: DevicePairingNonce::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        display_name: None,
        device_metadata: None,
    };
    let stage_outcome = DevicePairingStageResponseBody {
        device_pairing_request_id: request_id.clone(),
        pairing_code: DevicePairingCode::new("AAAAAA47".into()).unwrap(),
        gate_audience_uri: "https://account.example".into(),
        server_nonce: DevicePairingNonce::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap(),
        expires_at: now + ttl,
    };
    let challenge = ServerDevicePairingChallenge::from_stage(&stage_request, &stage_outcome);
    let (_, digest) = server_device_pairing_transcript(&public_key, &challenge).unwrap();
    let proof = sign_device_pairing_target_proof(
        UnsignedDevicePairingTargetProof::new(
            account.clone(),
            device,
            DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    key.verifying_key().as_bytes()
                )
            ))
            .unwrap(),
            NonEmptyString::new("hpke-public-key-fixture").unwrap(),
            vec![NonEmptyString::new("Ed25519").unwrap()],
            digest,
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    (
        NewDevicePairingPendingRecord {
            stage_idempotency_key: "pairing-window:47".into(),
            stage_request_digest: Hash::new(
                arkret_canonical::canonical_sha256(&stage_request).unwrap(),
            )
            .unwrap(),
            stage_outcome: arkret_canonical::canonical_json_bytes(&stage_outcome).unwrap(),
            device_pairing_request_id: request_id,
            pairing_code: stage_outcome.pairing_code,
            new_device_public_key: public_key,
            client_nonce: stage_request.client_nonce,
            display_name: None,
            device_metadata: None,
            gate_audience_uri: stage_outcome.gate_audience_uri,
            server_nonce: stage_outcome.server_nonce,
            expires_at: stage_outcome.expires_at,
            retained_until: stage_outcome.expires_at + Duration::hours(24),
            created_at: now,
        },
        proof,
    )
}

async fn seed_pending(
    factory: &coauth_storage_postgres::PgRepositoryFactory,
    pending: &NewDevicePairingPendingRecord,
    proof: &DevicePairingTargetProof,
    now: chrono::DateTime<chrono::Utc>,
) {
    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .insert_device_pairing_stage(pending.clone())
            .await
            .unwrap(),
        DevicePairingStageInsert::Inserted
    );
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                coauth_data::storage::account_handoff::DevicePairingFinalizeInput {
                    request_id: &pending.device_pairing_request_id,
                    pairing_code: &pending.pairing_code,
                    account_id: &proof.account_id,
                    target_proof: proof,
                    request_digest: &Hash::new(arkret_canonical::canonical_sha256(proof).unwrap())
                        .unwrap(),
                    canonical_outcome: b"{\"state\":\"ready_for_claim\"}",
                    now,
                }
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Committed(_)
    ));
    repo.save().await.unwrap();
}

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct PendingSnapshot {
    #[diesel(sql_type = diesel::sql_types::Text)]
    body: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    failures: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    dpop_count: i64,
}

async fn snapshot(conn: &mut diesel_async::AsyncPgConnection) -> PendingSnapshot {
    diesel::sql_query(
        "SELECT row_to_json(p)::text AS body, \
         (SELECT count(*) FROM device_pairing_abuse_ledger) AS failures, \
         (SELECT count(*) FROM dpop_jti_replay) AS dpop_count \
         FROM device_pairing_pending p",
    )
    .get_result(conn)
    .await
    .unwrap()
}

async fn wait_on_holder_lock(holder: &mut diesel_async::AsyncPgConnection) {
    tokio::time::timeout(WaitDuration::from_secs(5), async {
        loop {
            holder
                .batch_execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            let blocked = diesel::sql_query(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a \
                 WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() \
                 AND a.wait_event_type='Lock' \
                 AND pg_backend_pid()=ANY(pg_blocking_pids(a.pid))) AS acquired",
            )
            .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(holder)
            .await
            .unwrap()
            .acquired;
            if blocked {
                break;
            }
            tokio::time::sleep(WaitDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("the production pending operation must really await the row lock");
}

#[tokio::test]
async fn code_claim_row_wait_cannot_extend_current_device_observation() {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let clock = Arc::new(MockClock::new(
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    ));
    let (account, binding, commit) = authority_fixture();
    let (pending, proof) = pending_fixture(clock.now(), Duration::minutes(10), &account);
    seed_pending(&factory, &pending, &proof, clock.now()).await;
    let peer = MockServer::start().await;
    let observation = current_observation(
        &peer,
        &clock,
        &account,
        &binding,
        &commit,
        arkret_wire::DeviceRevocationDeniedAction::DevicePairingCodeClaim,
    )
    .await;
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    let before = snapshot(&mut holder).await;
    holder.batch_execute("BEGIN").await.unwrap();
    holder
        .batch_execute("SELECT 1 FROM device_pairing_pending FOR UPDATE")
        .await
        .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        let row = repo
            .account_handoff()
            .get_device_pairing_by_code(&pending.pairing_code, next_clock.now())
            .await
            .unwrap()
            .unwrap();
        assert!(row.expires_at > next_clock.now());
        let result = require_pairing_current_device_window(&observation, next_clock.now());
        repo.cancel().await.unwrap();
        result
    });
    wait_on_holder_lock(&mut holder).await;
    assert!(
        tokio::time::timeout(WaitDuration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    clock.advance(Duration::seconds(31));
    holder.batch_execute("ROLLBACK").await.unwrap();
    let result = tokio::time::timeout(WaitDuration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
            ..
        })
    ));
    assert_eq!(snapshot(&mut holder).await, before);
    assert_eq!(peer.received_requests().await.unwrap().len(), 1);
}

async fn first_fence_wait(delta: Duration, ttl: Duration) {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let clock = Arc::new(MockClock::new(
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    ));
    let (account, binding, commit) = authority_fixture();
    let (pending, proof) = pending_fixture(clock.now(), ttl, &account);
    seed_pending(&factory, &pending, &proof, clock.now()).await;
    let peer = MockServer::start().await;
    let observation = current_observation(
        &peer,
        &clock,
        &account,
        &binding,
        &commit,
        arkret_wire::DeviceRevocationDeniedAction::EventWrite,
    )
    .await;
    let request_bytes = b"{\"immutable_intent\":47}".to_vec();
    let admission = NewDevicePairingAdmission {
        device_pairing_request_id: pending.device_pairing_request_id.clone(),
        pairing_code: pending.pairing_code,
        approving_account_id: account.clone(),
        approving_device_id: binding.device_id.clone(),
        canonical_request_digest: Hash::new(arkret_canonical::sha256_digest(&request_bytes))
            .unwrap(),
        canonical_request_bytes: request_bytes,
        authorize_event_bytes: b"{\"same_original\":47}".to_vec(),
        authorize_event_id: binding.authorization_event_id.clone(),
    };
    // This exercises reserve/fence durability, not the subsequent Station
    // Event-signature admission (which has its separate real fixture).
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    let before = snapshot(&mut holder).await;
    holder.batch_execute("BEGIN").await.unwrap();
    holder
        .batch_execute("SELECT 1 FROM device_pairing_pending FOR UPDATE")
        .await
        .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let candidate = admission.clone();
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        let result = repo
            .account_handoff()
            .reserve_device_pairing_admission(candidate, next_clock.now())
            .await
            .unwrap();
        assert!(matches!(result, DevicePairingAdmissionReserve::Started(_)));
        let qualification = require_pairing_first_admission_current(
            &result,
            &observation,
            pending.expires_at,
            next_clock.now(),
        );
        repo.cancel().await.unwrap();
        qualification
    });
    wait_on_holder_lock(&mut holder).await;
    assert!(
        tokio::time::timeout(WaitDuration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    clock.advance(delta);
    holder.batch_execute("ROLLBACK").await.unwrap();
    let result = tokio::time::timeout(WaitDuration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    if delta >= ttl {
        assert!(matches!(result, Err(ArkretRouteError::NotFound)));
    } else {
        assert!(matches!(
            result,
            Err(ArkretRouteError::Coded {
                code: arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
                ..
            })
        ));
    }
    assert_eq!(snapshot(&mut holder).await, before);
    drop(holder);
    if delta < ttl {
        let fresh = current_observation(
            &peer,
            &clock,
            &account,
            &binding,
            &commit,
            arkret_wire::DeviceRevocationDeniedAction::EventWrite,
        )
        .await;
        let mut repo = factory.create().await.unwrap();
        let result = repo
            .account_handoff()
            .reserve_device_pairing_admission(admission.clone(), clock.now())
            .await
            .unwrap();
        require_pairing_first_admission_current(&result, &fresh, pending.expires_at, clock.now())
            .unwrap();
        assert!(matches!(result, DevicePairingAdmissionReserve::Started(_)));
        repo.save().await.unwrap();
        clock.advance(Duration::minutes(11));
        let mut repo = factory.create().await.unwrap();
        let result = repo
            .account_handoff()
            .reserve_device_pairing_admission(admission.clone(), clock.now())
            .await
            .unwrap();
        require_pairing_first_admission_current(&result, &fresh, pending.expires_at, clock.now())
            .unwrap();
        let DevicePairingAdmissionReserve::Resume(original) = result else {
            panic!("a durable same-intent fence must resume after both old windows");
        };
        assert_eq!(
            original.canonical_request_bytes,
            admission.canonical_request_bytes
        );
        assert_eq!(
            original.authorize_event_bytes,
            admission.authorize_event_bytes
        );
        repo.cancel().await.unwrap();
        assert_eq!(peer.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn first_pairing_fence_wait_cannot_extend_witness_but_exact_resume_is_historical() {
    first_fence_wait(Duration::seconds(31), Duration::minutes(10)).await;
}

#[tokio::test]
async fn first_pairing_fence_wait_cannot_extend_pending_even_with_a_live_witness() {
    first_fence_wait(Duration::seconds(11), Duration::seconds(10)).await;
}

fn verified_outer(
    now: chrono::DateTime<chrono::Utc>,
    near_bound: bool,
) -> arkret_signatures::dpop::VerifiedDpopProof {
    use arkret_signatures::dpop::{VerifiedDpopClaims, dpop_access_token_hash};
    use coauth_jose::jwa::AsymmetricSigningKey;
    use coauth_jose::jwk::{JsonWebKeyPublicParameters, PublicJsonWebKey};
    use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
    let signing = ed25519_dalek::SigningKey::from_bytes(&[65; 32]);
    let header: JsonWebSignatureHeader = serde_json::from_value(serde_json::json!({
        "alg":"Ed25519","typ":"dpop+jwt", "jwk":PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&signing.verifying_key())),
    })).unwrap();
    let secret = arkret_identifiers::SessionGrantSecret::from_bytes([81; 32]);
    let claims = VerifiedDpopClaims {
        jti: "pairing-last-authentication-window".into(),
        htm: "POST".into(),
        htu: "https://station.example/_arkret/gate/account/device-pairing/code-claims".into(),
        iat: now.timestamp() - if near_bound { 299 } else { 0 },
        ath: Some(dpop_access_token_hash(secret.as_str())),
        nonce: None,
    };
    let jwt = Jwt::sign(
        header,
        claims.clone(),
        &AsymmetricSigningKey::ed25519(signing),
    )
    .unwrap()
    .into_string();
    crate::services::dpop::DpopVerifier::verify_without_replay(
        &jwt,
        &claims.htm,
        &claims.htu,
        now,
        Some(secret.as_str()),
    )
    .unwrap()
}

/// A time-gate adapter test, not a replacement for the full issuer lookup and
/// HTTP authentication tests: the private carrier is assembled here from an
/// actual verified JWT and the ledger's exclusive-expiry field under test.
async fn credentials_cannot_outlive_pending_wait(outer_near_bound: bool, first_fence: bool) {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let clock = Arc::new(MockClock::new(now));
    let (account, binding, commit) = authority_fixture();
    let (pending, proof) = pending_fixture(now, Duration::minutes(10), &account);
    seed_pending(&factory, &pending, &proof, now).await;
    let verified = verified_outer(now, outer_near_bound);
    let authenticated = AuthenticatedCurrentDevice {
        account_id: account.clone(),
        local_account_id: coauth_data::Ulid::from(uuid::Uuid::from_u128(47)),
        device_id: binding.device_id.clone(),
        device_binding: binding.clone(),
        principal_control_realm_id: fixture_principal_control_realm(),
        credential_expires_at: now
            + if outer_near_bound {
                Duration::minutes(5)
            } else {
                Duration::seconds(1)
            },
        outer_dpop_valid_through: crate::services::dpop::verified_proof_valid_through(&verified)
            .unwrap(),
    };
    require_pairing_credentials_current(&authenticated, now).unwrap();
    let peer = MockServer::start().await;
    let observation = current_observation(
        &peer,
        &clock,
        &account,
        &binding,
        &commit,
        if first_fence {
            arkret_wire::DeviceRevocationDeniedAction::EventWrite
        } else {
            arkret_wire::DeviceRevocationDeniedAction::DevicePairingCodeClaim
        },
    )
    .await;
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    let before = snapshot(&mut holder).await;
    holder.batch_execute("BEGIN").await.unwrap();
    holder
        .batch_execute("SELECT 1 FROM device_pairing_pending FOR UPDATE")
        .await
        .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        if first_fence {
            let bytes = b"{\"intent\":47}".to_vec();
            let result = repo
                .account_handoff()
                .reserve_device_pairing_admission(
                    NewDevicePairingAdmission {
                        device_pairing_request_id: pending.device_pairing_request_id,
                        pairing_code: pending.pairing_code,
                        approving_account_id: account,
                        approving_device_id: binding.device_id,
                        canonical_request_digest: Hash::new(arkret_canonical::sha256_digest(
                            &bytes,
                        ))
                        .unwrap(),
                        canonical_request_bytes: bytes,
                        authorize_event_bytes: b"{\"original\":47}".to_vec(),
                        authorize_event_id: binding.authorization_event_id,
                    },
                    next_clock.now(),
                )
                .await
                .unwrap();
            assert!(matches!(result, DevicePairingAdmissionReserve::Started(_)));
        } else {
            assert!(
                repo.account_handoff()
                    .get_device_pairing_by_code(&pending.pairing_code, next_clock.now())
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        require_pairing_current_device_window(&observation, next_clock.now()).unwrap();
        assert!(next_clock.now() < pending.expires_at);
        let result = require_pairing_credentials_current(&authenticated, next_clock.now());
        repo.cancel().await.unwrap();
        result
    });
    wait_on_holder_lock(&mut holder).await;
    clock.advance(Duration::seconds(2));
    holder.batch_execute("ROLLBACK").await.unwrap();
    let result = tokio::time::timeout(WaitDuration::from_secs(10), &mut waiting)
        .await
        .unwrap()
        .unwrap();
    if outer_near_bound {
        assert!(matches!(
            result,
            Err(ArkretRouteError::Coded {
                code: arkret_wire::ErrorCode::SIGNATURE_INVALID,
                ..
            })
        ));
    } else {
        assert!(matches!(result, Err(ArkretRouteError::Unauthorized(_))));
    }
    assert_eq!(snapshot(&mut holder).await, before);
}

#[tokio::test]
async fn pairing_outer_dpop_cannot_outlive_first_fence_or_claim_row_waits() {
    credentials_cannot_outlive_pending_wait(true, true).await;
    credentials_cannot_outlive_pending_wait(true, false).await;
}

#[tokio::test]
async fn pairing_opaque_credential_cannot_outlive_first_fence_or_claim_row_waits() {
    credentials_cannot_outlive_pending_wait(false, true).await;
    credentials_cannot_outlive_pending_wait(false, false).await;
}

#[test]
fn pairing_credentials_keep_outer_inclusive_and_opaque_exclusive_boundaries() {
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let proof = verified_outer(now, true);
    let (account, binding, _) = authority_fixture();
    let through = crate::services::dpop::verified_proof_valid_through(&proof).unwrap();
    let mut authenticated = AuthenticatedCurrentDevice {
        account_id: account,
        local_account_id: coauth_data::Ulid::from(uuid::Uuid::from_u128(47)),
        device_id: binding.device_id.clone(),
        device_binding: binding,
        principal_control_realm_id: fixture_principal_control_realm(),
        credential_expires_at: through + Duration::seconds(1),
        outer_dpop_valid_through: through,
    };
    require_pairing_credentials_current(&authenticated, through).unwrap();
    assert!(
        require_pairing_credentials_current(&authenticated, through + Duration::nanoseconds(1))
            .is_err()
    );
    authenticated.credential_expires_at = through;
    assert!(require_pairing_credentials_current(&authenticated, through).is_err());
}

#[tokio::test]
async fn pairing_authentication_jti_wait_rolls_back_when_outer_or_opaque_expire() {
    for near_outer in [true, false] {
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let clock = Arc::new(MockClock::new(now));
        let (account, binding, _) = authority_fixture();
        let (pending, target_proof) = pending_fixture(now, Duration::minutes(10), &account);
        seed_pending(&factory, &pending, &target_proof, now).await;
        let proof = verified_outer(now, near_outer);
        let authenticated = AuthenticatedCurrentDevice {
            account_id: account,
            local_account_id: coauth_data::Ulid::from(uuid::Uuid::from_u128(47)),
            device_id: binding.device_id.clone(),
            device_binding: binding,
            principal_control_realm_id: fixture_principal_control_realm(),
            credential_expires_at: now
                + if near_outer {
                    Duration::minutes(5)
                } else {
                    Duration::seconds(1)
                },
            outer_dpop_valid_through: crate::services::dpop::verified_proof_valid_through(&proof)
                .unwrap(),
        };
        let row = crate::services::dpop::dpop_replay_record(&proof.claims.jti, now);
        let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
            .await
            .unwrap();
        let before = snapshot(&mut holder).await;
        holder.batch_execute("BEGIN").await.unwrap();
        diesel::sql_query("INSERT INTO dpop_jti_replay(jti_digest,seen_at,expires_at,created_at) VALUES($1,$2,$3,$2)")
            .bind::<diesel::sql_types::Text,_>(&row.jti_digest)
            .bind::<diesel::sql_types::Timestamptz,_>(row.seen_at)
            .bind::<diesel::sql_types::Timestamptz,_>(row.expires_at)
            .execute(&mut *holder).await.unwrap();
        let next_factory = factory.clone();
        let next_clock = Arc::clone(&clock);
        let mut waiting = tokio::spawn(async move {
            let mut repo = next_factory.create().await.unwrap();
            require_pairing_credentials_current(&authenticated, next_clock.now()).unwrap();
            assert!(
                repo.dpop_replay()
                    .consume_jti(crate::services::dpop::dpop_replay_record(
                        &proof.claims.jti,
                        next_clock.now()
                    ))
                    .await
                    .unwrap()
            );
            let result = require_pairing_credentials_current(&authenticated, next_clock.now());
            repo.cancel().await.unwrap();
            result
        });
        wait_on_holder_lock(&mut holder).await;
        clock.advance(Duration::seconds(2));
        holder.batch_execute("ROLLBACK").await.unwrap();
        let result = tokio::time::timeout(WaitDuration::from_secs(10), &mut waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
        assert_eq!(
            snapshot(&mut holder).await,
            before,
            "failed authentication must not retain its JTI or pairing effects"
        );
    }
}
