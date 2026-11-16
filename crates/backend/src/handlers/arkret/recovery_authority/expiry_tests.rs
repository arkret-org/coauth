//! PostgreSQL races for the production completion business-key inspector.
use std::sync::Arc;
use std::time::Duration as WaitDuration;

use coauth_data::clock::MockClock;
use coauth_data::{Clock as _, RepositoryFactory as _};
use diesel_async::SimpleAsyncConnection as _;
use rand_core::SeedableRng as _;

use super::*;

fn fixture() -> (
    RecoveryCompletionGrantRequestBody,
    arkret_wire::RecoveryCompletionAttestation,
) {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../arkret-spec/spec/v1/artifacts/fixtures/security-transaction-resilience-fixture.json"))).unwrap();
    let kat = &value["single_submit_recovery_kat"];
    (
        serde_json::from_value(kat["completion_request"].clone()).unwrap(),
        serde_json::from_value(kat["expected_outcome"]["completion_attestation"].clone()).unwrap(),
    )
}

#[test]
fn only_the_locked_expiry_problem_combination_permits_pending_pop_renewal() {
    let error = expired_unaccepted_completion();
    match error {
        ArkretRouteError::CodedDetailed {
            status,
            code,
            details,
            ..
        } => {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(code, arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED);
            assert_eq!(
                details,
                vec![("reason_code", serde_json::json!("proof_invalid"))]
            );
        }
        other => panic!("expiry fence must be typed and unambiguous: {other:?}"),
    }
    let ordinary = ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED,
        "fresh authentication required",
    );
    assert!(matches!(ordinary, ArkretRouteError::Coded { .. }));
    assert!(matches!(
        unauthenticated_handoff(),
        ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::UNAUTHENTICATED,
            ..
        }
    ));
    assert!(matches!(
        signature_invalid("wrong HTTP holder"),
        ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::SIGNATURE_INVALID,
            ..
        }
    ));
}

async fn seed_accepted(
    repo: &mut coauth_data::BoxRepository,
    request: &RecoveryCompletionGrantRequestBody,
    completion: &arkret_wire::RecoveryCompletionAttestation,
    clock: &MockClock,
) -> Vec<u8> {
    seed_first_attempt(
        repo,
        request,
        completion,
        clock,
        request.accepted_device_possession_proof.expires_at,
    )
    .await
    .expect("fresh first issuer authorization")
}

async fn seed_first_attempt(
    repo: &mut coauth_data::BoxRepository,
    request: &RecoveryCompletionGrantRequestBody,
    completion: &arkret_wire::RecoveryCompletionAttestation,
    clock: &MockClock,
    proof_deadline: DateTime<Utc>,
) -> Result<Vec<u8>, coauth_data::SessionGrantOperation> {
    let issuer = &request.terminal_receipt.session_grant_ref.issuer_id;
    let account = &request.terminal_receipt.account_id;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(19);
    let user = repo
        .user()
        .add(&mut rng, clock, "completion-race".into())
        .await
        .unwrap();
    let local = coauth_data::LocalAccountId::new(user.id.to_string()).unwrap();
    let canonical_request = arkret_canonical::canonical_json_bytes(request).unwrap();
    let identity = arkret_canonical::sha256_digest(request.operation_identity(issuer).unwrap());
    let not_before = clock.now();
    let expires_at = not_before + Duration::minutes(15);
    let operation = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            clock,
            NewSessionGrantOperation {
                issuer_id: issuer.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: Some(SessionGrantProofKind::AccountHandoff),
                request_identity: &identity,
                canonical_intent_digest: arkret_canonical::sha256_bytes(&canonical_request),
                canonical_intent: &canonical_request,
                target_session_grant_id: None,
                grant_not_before: Some(not_before),
                grant_expires_at: Some(expires_at),
                retained_until: expires_at + Duration::days(7),
            },
        )
        .await
        .unwrap();
    let SessionGrantReserveOutcome::Reserved(operation) = operation else {
        panic!("fresh issuer operation required")
    };
    let seed = SessionGrantIssuanceSeed::from_operation(&operation).unwrap();
    let device = request.initial_session.device_id.clone();
    let key = request.initial_session.session_public_key.clone();
    let metadata = arkret_models_identity::SessionGrantMetadata {
        id: seed.grant_id.clone(),
        issuer_id: issuer.clone(),
        account_id: account.clone(),
        device_id: Some(device.clone()),
        audience_id: account.station_id.clone(),
        scopes: STANDARD_INITIAL_SESSION_GRANT_OPERATIONS
            .iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
        not_before,
        expires_at,
        session_id: seed.session_id.clone(),
        cnf_jkt: key.thumbprint_sha256().unwrap(),
        session_public_key: key.clone(),
        credential_class: arkret_models_identity::SessionGrantCredentialClass::Standard,
        holder_binding: arkret_models_identity::SessionGrantHolderBinding::HumanDevice {
            device_binding: device.to_string(),
        },
        device_binding: Some(arkret_models_identity::SessionGrantDeviceBinding {
            device_id: device.clone(),
            authorization_event_id: completion.device_authorization_event_ref.event_id.clone(),
            model_generation_ref: completion.new_model_generation_ref,
        }),
        proof_kind: Some(SessionGrantProofKind::AccountHandoff),
        scope_details: None,
    };
    metadata.validate().unwrap();
    let outcome = IssueRecoveryCompletionGrantResponseBody {
        transaction_id: request.terminal_receipt.transaction_id.clone(),
        issued_at: not_before,
        issued_session: SessionGrantResponseBody {
            account_id: account.clone(),
            issuer_id: issuer.clone(),
            device_id: Some(device.clone()),
            session_grant: seed.session_grant.clone(),
            expires_at,
            session_grant_id: seed.grant_id.clone(),
            session_public_key: key,
            audience_id: account.station_id.clone(),
            granted_scope: metadata.scopes.clone(),
            previous_session_grant_id: None,
        },
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
    let checkpoint = serde_json::json!({"kind":"accepted_native_recovery_test", "completion_attestation":completion});
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            &mut rng,
            clock,
            operation.id,
            SessionGrantProofAuthorization {
                authorization_ref: &identity,
                checkpoint: &checkpoint,
                proof_expires_at: proof_deadline,
            },
            SessionGrantExactOutcome {
                canonical_response: &canonical_outcome,
                response_digest: arkret_canonical::sha256_bytes(&canonical_outcome),
            },
            coauth_data::storage::oauth::NewSessionGrant {
                grant_id: seed.grant_id,
                browser_session_id: None,
                issuer_id: issuer,
                subject_id: &account.principal_id,
                local_account_id: &local,
                device_id: Some(device.as_str()),
                audience_id: &account.station_id,
                scope: metadata
                    .scopes
                    .iter()
                    .map(|scope| {
                        scope
                            .parse::<coauth_oauth_types::scope::ScopeToken>()
                            .unwrap()
                    })
                    .collect(),
                session_grant: &seed.session_grant,
                metadata: &metadata,
                session_id: &metadata.session_id,
                session_public_key: metadata.session_public_key.as_str(),
                credential_class: "standard",
                not_before,
                expires_at,
            },
        )
        .await
        .unwrap();
    match committed {
        SessionGrantCommitOutcome::Committed(_) => {}
        SessionGrantCommitOutcome::AuthorizationExpired(operation) => return Err(operation),
        other => panic!("unexpected first issuer outcome: {other:?}"),
    }
    assert!(
        repo.recovery_authority()
            .insert_completion_issuance(NewRecoveryCompletionGrantIssuance {
                issuer_id: issuer.clone(),
                account_id: account.clone(),
                transaction_id: request.terminal_receipt.transaction_id.clone(),
                terminal_receipt_digest: request.terminal_receipt.receipt_digest().unwrap(),
                local_account_id: user.id,
                reanchor_ref: completion.reanchor_event_ref.clone(),
                device_authorization_ref: completion.device_authorization_event_ref.clone(),
                new_model_generation_ref: completion.new_model_generation_ref,
                canonical_request_digest: request.canonical_request_digest.clone(),
                canonical_request,
                session_grant_operation_id: operation.id,
                canonical_outcome: canonical_outcome.clone(),
                issued_at: not_before,
            })
            .await
            .unwrap()
    );
    Ok(canonical_outcome)
}

async fn wait_for_completion_business_lock(
    pool: &coauth_storage_postgres::test_utils::TestDatabase,
    request: &RecoveryCompletionGrantRequestBody,
    issuer: &arkret_identifiers::DidCoreId,
) {
    use horme::RunQueryDsl as _;

    let identity = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "issuer_id": issuer,
        "operation": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1,
        "account_id": request.terminal_receipt.account_id,
        "transaction_id": request.terminal_receipt.transaction_id,
    })).unwrap();
    let key = coauth_storage_postgres::advisory_lock::advisory_lock_key(&format!(
        "coauth:recovery-completion:{}",
        arkret_canonical::sha256_digest(identity)
    ));
    let mut observer = coauth_storage_postgres::pool::queries(pool);
    tokio::time::timeout(WaitDuration::from_secs(5), async {
        loop {
            let blocked = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_locks w JOIN pg_locks h ON h.locktype=w.locktype AND h.database=w.database AND h.classid=w.classid AND h.objid=w.objid AND h.objsubid=w.objsubid WHERE w.locktype='advisory' AND NOT w.granted AND h.granted AND w.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND w.classid=0 AND w.objid::bigint=$1 AND h.pid=ANY(pg_blocking_pids(w.pid))) AS acquired")
                .bind::<diesel::sql_types::BigInt, _>(key)
                .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut observer)
                .await.unwrap().acquired;
            if blocked {
                break;
            }
            tokio::time::sleep(WaitDuration::from_millis(10)).await;
        }
    }).await.expect("completion inspector must actually wait on its exact business-key lock");
}

#[tokio::test]
async fn old_request_waiting_for_the_business_lock_cannot_accept_after_expiry() {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, _) = fixture();
    let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let mut holder = factory.create().await.unwrap();
    holder
        .recovery_authority()
        .lock_completion_business_key(
            &issuer,
            &request.terminal_receipt.account_id,
            &request.terminal_receipt.transaction_id,
        )
        .await
        .unwrap();
    let observed_request = request.clone();
    let observed_issuer = issuer.clone();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        let result = inspect_completion_attempt(&mut repo, &request, &issuer, &*next_clock)
            .await
            .unwrap();
        repo.cancel().await.unwrap();
        result
    });
    wait_for_completion_business_lock(&pool, &observed_request, &observed_issuer).await;
    clock.advance(Duration::minutes(6));
    holder.cancel().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(WaitDuration::from_secs(10), waiting)
            .await
            .unwrap()
            .unwrap(),
        CompletionAttempt::ExpiredUnaccepted
    ));
}

#[tokio::test]
async fn accepted_before_the_expiry_probe_replays_original_bytes_after_old_pop_expires() {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, completion) = fixture();
    let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let mut holder = factory.create().await.unwrap();
    holder
        .recovery_authority()
        .lock_completion_business_key(
            &issuer,
            &request.terminal_receipt.account_id,
            &request.terminal_receipt.transaction_id,
        )
        .await
        .unwrap();
    let bytes = seed_accepted(&mut holder, &request, &completion, &clock).await;
    let stored_request = request.clone();
    let observed_request = request.clone();
    let observed_issuer = issuer.clone();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        let result = inspect_completion_attempt(&mut repo, &request, &issuer, &*next_clock)
            .await
            .unwrap();
        repo.cancel().await.unwrap();
        result
    });
    wait_for_completion_business_lock(&pool, &observed_request, &observed_issuer).await;
    clock.advance(Duration::minutes(6));
    holder.save().await.unwrap();
    let CompletionAttempt::Accepted(record) =
        tokio::time::timeout(WaitDuration::from_secs(10), waiting)
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("accepted history must win over the old proof's expiry")
    };
    assert_eq!(record.canonical_outcome, bytes);
    let original: RecoveryCompletionGrantRequestBody =
        serde_json::from_slice(&record.canonical_request).unwrap();
    stored_request
        .validate_exact_replay(
            &original,
            &record.account_id,
            &stored_request.accepted_device_possession_proof.holder_jkt,
        )
        .unwrap();
}

async fn seed_handoff(
    factory: &coauth_storage_postgres::PgRepositoryFactory,
    request: &RecoveryCompletionGrantRequestBody,
    clock: &MockClock,
    expires_at: DateTime<Utc>,
    tag: u64,
) -> coauth_data::AccountHandoffGrant {
    let mut repo = factory.create().await.unwrap();
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(tag);
    let user = repo
        .user()
        .add(&mut rng, clock, format!("completion-handoff-{tag}"))
        .await
        .unwrap();
    let browser = repo
        .browser_session()
        .add(&mut rng, clock, &user, None)
        .await
        .unwrap();
    let coauth_data::AccountHandoffCreation::Active { grant, .. } = repo
        .account_handoff()
        .create_with_lease(coauth_data::AccountHandoffGrantInput {
            id: coauth_data::Ulid::from(uuid::Uuid::from_u128(u128::from(tag))),
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:00000000-0000-7000-8000-{tag:012x}"
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                format!("handoff-{tag}"),
            ))
            .unwrap(),
            local_account_id: user.id,
            browser_session_id: Some(browser.id),
            audience_id: request.terminal_receipt.account_id.station_id.to_string(),
            account_subject: request
                .accepted_device_possession_proof
                .account_subject
                .clone(),
            risk_decision: coauth_data::IdentityCreationLeaseRiskDecision::Allowed,
            cnf_jkt: request.accepted_device_possession_proof.holder_jkt.clone(),
            account_handoff_grant: format!("handoff-{tag:036x}"),
            issued_at: clock.now(),
            expires_at,
            lease_id: format!("lease-{tag:018x}"),
            lease_expires_at: expires_at,
        })
        .await
        .unwrap()
    else {
        panic!("a new native handoff must have an active creation lease")
    };
    repo.save().await.unwrap();
    grant
}

async fn issuer_and_handoff_snapshot(
    pool: &coauth_storage_postgres::test_utils::TestDatabase,
) -> serde_json::Value {
    use horme::RunQueryDsl as _;

    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }

    let mut connection = coauth_storage_postgres::pool::queries(pool);
    diesel::sql_query("SELECT jsonb_build_object(
        'grants', COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM oauth_session_grants g), '[]'::jsonb),
        'operations', COALESCE((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM oauth_session_grant_operations o), '[]'::jsonb),
        'completions', COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.issuer_id, c.principal_id, c.account_station_id, c.transaction_id) FROM recovery_completion_grant_issuances c), '[]'::jsonb),
        'handoffs', COALESCE((SELECT jsonb_agg(to_jsonb(h) ORDER BY h.id) FROM account_handoff_grants h), '[]'::jsonb),
        'dpop', COALESCE((SELECT jsonb_agg(to_jsonb(d) ORDER BY d.jti_digest) FROM dpop_jti_replay d), '[]'::jsonb)
    ) AS value")
        .get_result::<Snapshot>(&mut connection).await.unwrap().value
}

#[tokio::test]
async fn late_business_lock_cannot_extend_handoff_even_while_inner_pop_is_valid() {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, _) = fixture();
    let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let handoff = seed_handoff(
        &factory,
        &request,
        &clock,
        clock.now() + Duration::seconds(10),
        101,
    )
    .await;
    let before = issuer_and_handoff_snapshot(&pool).await;
    let mut holder = factory.create().await.unwrap();
    holder
        .recovery_authority()
        .lock_completion_business_key(
            &issuer,
            &request.terminal_receipt.account_id,
            &request.terminal_receipt.transaction_id,
        )
        .await
        .unwrap();
    let proof_expires_at = request.accepted_device_possession_proof.expires_at;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        started_tx.send(()).unwrap();
        assert!(matches!(
            inspect_completion_attempt(&mut repo, &request, &issuer, &*next_clock)
                .await
                .unwrap(),
            CompletionAttempt::Unaccepted
        ));
        let result = fresh_completion_handoff_at_cut(&mut repo, &handoff, &*next_clock).await;
        repo.cancel().await.unwrap();
        result
    });
    started_rx.await.unwrap();
    assert!(
        tokio::time::timeout(WaitDuration::from_millis(50), &mut waiting)
            .await
            .is_err()
    );
    clock.advance(Duration::seconds(20));
    assert!(clock.now() < proof_expires_at, "only the handoff expired");
    holder.cancel().await.unwrap();
    let result = tokio::time::timeout(WaitDuration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(ArkretRouteError::Coded {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::ErrorCode::UNAUTHENTICATED,
            ..
        })
    ));
    assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
}

#[tokio::test]
async fn revoked_handoff_during_business_lock_wait_is_not_fresh_authentication() {
    use horme::RunQueryDsl as _;

    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, _) = fixture();
    let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let handoff = seed_handoff(
        &factory,
        &request,
        &clock,
        clock.now() + Duration::minutes(5),
        102,
    )
    .await;
    let handoff_id = uuid::Uuid::from(handoff.id);
    let mut holder = factory.create().await.unwrap();
    holder
        .recovery_authority()
        .lock_completion_business_key(
            &issuer,
            &request.terminal_receipt.account_id,
            &request.terminal_receipt.transaction_id,
        )
        .await
        .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        started_tx.send(()).unwrap();
        assert!(matches!(
            inspect_completion_attempt(&mut repo, &request, &issuer, &*next_clock)
                .await
                .unwrap(),
            CompletionAttempt::Unaccepted
        ));
        let result = fresh_completion_handoff_at_cut(&mut repo, &handoff, &*next_clock).await;
        repo.cancel().await.unwrap();
        result
    });
    started_rx.await.unwrap();
    assert!(
        tokio::time::timeout(WaitDuration::from_millis(50), &mut waiting)
            .await
            .is_err()
    );
    let mut connection = coauth_storage_postgres::pool::queries(&pool);
    assert_eq!(
        diesel::sql_query("UPDATE account_handoff_grants SET revoked_at = $1 WHERE id = $2")
            .bind::<diesel::sql_types::Timestamptz, _>(clock.now())
            .bind::<diesel::sql_types::Uuid, _>(handoff_id)
            .execute(&mut connection)
            .await
            .unwrap(),
        1
    );
    let after_revoke = issuer_and_handoff_snapshot(&pool).await;
    holder.cancel().await.unwrap();
    let result = tokio::time::timeout(WaitDuration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::UNAUTHENTICATED,
            ..
        })
    ));
    assert_eq!(after_revoke, issuer_and_handoff_snapshot(&pool).await);
}

fn current_device_depot(endpoint: url::Url, station: &arkret_identifiers::DidCoreId) -> Depot {
    crate::handlers::test_utils::setup();
    crate::services::station_trust::shared().insert_for_test(&endpoint, station.as_str());
    let mut depot = Depot::new();
    depot.insert(
        "arkret_config",
        coauth_config::ArkretConfig {
            stations: vec![coauth_config::StationConfig {
                name: "completion-origin".into(),
                endpoint,
                internal_authority_shared_secret: Some(coauth_config::ClientSecret::Value(
                    "completion-test-registered-channel".into(),
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
    depot
}

/// This is a native PG lock plus the production private-HTTP adapter. The
/// configured peer below supplies observable revoked/reanchored decisions and
/// a clock advance while the RPC is in flight;
/// this does not stand in for a Coland end-to-end device transition test.
#[tokio::test]
async fn replacement_and_first_proof_are_admitted_after_business_lock_and_rpc_waits() {
    use std::sync::atomic::{AtomicU8, Ordering};

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    for (case, decision, expected_code) in [
        (1, "revoked", arkret_wire::ErrorCode::DEVICE_REVOKED),
        (
            2,
            "generation_mismatch",
            arkret_wire::ErrorCode::DEVICE_REVOKED,
        ),
        (3, "allow", arkret_wire::ErrorCode::SIGNATURE_INVALID),
        (4, "allow", arkret_wire::ErrorCode::UNAUTHENTICATED),
    ] {
        let (request, completion) = fixture();
        let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
        let clock = Arc::new(MockClock::new(
            request.accepted_device_possession_proof.issued_at,
        ));
        let handoff = seed_handoff(
            &factory,
            &request,
            &clock,
            clock.now()
                + if case == 4 {
                    Duration::seconds(10)
                } else {
                    Duration::minutes(15)
                },
            110 + case,
        )
        .await;
        let before = issuer_and_handoff_snapshot(&pool).await;
        let expected = arkret_models_identity::SessionGrantDeviceBinding {
            device_id: request.terminal_receipt.new_device_id.clone(),
            authorization_event_id: completion.device_authorization_event_ref.event_id.clone(),
            model_generation_ref: request.terminal_receipt.new_model_generation_ref,
        };
        let server = MockServer::start().await;
        let depot = current_device_depot(
            server.uri().parse().unwrap(),
            &request.terminal_receipt.account_id.station_id,
        );
        let current_decision = Arc::new(AtomicU8::new(0));
        let peer_decision = Arc::clone(&current_decision);
        let peer_clock = Arc::clone(&clock);
        let peer_request = request.clone();
        let peer_expected = expected.clone();
        Mock::given(method("POST"))
            .and(path("/_coland/account-authority/current-device/check"))
            .and(header(
                "authorization",
                "Bearer completion-test-registered-channel",
            ))
            .respond_with(move |http_request: &wiremock::Request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&http_request.body).unwrap();
                let proof = arkret_wire::AcceptedDevicePossessionProof::Issue(
                    peer_request.accepted_device_possession_proof.clone(),
                );
                assert_eq!(
                    body["account_id"],
                    serde_json::to_value(&peer_request.terminal_receipt.account_id).unwrap()
                );
                assert_eq!(body["device_id"], serde_json::json!(peer_expected.device_id));
                assert_eq!(
                    body["expected_device_authorize_event_id"],
                    serde_json::json!(peer_expected.authorization_event_id)
                );
                assert_eq!(
                    body["expected_device_generation_ref"],
                    serde_json::json!(peer_expected.model_generation_ref)
                );
                assert_eq!(
                    body["accepted_device_possession_proof"],
                    serde_json::to_value(&proof).unwrap()
                );
                let allow = peer_decision.load(Ordering::SeqCst) == 0 || decision == "allow";
                let now = peer_clock.now();
                let mut response = serde_json::json!({
                    "account_id": peer_request.terminal_receipt.account_id,
                    "device_id": peer_expected.device_id,
                    "authorization_event_id": peer_expected.authorization_event_id,
                    "device_generation_ref": peer_expected.model_generation_ref,
                    "action_class": "session_grant_issue_or_refresh",
                    "intent_digest": peer_request.accepted_device_possession_proof.session_intent_digest,
                    "accepted_device_possession_proof_digest": proof.proof_digest().unwrap(),
                    "decision": if allow { "allow" } else { decision },
                    "linearization_seq": 1,
                    "linearized_at": now,
                    "expires_at": now + Duration::seconds(30),
                    "accepted_commit_id": completion.device_authorization_event_ref.commit_id,
                });
                if !allow {
                    response["authorization_event_id"] = serde_json::Value::Null;
                    response["device_generation_ref"] = serde_json::Value::Null;
                    response["accepted_commit_id"] = serde_json::Value::Null;
                }
                if decision == "allow" {
                    // The one RPC was requested while the original proof was
                    // fresh. Its return cannot extend that first-use window.
                    peer_clock.advance(Duration::minutes(6));
                }
                ResponseTemplate::new(200).set_body_json(response)
            })
            .expect(1)
            .mount(&server)
            .await;
        let mut holder = factory.create().await.unwrap();
        holder
            .recovery_authority()
            .lock_completion_business_key(
                &issuer,
                &request.terminal_receipt.account_id,
                &request.terminal_receipt.transaction_id,
            )
            .await
            .unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let next_factory = factory.clone();
        let next_clock = Arc::clone(&clock);
        let candidate_completion = fixture().1;
        let mut waiting = tokio::spawn(async move {
            let mut repo = next_factory.create().await.unwrap();
            started_tx.send(()).unwrap();
            assert!(matches!(
                inspect_completion_attempt(&mut repo, &request, &issuer, &*next_clock)
                    .await
                    .unwrap(),
                CompletionAttempt::Unaccepted
            ));
            fresh_completion_handoff_at_cut(&mut repo, &handoff, &*next_clock)
                .await
                .unwrap();
            let result = async {
                let admission = acquire_private_current_device_admission(
                    &depot,
                    &request.terminal_receipt.account_id,
                    expected.device_id.clone(),
                    arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
                    Some(&expected),
                    Some(arkret_wire::AcceptedDevicePossessionProof::Issue(
                        request.accepted_device_possession_proof.clone(),
                    )),
                    request
                        .accepted_device_possession_proof
                        .session_intent_digest
                        .clone(),
                    next_clock.now(),
                )
                .await
                .map_err(recovery_completion_device_refusal)?;
                let binding = admission.binding;
                assert_eq!(binding, expected);
                let now =
                    fresh_completion_handoff_at_cut(&mut repo, &handoff, &*next_clock).await?;
                let proof = &request.accepted_device_possession_proof;
                request
                    .validate_first_issue(
                        &candidate_completion,
                        &proof.account_subject,
                        &proof.account_handoff_grant_digest,
                        &proof.holder_jkt,
                        now,
                    )
                    .map_err(|error| signature_invalid(error.to_string()))?;
                Ok(binding)
            }
            .await;
            repo.cancel().await.unwrap();
            result
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(WaitDuration::from_millis(50), &mut waiting)
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        current_decision.store(1, Ordering::SeqCst);
        holder.cancel().await.unwrap();
        let result = tokio::time::timeout(WaitDuration::from_secs(10), waiting)
            .await
            .unwrap()
            .unwrap();
        match result {
            Err(ArkretRouteError::Coded { code, .. }) => assert_eq!(code, expected_code),
            other => panic!("{decision} must refuse before issuer writes: {other:?}"),
        }
        assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
        server.verify().await;
    }
}

#[tokio::test]
async fn accepted_replay_handoff_remains_fresh_without_readmitting_the_historical_inner_pop() {
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, _) = fixture();
    let clock = MockClock::new(request.accepted_device_possession_proof.issued_at);
    let handoff = seed_handoff(
        &factory,
        &request,
        &clock,
        clock.now() + Duration::minutes(10),
        120,
    )
    .await;
    let mut repo = factory.create().await.unwrap();
    assert!(
        repo.account_handoff()
            .consume_grant(&handoff, clock.now())
            .await
            .unwrap()
    );
    repo.save().await.unwrap();
    let before = issuer_and_handoff_snapshot(&pool).await;
    clock.advance(Duration::minutes(6));
    assert!(clock.now() >= request.accepted_device_possession_proof.expires_at);
    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        fresh_completion_handoff_at_cut(&mut repo, &handoff, &clock)
            .await
            .unwrap(),
        clock.now()
    );
    request
        .validate_exact_replay(
            &request,
            &request.terminal_receipt.account_id,
            &handoff.cnf_jkt,
        )
        .unwrap();
    repo.cancel().await.unwrap();
    assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
}

async fn first_commit_waits_past_qualification(delta: Duration) {
    use horme::RunQueryDsl as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, completion) = fixture();
    let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let expected = arkret_models_identity::SessionGrantDeviceBinding {
        device_id: request.terminal_receipt.new_device_id.clone(),
        authorization_event_id: completion.device_authorization_event_ref.event_id.clone(),
        model_generation_ref: completion.new_model_generation_ref,
    };
    let peer = MockServer::start().await;
    let depot = current_device_depot(
        peer.uri().parse().unwrap(),
        &request.terminal_receipt.account_id.station_id,
    );
    let proof = arkret_wire::AcceptedDevicePossessionProof::Issue(
        request.accepted_device_possession_proof.clone(),
    );
    let peer_clock = Arc::clone(&clock);
    let response_base = serde_json::json!({
        "account_id":request.terminal_receipt.account_id,
        "device_id":expected.device_id,"authorization_event_id":expected.authorization_event_id,
        "device_generation_ref":expected.model_generation_ref,"action_class":"session_grant_issue_or_refresh",
        "intent_digest":request.accepted_device_possession_proof.session_intent_digest,
        "accepted_device_possession_proof_digest":proof.proof_digest().unwrap(),
        "decision":"allow","linearization_seq":1,
        "accepted_commit_id":completion.device_authorization_event_ref.commit_id,
    });
    Mock::given(method("POST"))
        .and(path("/_coland/account-authority/current-device/check"))
        .and(header(
            "authorization",
            "Bearer completion-test-registered-channel",
        ))
        .respond_with(move |_: &wiremock::Request| {
            let mut body = response_base.clone();
            body["linearized_at"] = serde_json::json!(peer_clock.now());
            body["expires_at"] = serde_json::json!(peer_clock.now() + Duration::seconds(30));
            ResponseTemplate::new(200).set_body_json(body)
        })
        .expect(if delta < Duration::minutes(5) { 2 } else { 1 })
        .mount(&peer)
        .await;
    let observation = acquire_private_current_device_admission(
        &depot,
        &request.terminal_receipt.account_id,
        expected.device_id.clone(),
        arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        Some(&expected),
        Some(proof.clone()),
        request
            .accepted_device_possession_proof
            .session_intent_digest
            .clone(),
        clock.now(),
    )
    .await
    .unwrap();
    assert_eq!(observation.binding, expected);
    let deadline = observation
        .expires_at()
        .min(request.accepted_device_possession_proof.expires_at);
    let before = issuer_and_handoff_snapshot(&pool).await;
    // Hold the real last issuer lock, not a process mutex or a fabricated wait.
    let key = coauth_storage_postgres::advisory_lock::advisory_lock_key(&format!(
        "coauth:session-grant-ledger:{issuer}:{}",
        request.terminal_receipt.account_id.principal_id
    ));
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query("SELECT pg_advisory_xact_lock($1),true AS acquired")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder)
        .await
        .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let candidate = request.clone();
    let witness = completion.clone();
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        assert!(matches!(
            inspect_completion_attempt(
                &mut repo,
                &candidate,
                &candidate.terminal_receipt.session_grant_ref.issuer_id,
                &*next_clock
            )
            .await
            .unwrap(),
            CompletionAttempt::Unaccepted
        ));
        let result =
            seed_first_attempt(&mut repo, &candidate, &witness, &next_clock, deadline).await;
        assert!(
            result.is_err(),
            "a first outcome must not survive the last-lock deadline"
        );
        repo.cancel().await.unwrap();
    });
    tokio::time::timeout(WaitDuration::from_secs(5), async {
        loop {
            let blocked = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=0 AND objid::bigint=$1) AS acquired")
                .bind::<diesel::sql_types::BigInt,_>(key)
                .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder).await.unwrap().acquired;
            if blocked { break; }
            tokio::time::sleep(WaitDuration::from_millis(10)).await;
        }
    }).await.expect("issuer must actually wait on the subject lock");
    assert!(
        tokio::time::timeout(WaitDuration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    clock.advance(delta);
    holder.batch_execute("ROLLBACK").await.unwrap();
    drop(holder);
    tokio::time::timeout(WaitDuration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
    let mut repo = factory.create().await.unwrap();
    let state = inspect_completion_attempt(&mut repo, &request, &issuer, &*clock)
        .await
        .unwrap();
    repo.cancel().await.unwrap();
    if clock.now() >= request.accepted_device_possession_proof.expires_at {
        assert!(matches!(state, CompletionAttempt::ExpiredUnaccepted));
    } else {
        assert!(
            matches!(state, CompletionAttempt::Unaccepted),
            "witness expiry cannot authorize a PoP replacement"
        );
        // Exact body retry obtains a new private observation window; no stale
        // reserved seed or outcome survived the rolled-back first transaction.
        let renewed = acquire_private_current_device_admission(
            &depot,
            &request.terminal_receipt.account_id,
            expected.device_id.clone(),
            arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            Some(&expected),
            Some(proof),
            request
                .accepted_device_possession_proof
                .session_intent_digest
                .clone(),
            clock.now(),
        )
        .await
        .unwrap();
        let mut repo = factory.create().await.unwrap();
        let bytes = seed_first_attempt(
            &mut repo,
            &request,
            &completion,
            &clock,
            renewed
                .expires_at()
                .min(request.accepted_device_possession_proof.expires_at),
        )
        .await
        .unwrap();
        repo.save().await.unwrap();
        clock.advance(Duration::minutes(6));
        let mut replay = factory.create().await.unwrap();
        let CompletionAttempt::Accepted(record) =
            inspect_completion_attempt(&mut replay, &request, &issuer, &*clock)
                .await
                .unwrap()
        else {
            panic!("accepted outcome must outlive historical PoP");
        };
        assert_eq!(record.canonical_outcome, bytes);
        replay.cancel().await.unwrap();
    }
    peer.verify().await;
}

#[tokio::test]
async fn issuer_subject_lock_cannot_extend_first_pop_after_business_and_head_checks() {
    first_commit_waits_past_qualification(Duration::minutes(6)).await;
}

#[tokio::test]
async fn issuer_subject_lock_cannot_extend_device_witness_and_exact_retry_still_commits_once() {
    first_commit_waits_past_qualification(Duration::seconds(31)).await;
}

#[tokio::test]
async fn final_handoff_row_wait_requires_a_new_clock_and_rollback_before_pop_renewal() {
    use horme::RunQueryDsl as _;
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, _) = fixture();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let handoff = seed_handoff(
        &factory,
        &request,
        &clock,
        clock.now() + Duration::minutes(10),
        150,
    )
    .await;
    let before = issuer_and_handoff_snapshot(&pool).await;
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query("SELECT true AS acquired FROM account_handoff_grants WHERE id=$1 FOR UPDATE")
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::from(handoff.id))
        .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder)
        .await
        .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
        assert!(matches!(
            inspect_completion_attempt(&mut repo, &request, &issuer, &*next_clock)
                .await
                .unwrap(),
            CompletionAttempt::Unaccepted
        ));
        let before_wait = fresh_completion_handoff_at_cut(&mut repo, &handoff, &*next_clock)
            .await
            .unwrap();
        assert!(
            repo.account_handoff()
                .consume_grant(&handoff, before_wait)
                .await
                .unwrap()
        );
        let after_wait = fresh_completion_handoff_at_cut(&mut repo, &handoff, &*next_clock)
            .await
            .unwrap();
        assert!(after_wait >= request.accepted_device_possession_proof.expires_at);
        // The endpoint's stale path cancels all unpublished effects before
        // the existing business inspector may authorize only a PoP renewal.
        repo.cancel().await.unwrap();
        let mut probe = next_factory.create().await.unwrap();
        assert!(matches!(
            inspect_completion_attempt(&mut probe, &request, &issuer, &*next_clock)
                .await
                .unwrap(),
            CompletionAttempt::ExpiredUnaccepted
        ));
        probe.cancel().await.unwrap();
    });
    tokio::time::timeout(WaitDuration::from_secs(5), async {
        loop {
            holder.batch_execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
            let blocked = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.wait_event_type='Lock' AND pg_backend_pid()=ANY(pg_blocking_pids(a.pid))) AS acquired")
                .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder).await.unwrap().acquired;
            if blocked { break; }
            tokio::time::sleep(WaitDuration::from_millis(10)).await;
        }
    }).await.expect("the real conditional handoff consumption must wait");
    assert!(
        tokio::time::timeout(WaitDuration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    clock.advance(Duration::minutes(6));
    holder.batch_execute("ROLLBACK").await.unwrap();
    drop(holder);
    tokio::time::timeout(WaitDuration::from_secs(10), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
}

/// The KAT's actual initial-session holder key (recovery_commit_kat.py), not
/// a fabricated VerifiedDpopProof or a caller-supplied deadline.
fn near_expiry_outer(
    handoff: &coauth_data::AccountHandoffGrant,
    now: DateTime<Utc>,
    jti: &str,
) -> arkret_signatures::dpop::VerifiedDpopProof {
    use arkret_signatures::dpop::{VerifiedDpopClaims, dpop_access_token_hash};
    use coauth_jose::jwa::AsymmetricSigningKey;
    use coauth_jose::jwk::{JsonWebKeyPublicParameters, PublicJsonWebKey};
    use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};

    let seed: [u8; 32] = std::array::from_fn(|index| index as u8 + 65);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&signing.verifying_key()));
    let header: JsonWebSignatureHeader = serde_json::from_value(serde_json::json!({
        "alg":"Ed25519","typ":"dpop+jwt","jwk":public,
    }))
    .unwrap();
    let claims = VerifiedDpopClaims {
        jti: jti.into(),
        htm: "POST".into(),
        htu: "https://station.example/_arkret/gate/account/recovery-session-grants/issue".into(),
        iat: now.timestamp() - 299,
        ath: Some(dpop_access_token_hash(&handoff.account_handoff_grant)),
        nonce: None,
    };
    let jwt = Jwt::sign(
        header,
        claims.clone(),
        &AsymmetricSigningKey::ed25519(signing),
    )
    .unwrap()
    .into_string();
    let proof = crate::services::dpop::DpopVerifier::verify_without_replay(
        &jwt,
        &claims.htm,
        &claims.htu,
        now,
        Some(&handoff.account_handoff_grant),
    )
    .unwrap();
    assert_eq!(proof.jkt, handoff.cnf_jkt);
    assert_eq!(
        crate::services::dpop::verified_proof_valid_through(&proof).unwrap(),
        DateTime::from_timestamp(now.timestamp() + 1, 0).unwrap()
    );
    proof
}

#[tokio::test]
async fn final_subject_wait_cannot_extend_outer_dpop_while_inner_and_device_are_live() {
    use horme::RunQueryDsl as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, completion) = fixture();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let handoff = seed_handoff(
        &factory,
        &request,
        &clock,
        clock.now() + Duration::minutes(10),
        151,
    )
    .await;
    let outer = near_expiry_outer(&handoff, clock.now(), "completion-first-outer-at-last-lock");
    let peer = MockServer::start().await;
    let expected = arkret_models_identity::SessionGrantDeviceBinding {
        device_id: request.terminal_receipt.new_device_id.clone(),
        authorization_event_id: completion.device_authorization_event_ref.event_id.clone(),
        model_generation_ref: completion.new_model_generation_ref,
    };
    let depot = current_device_depot(
        peer.uri().parse().unwrap(),
        &request.terminal_receipt.account_id.station_id,
    );
    let proof = arkret_wire::AcceptedDevicePossessionProof::Issue(
        request.accepted_device_possession_proof.clone(),
    );
    Mock::given(method("POST"))
        .and(path("/_coland/account-authority/current-device/check"))
        .and(header("authorization", "Bearer completion-test-registered-channel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "account_id":request.terminal_receipt.account_id,"device_id":expected.device_id,
            "authorization_event_id":expected.authorization_event_id,"device_generation_ref":expected.model_generation_ref,
            "action_class":"session_grant_issue_or_refresh","intent_digest":request.accepted_device_possession_proof.session_intent_digest,
            "accepted_device_possession_proof_digest":proof.proof_digest().unwrap(),"decision":"allow","linearization_seq":1,
            "linearized_at":clock.now(),"expires_at":clock.now()+Duration::seconds(30),
            "accepted_commit_id":completion.device_authorization_event_ref.commit_id,
        })))
        .expect(1).mount(&peer).await;
    let witness = acquire_private_current_device_admission(
        &depot,
        &request.terminal_receipt.account_id,
        expected.device_id.clone(),
        arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        Some(&expected),
        Some(proof),
        request
            .accepted_device_possession_proof
            .session_intent_digest
            .clone(),
        clock.now(),
    )
    .await
    .unwrap();
    let before = issuer_and_handoff_snapshot(&pool).await;
    let issuer = &request.terminal_receipt.session_grant_ref.issuer_id;
    let key = coauth_storage_postgres::advisory_lock::advisory_lock_key(&format!(
        "coauth:session-grant-ledger:{issuer}:{}",
        request.terminal_receipt.account_id.principal_id
    ));
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query("SELECT pg_advisory_xact_lock($1),true AS acquired")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder)
        .await
        .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        fresh_completion_qualification_at_cut(&mut repo, &handoff, &outer, &*next_clock)
            .await
            .unwrap();
        seed_first_attempt(
            &mut repo,
            &request,
            &completion,
            &next_clock,
            witness
                .expires_at()
                .min(request.accepted_device_possession_proof.expires_at),
        )
        .await
        .unwrap();
        assert!(next_clock.now() < witness.expires_at());
        assert!(next_clock.now() < request.accepted_device_possession_proof.expires_at);
        let result =
            fresh_completion_qualification_at_cut(&mut repo, &handoff, &outer, &*next_clock).await;
        repo.cancel().await.unwrap();
        result
    });
    tokio::time::timeout(WaitDuration::from_secs(5), async {
        loop {
            if diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=0 AND objid::bigint=$1) AS acquired")
                .bind::<diesel::sql_types::BigInt,_>(key)
                .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder).await.unwrap().acquired { break; }
            tokio::time::sleep(WaitDuration::from_millis(10)).await;
        }
    }).await.expect("the real final issuer subject lock must block");
    clock.advance(Duration::seconds(2));
    holder.batch_execute("ROLLBACK").await.unwrap();
    drop(holder);
    let result = tokio::time::timeout(WaitDuration::from_secs(10), &mut waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::SIGNATURE_INVALID,
            ..
        })
    ));
    assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
    peer.verify().await;
}

/// Exercise the same final JTI admission used by accepted replay and the
/// deterministic expired-unaccepted probe. A stale outer proof authorizes
/// neither outcome delivery nor consuming a replay key.
async fn outer_expiry_while_waiting_for_jti(accepted_history: bool) {
    use horme::RunQueryDsl as _;
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = coauth_storage_postgres::PgRepositoryFactory::new((*pool).clone());
    let (request, completion) = fixture();
    let clock = Arc::new(MockClock::new(
        request.accepted_device_possession_proof.issued_at,
    ));
    let handoff = seed_handoff(
        &factory,
        &request,
        &clock,
        clock.now() + Duration::minutes(15),
        152,
    )
    .await;
    if accepted_history {
        let mut repo = factory.create().await.unwrap();
        seed_accepted(&mut repo, &request, &completion, &clock).await;
        repo.save().await.unwrap();
    }
    clock.advance(Duration::minutes(6));
    let outer = near_expiry_outer(&handoff, clock.now(), "completion-final-jti-outer");
    let replay_row = crate::services::dpop::dpop_replay_record(&outer.claims.jti, clock.now());
    let before = issuer_and_handoff_snapshot(&pool).await;
    let mut holder = coauth_storage_postgres::pool::get_connection(&pool)
        .await
        .unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query(
        "INSERT INTO dpop_jti_replay(jti_digest,seen_at,expires_at,created_at) VALUES($1,$2,$3,$2)",
    )
    .bind::<diesel::sql_types::Text, _>(&replay_row.jti_digest)
    .bind::<diesel::sql_types::Timestamptz, _>(replay_row.seen_at)
    .bind::<diesel::sql_types::Timestamptz, _>(replay_row.expires_at)
    .execute(&mut *holder)
    .await
    .unwrap();
    let next_factory = factory.clone();
    let next_clock = Arc::clone(&clock);
    let mut waiting = tokio::spawn(async move {
        let mut repo = next_factory.create().await.unwrap();
        let state = inspect_completion_attempt(
            &mut repo,
            &request,
            &request.terminal_receipt.session_grant_ref.issuer_id,
            &*next_clock,
        )
        .await
        .unwrap();
        match state {
            CompletionAttempt::Accepted(record) if accepted_history => {
                let original: RecoveryCompletionGrantRequestBody =
                    serde_json::from_slice(&record.canonical_request).unwrap();
                request
                    .validate_exact_replay(&original, &record.account_id, &outer.jkt)
                    .unwrap();
            }
            CompletionAttempt::ExpiredUnaccepted if !accepted_history => {}
            other => panic!("the business-key fact must remain exact: {other:?}"),
        }
        let now = fresh_completion_qualification_at_cut(&mut repo, &handoff, &outer, &*next_clock)
            .await
            .unwrap();
        assert!(
            repo.dpop_replay()
                .consume_jti(crate::services::dpop::dpop_replay_record(
                    &outer.claims.jti,
                    now
                ))
                .await
                .unwrap()
        );
        let result =
            fresh_completion_qualification_at_cut(&mut repo, &handoff, &outer, &*next_clock).await;
        repo.cancel().await.unwrap();
        result
    });
    tokio::time::timeout(WaitDuration::from_secs(5), async {
        loop {
            holder.batch_execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
            if diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.wait_event_type='Lock' AND pg_backend_pid()=ANY(pg_blocking_pids(a.pid))) AS acquired")
                .get_result::<coauth_storage_postgres::advisory_lock::AdvisoryLockResult>(&mut *holder).await.unwrap().acquired { break; }
            tokio::time::sleep(WaitDuration::from_millis(10)).await;
        }
    }).await.expect("actual JTI uniqueness admission must wait");
    clock.advance(Duration::seconds(2));
    holder.batch_execute("ROLLBACK").await.unwrap();
    drop(holder);
    let result = tokio::time::timeout(WaitDuration::from_secs(10), &mut waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(ArkretRouteError::Coded {
            code: arkret_wire::ErrorCode::SIGNATURE_INVALID,
            ..
        })
    ));
    assert_eq!(before, issuer_and_handoff_snapshot(&pool).await);
}

#[tokio::test]
async fn accepted_replay_outer_expiry_during_jti_wait_keeps_outcome_and_does_not_consume_jti() {
    outer_expiry_while_waiting_for_jti(true).await;
}

#[tokio::test]
async fn expired_unaccepted_probe_outer_expiry_during_jti_wait_does_not_consume_jti() {
    outer_expiry_while_waiting_for_jti(false).await;
}
