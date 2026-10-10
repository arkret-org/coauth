use coauth_data::user::UserRepository as _;
use coauth_data::{Clock as _, RepositoryAccess as _, RepositoryFactory as _};
use diesel_async::SimpleAsyncConnection as _;
use rand_core::SeedableRng as _;

use super::*;

fn request(tag: u64) -> arkret_identifiers::RequestId {
    arkret_identifiers::RequestId::new(format!("ak:request:00000000-0000-7000-8000-{tag:012x}"))
        .unwrap()
}
fn hash(tag: char) -> arkret_identifiers::Hash {
    arkret_identifiers::Hash::new(format!("sha256:{}", tag.to_string().repeat(64))).unwrap()
}

async fn seed(
    pool: &crate::test_utils::TestDatabase,
) -> (AccountHandoffGrantInput, IdentityBindingChallengeInput) {
    let mut repo = crate::PgRepositoryFactory::new((**pool).clone())
        .create()
        .await
        .unwrap();
    let clock = coauth_data::clock::SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1050);
    let user = repo
        .user()
        .add(&mut rng, &clock, "challenge-holder".to_owned())
        .await
        .unwrap();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let handoff = AccountHandoffGrantInput {
        id: Ulid::from(Uuid::from_u128(1050)),
        request_id: request(1),
        request_digest: hash('1'),
        local_account_id: user.id,
        browser_session_id: None,
        audience_id: "ak:did_core:webvh:zchallengeStation".to_owned(),
        account_subject: hash('2'),
        risk_decision: IdentityCreationLeaseRiskDecision::Allowed,
        cnf_jkt: "h".repeat(43),
        account_handoff_grant: "g".repeat(40),
        issued_at: now,
        expires_at: now + Duration::seconds(30),
        lease_id: "l".repeat(24),
        lease_expires_at: now + Duration::seconds(20),
    };
    assert!(matches!(
        repo.account_handoff()
            .create_with_lease(handoff.clone())
            .await
            .unwrap(),
        AccountHandoffCreation::Active { .. }
    ));
    repo.save().await.unwrap();
    // The storage boundary accepts an anchor already verified by the handler.
    let anchor =
        crate::test_utils::principal_registration_anchor_fixture("challenge-holder", [8; 32]);
    let validated = arkret_identity::validate_principal_registration_anchor(&anchor).unwrap();
    let reserved =
        arkret_models_identity::ReservedIdentityCreation::from_anchor(anchor.clone()).unwrap();
    let challenge = IdentityBindingChallengeInput {
        request_id: request(2),
        request_digest: hash('3'),
        local_account_id: user.id,
        audience_id: arkret_identifiers::DidCoreId::new(handoff.audience_id.clone()).unwrap(),
        lease_id: handoff.lease_id.clone(),
        lease_fence: 1,
        holder_jkt: handoff.cnf_jkt.clone(),
        principal_registration_anchor: anchor,
        principal_id: reserved.principal_id,
        did: reserved.did,
        registration_anchor_digest: reserved.registration_anchor_digest,
        account_subject: handoff.account_subject.clone(),
        did_version_id: validated.did_version_id,
        method_history_head: validated.method_history_head,
        control_key_digest: validated.control_key_digest,
        pcr_realm_id: crate::test_utils::principal_control_realm_id(),
        realm_create_payload_digest: hash('6'),
        founding_authorize_payload_digest: hash('7'),
        initial_session_request_digest: hash('8'),
        challenge_id: "c".repeat(24),
        challenge: "n".repeat(32),
        origin: arkret_identifiers::WebOrigin::new("https://example.com").unwrap(),
        trust_domain: arkret_identifiers::TrustDomainId::new("ak:trust_domain:example.com")
            .unwrap(),
        handoff_grant_id: handoff.id,
        challenge_ttl: Duration::seconds(300),
    };
    (handoff, challenge)
}

async fn issue(
    conn: &mut AsyncPgConnection,
    input: IdentityBindingChallengeInput,
) -> IdentityBindingChallengeIssue {
    conn.batch_execute("BEGIN").await.unwrap();
    let result = PgAccountHandoffRepository::new(conn)
        .reserve_and_issue_challenge(input)
        .await
        .unwrap();
    let commit = matches!(
        result,
        IdentityBindingChallengeIssue::Issued(_) | IdentityBindingChallengeIssue::Replay(_)
    );
    conn.batch_execute(if commit { "COMMIT" } else { "ROLLBACK" })
        .await
        .unwrap();
    result
}

async fn registration_admission(
    conn: &mut AsyncPgConnection,
    input: &IdentityBindingChallengeInput,
) -> IdentityCreationRegistrationAdmission {
    conn.batch_execute("BEGIN").await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct GrantRequest {
        #[diesel(sql_type = SqlUuid)]
        request_id: Uuid,
    }
    let grant_request =
        diesel::sql_query("SELECT request_id FROM account_handoff_grants WHERE id = $1")
            .bind::<SqlUuid, _>(Uuid::from(input.handoff_grant_id))
            .get_result::<GrantRequest>(conn)
            .await
            .unwrap();
    let mut storage = PgAccountHandoffRepository::new(conn);
    let grant = storage
        .handoff_by_request_uuid(grant_request.request_id)
        .await
        .unwrap()
        .unwrap();
    let result = storage
        .registration_context(
            &grant,
            &input.lease_id,
            input.lease_fence,
            &input.challenge_id,
        )
        .await
        .unwrap();
    conn.batch_execute("ROLLBACK").await.unwrap();
    result
}

fn pairing_fixture(
    tag: u64,
    now: DateTime<Utc>,
    account_id: &arkret_wire::AccountId,
) -> (
    NewDevicePairingPendingRecord,
    arkret_models_collaboration::device_pairing::DevicePairingTargetProof,
) {
    use arkret_models_collaboration::device_pairing::{
        DevicePairingCode, DevicePairingNonce, DevicePairingRequestId, DevicePairingStageOutcome,
        DevicePairingStageRequestBody, UnsignedDevicePairingTargetProof,
    };
    use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
    use arkret_signatures::device_pairing::{
        ServerDevicePairingChallenge, server_device_pairing_transcript,
        sign_device_pairing_target_proof,
    };
    use arkret_wire::{Base64UrlString, DeviceId, DidKey, NonEmptyString};

    let signing_key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(
        &[u8::try_from(tag).unwrap(); 32],
    );
    let kid = format!("ak:device:00000000-0000-7000-8000-{tag:012x}");
    let public_key = PublicKey {
        kty: NonEmptyString::new("OKP").unwrap(),
        kid: NonEmptyString::new(kid.clone()).unwrap(),
        algorithm: NonEmptyString::new("Ed25519").unwrap(),
        key: Base64UrlString::new(arkret_canonical::base64url_encode(
            signing_key.verifying_key().as_bytes(),
        ))
        .unwrap(),
        key_digest: None,
    };
    let request_id = DevicePairingRequestId::new(format!(
        "device_pairing_request:00000000-0000-7000-8000-{tag:012x}"
    ))
    .unwrap();
    let pairing_code = DevicePairingCode::new(format!("AAAAAA{:02}", tag + 22)).unwrap();
    let client_nonce = DevicePairingNonce::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let server_nonce = DevicePairingNonce::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
    let expires_at = now + Duration::minutes(10);
    let stage_request = DevicePairingStageRequestBody {
        new_device_pubkey: public_key.clone(),
        client_nonce: client_nonce.clone(),
        display_name: None,
        device_metadata: None,
    };
    let stage_outcome = DevicePairingStageOutcome {
        device_pairing_request_id: request_id.clone(),
        pairing_code: pairing_code.clone(),
        gate_audience_uri: "https://account.example".to_owned(),
        server_nonce: server_nonce.clone(),
        expires_at,
    };
    let stage_request_bytes = arkret_canonical::canonical_json_bytes(&stage_request).unwrap();
    let stage_outcome_bytes = arkret_canonical::canonical_json_bytes(&stage_outcome).unwrap();
    let challenge = ServerDevicePairingChallenge::from_stage(&stage_request, &stage_outcome);
    let (_, digest) = server_device_pairing_transcript(&public_key, &challenge).unwrap();
    let did_key = DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes()
        )
    ))
    .unwrap();
    let proof = sign_device_pairing_target_proof(
        UnsignedDevicePairingTargetProof::new(
            account_id.clone(),
            DeviceId::new(kid).unwrap(),
            did_key,
            NonEmptyString::new("hpke-public-key-fixture").unwrap(),
            vec![NonEmptyString::new("Ed25519").unwrap()],
            digest,
        )
        .unwrap(),
        &signing_key,
    )
    .unwrap();
    (
        NewDevicePairingPendingRecord {
            stage_idempotency_key: format!("pairing-fixture:{tag}"),
            stage_request_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                &stage_request_bytes,
            ))
            .unwrap(),
            stage_outcome: stage_outcome_bytes,
            device_pairing_request_id: request_id,
            pairing_code,
            new_device_pubkey: public_key,
            client_nonce,
            display_name: None,
            device_metadata: None,
            gate_audience_uri: stage_outcome.gate_audience_uri,
            server_nonce,
            expires_at,
            retained_until: expires_at + Duration::hours(24),
            created_at: now,
        },
        proof,
    )
}

#[tokio::test]
async fn pairing_stage_idempotency_replays_exact_bytes_and_conflicts_on_changed_body() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let now = arkret_canonical::normalize_timestamp_canonical(coauth_data::Clock::now(
        &coauth_data::SystemClock::default(),
    ));
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zpairingPrincipal").unwrap(),
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zpairingStation").unwrap(),
    );
    let (input, _) = pairing_fixture(7, now, &account_id);
    let expected = input.stage_outcome.clone();
    let factory = crate::PgRepositoryFactory::new((*pool).clone());

    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .insert_device_pairing_stage(input.clone())
            .await
            .unwrap(),
        DevicePairingStageInsert::Inserted
    );
    repo.save().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .insert_device_pairing_stage(input.clone())
            .await
            .unwrap(),
        DevicePairingStageInsert::Replay(expected)
    );
    repo.cancel().await.unwrap();

    let mut changed = input;
    changed.stage_request_digest =
        arkret_identifiers::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .insert_device_pairing_stage(changed)
            .await
            .unwrap(),
        DevicePairingStageInsert::DuplicateConflict
    );
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn pairing_finalize_replays_exactly_conflicts_on_change_and_supersedes_prior_ready_row() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let now = arkret_canonical::normalize_timestamp_canonical(coauth_data::Clock::now(
        &coauth_data::SystemClock::default(),
    ));
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zpairingPrincipal").unwrap(),
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zpairingStation").unwrap(),
    );
    let (first, first_proof) = pairing_fixture(1, now, &account_id);
    let (second, second_proof) = pairing_fixture(2, now, &account_id);
    let factory = crate::PgRepositoryFactory::new((*pool).clone());

    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .insert_device_pairing_stage(first.clone())
            .await
            .unwrap(),
        DevicePairingStageInsert::Inserted
    );
    assert_eq!(
        repo.account_handoff()
            .insert_device_pairing_stage(second.clone())
            .await
            .unwrap(),
        DevicePairingStageInsert::Inserted
    );
    repo.save().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &first.device_pairing_request_id,
                &second.pairing_code,
                &account_id,
                &first_proof,
                &hash('0'),
                b"{\"wrong_code\":true}",
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::NotFound
    ));
    repo.cancel().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let still_staged = repo
        .account_handoff()
        .get_device_pairing_stage(&first.device_pairing_request_id)
        .await
        .unwrap()
        .unwrap();
    repo.cancel().await.unwrap();
    assert_eq!(
        still_staged.state,
        arkret_models_collaboration::device_pairing::DevicePairingState::Staged
    );
    assert!(still_staged.finalize_request_digest.is_none());
    assert!(still_staged.finalize_outcome.is_none());

    let first_digest = hash('a');
    let first_outcome = b"{\"state\":\"ready_for_claim\"}";
    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &first.device_pairing_request_id,
                &first.pairing_code,
                &account_id,
                &first_proof,
                &first_digest,
                first_outcome,
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Committed(bytes) if bytes == first_outcome
    ));
    repo.save().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &first.device_pairing_request_id,
                &first.pairing_code,
                &account_id,
                &first_proof,
                &first_digest,
                first_outcome,
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Replay(bytes) if bytes == first_outcome
    ));
    repo.cancel().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &first.device_pairing_request_id,
                &first.pairing_code,
                &account_id,
                &first_proof,
                &hash('b'),
                first_outcome,
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::DuplicateConflict
    ));
    repo.cancel().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let unchanged = repo
        .account_handoff()
        .get_device_pairing_stage(&first.device_pairing_request_id)
        .await
        .unwrap()
        .unwrap();
    repo.cancel().await.unwrap();
    assert_eq!(
        unchanged.state,
        arkret_models_collaboration::device_pairing::DevicePairingState::ReadyForClaim
    );
    assert_eq!(
        unchanged.finalize_request_digest,
        Some(first_digest.clone())
    );
    assert_eq!(
        unchanged.finalize_outcome.as_deref(),
        Some(first_outcome.as_slice())
    );

    let second_digest = hash('c');
    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &second.device_pairing_request_id,
                &second.pairing_code,
                &account_id,
                &second_proof,
                &second_digest,
                b"{\"second\":true}",
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Committed(_)
    ));
    repo.save().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let first_after = repo
        .account_handoff()
        .get_device_pairing_stage(&first.device_pairing_request_id)
        .await
        .unwrap()
        .unwrap();
    let second_after = repo
        .account_handoff()
        .get_device_pairing_stage(&second.device_pairing_request_id)
        .await
        .unwrap()
        .unwrap();
    repo.cancel().await.unwrap();
    assert_eq!(
        first_after.state,
        arkret_models_collaboration::device_pairing::DevicePairingState::Expired
    );
    assert_eq!(
        second_after.state,
        arkret_models_collaboration::device_pairing::DevicePairingState::ReadyForClaim
    );

    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &first.device_pairing_request_id,
                &first.pairing_code,
                &account_id,
                &first_proof,
                &first_digest,
                first_outcome,
                now + Duration::hours(1),
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Replay(bytes) if bytes == first_outcome
    ));
    repo.cancel().await.unwrap();
}

#[derive(diesel::QueryableByName)]
struct PairingAbuseStateRow {
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    code_consumed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    abuse_locked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<SmallInt>)]
    failure_count: Option<i16>,
}

#[derive(diesel::QueryableByName)]
struct PairingCountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn pairing_abuse_state(
    conn: &mut AsyncPgConnection,
    request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
) -> PairingAbuseStateRow {
    diesel::sql_query(
        "SELECT p.state, p.code_consumed_at, p.abuse_locked_at, l.failure_count \
         FROM device_pairing_pending p LEFT JOIN device_pairing_abuse_ledger l \
         USING (device_pairing_request_id) WHERE p.device_pairing_request_id=$1",
    )
    .bind::<Text, _>(request_id.as_str())
    .get_result(conn)
    .await
    .unwrap()
}

#[tokio::test]
async fn pairing_failure_budget_is_durable_bounded_and_transactional() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let now = arkret_canonical::normalize_timestamp_canonical(coauth_data::Clock::now(
        &coauth_data::SystemClock::default(),
    ));
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zbudgetPrincipal").unwrap(),
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zbudgetStation").unwrap(),
    );
    let (pending, _) = pairing_fixture(3, now, &account_id);
    let (rolled_back, _) = pairing_fixture(4, now, &account_id);
    let factory = crate::PgRepositoryFactory::new((*pool).clone());

    let mut repo = factory.create().await.unwrap();
    for stage in [pending.clone(), rolled_back.clone()] {
        assert_eq!(
            repo.account_handoff()
                .insert_device_pairing_stage(stage)
                .await
                .unwrap(),
            DevicePairingStageInsert::Inserted
        );
    }
    repo.save().await.unwrap();

    let unknown = arkret_models_collaboration::device_pairing::DevicePairingRequestId::new(
        "device_pairing_request:00000000-0000-7000-8000-000000000099".to_owned(),
    )
    .unwrap();
    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .record_device_pairing_failure(&unknown, now)
            .await
            .unwrap(),
        DevicePairingFailureRecord::NotCounted
    );
    let unknown_code =
        arkret_models_collaboration::device_pairing::DevicePairingCode::new("ZZZZZZZZ".to_owned())
            .unwrap();
    assert!(
        repo.account_handoff()
            .get_device_pairing_by_code(&unknown_code, now)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.account_handoff()
            .record_device_pairing_code_failure(&unknown_code, now)
            .await
            .unwrap(),
        DevicePairingFailureRecord::NotCounted
    );
    repo.save().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let located = repo
        .account_handoff()
        .get_device_pairing_by_code(&pending.pairing_code, now)
        .await
        .unwrap()
        .expect("the exact retained code locates its request");
    assert_eq!(
        located.device_pairing_request_id,
        pending.device_pairing_request_id
    );
    repo.cancel().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .record_device_pairing_failure(&rolled_back.device_pairing_request_id, now)
            .await
            .unwrap(),
        DevicePairingFailureRecord::Counted
    );
    repo.cancel().await.unwrap();

    for _ in 0..9 {
        let mut repo = factory.create().await.unwrap();
        assert_eq!(
            repo.account_handoff()
                .record_device_pairing_failure(&pending.device_pairing_request_id, now)
                .await
                .unwrap(),
            DevicePairingFailureRecord::Counted
        );
        repo.save().await.unwrap();
    }
    let mut conn = pool.get().await.unwrap();
    let ninth = pairing_abuse_state(&mut conn, &pending.device_pairing_request_id).await;
    assert_eq!(ninth.state, "staged");
    assert_eq!(ninth.failure_count, Some(9));
    assert!(ninth.code_consumed_at.is_none());
    assert!(ninth.abuse_locked_at.is_none());
    let rolled_back_state =
        pairing_abuse_state(&mut conn, &rolled_back.device_pairing_request_id).await;
    assert_eq!(rolled_back_state.failure_count, None);
    drop(conn);

    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .record_device_pairing_failure(&pending.device_pairing_request_id, now)
            .await
            .unwrap(),
        DevicePairingFailureRecord::Locked
    );
    repo.save().await.unwrap();

    let mut conn = pool.get().await.unwrap();
    let locked = pairing_abuse_state(&mut conn, &pending.device_pairing_request_id).await;
    assert_eq!(locked.state, "expired");
    assert_eq!(locked.failure_count, Some(10));
    assert_eq!(locked.code_consumed_at, Some(now));
    assert_eq!(locked.abuse_locked_at, Some(now));
    let unknown_rows: i64 = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM device_pairing_abuse_ledger \
         WHERE device_pairing_request_id=$1",
    )
    .bind::<Text, _>(unknown.as_str())
    .get_result::<PairingCountRow>(&mut conn)
    .await
    .unwrap()
    .count;
    assert_eq!(unknown_rows, 0);
}

#[tokio::test]
async fn pairing_failure_budget_linearizes_concurrent_failures_and_protects_terminal_success() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let now = arkret_canonical::normalize_timestamp_canonical(coauth_data::Clock::now(
        &coauth_data::SystemClock::default(),
    ));
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zconcurrentPrincipal").unwrap(),
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zconcurrentStation").unwrap(),
    );
    let (pending, _) = pairing_fixture(5, now, &account_id);
    let (replayable, replayable_proof) = pairing_fixture(6, now, &account_id);
    let (terminal, terminal_proof) = pairing_fixture(7, now, &account_id);
    let factory = crate::PgRepositoryFactory::new((*pool).clone());
    let mut repo = factory.create().await.unwrap();
    for stage in [pending.clone(), replayable.clone(), terminal.clone()] {
        assert_eq!(
            repo.account_handoff()
                .insert_device_pairing_stage(stage)
                .await
                .unwrap(),
            DevicePairingStageInsert::Inserted
        );
    }
    repo.save().await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let factory = factory.clone();
        let request_id = pending.device_pairing_request_id.clone();
        tasks.push(tokio::spawn(async move {
            let mut repo = factory.create().await.unwrap();
            let result = repo
                .account_handoff()
                .record_device_pairing_failure(&request_id, now)
                .await
                .unwrap();
            repo.save().await.unwrap();
            result
        }));
    }
    let mut locked = 0;
    for task in tasks {
        if task.await.unwrap() == DevicePairingFailureRecord::Locked {
            locked += 1;
        }
    }
    assert_eq!(locked, 1);

    let replayable_digest = hash('c');
    let replayable_outcome = b"{\"state\":\"ready_for_claim\"}";
    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &replayable.device_pairing_request_id,
                &replayable.pairing_code,
                &account_id,
                &replayable_proof,
                &replayable_digest,
                replayable_outcome,
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Committed(_)
    ));
    repo.save().await.unwrap();
    for _ in 0..10 {
        let mut repo = factory.create().await.unwrap();
        repo.account_handoff()
            .record_device_pairing_failure(&replayable.device_pairing_request_id, now)
            .await
            .unwrap();
        repo.save().await.unwrap();
    }
    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &replayable.device_pairing_request_id,
                &replayable.pairing_code,
                &account_id,
                &replayable_proof,
                &replayable_digest,
                replayable_outcome,
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Replay(bytes) if bytes == replayable_outcome
    ));
    repo.cancel().await.unwrap();

    let terminal_digest = hash('d');
    let terminal_outcome = b"{\"state\":\"ready_for_claim\"}";
    let mut repo = factory.create().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .finalize_device_pairing(
                &terminal.device_pairing_request_id,
                &terminal.pairing_code,
                &account_id,
                &terminal_proof,
                &terminal_digest,
                terminal_outcome,
                now,
            )
            .await
            .unwrap(),
        DevicePairingFinalizeCommit::Committed(_)
    ));
    repo.save().await.unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE device_pairing_pending SET state='authorized', code_consumed_at=$2 \
         WHERE device_pairing_request_id=$1",
    )
    .bind::<Text, _>(terminal.device_pairing_request_id.as_str())
    .bind::<Timestamptz, _>(now)
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);

    let mut repo = factory.create().await.unwrap();
    assert_eq!(
        repo.account_handoff()
            .record_device_pairing_failure(&terminal.device_pairing_request_id, now)
            .await
            .unwrap(),
        DevicePairingFailureRecord::NotCounted
    );
    repo.save().await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let concurrent = pairing_abuse_state(&mut conn, &pending.device_pairing_request_id).await;
    assert_eq!(concurrent.state, "expired");
    assert_eq!(concurrent.failure_count, Some(10));
    let replayed = pairing_abuse_state(&mut conn, &replayable.device_pairing_request_id).await;
    assert_eq!(replayed.state, "expired");
    assert_eq!(replayed.failure_count, Some(10));
    let protected = pairing_abuse_state(&mut conn, &terminal.device_pairing_request_id).await;
    assert_eq!(protected.state, "authorized");
    assert_eq!(protected.failure_count, None);
}

#[tokio::test]
async fn challenge_issuance_is_independent_and_same_binding_reauthentication_reuses_transcript() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let (mut handoff, input) = seed(&pool).await;
    let mut conn = pool.get().await.unwrap();
    // A successful same-holder renewal immediately before issuance cannot block it.
    handoff.id = Ulid::from(Uuid::from_u128(1051));
    handoff.request_id = request(3);
    handoff.account_handoff_grant = "r".repeat(40);
    handoff.request_digest = hash('9');
    conn.batch_execute("BEGIN").await.unwrap();
    assert!(matches!(
        PgAccountHandoffRepository::new(&mut conn)
            .create_with_lease(handoff.clone())
            .await
            .unwrap(),
        AccountHandoffCreation::Active { .. }
    ));
    conn.batch_execute("COMMIT").await.unwrap();
    let first = match issue(&mut conn, input.clone()).await {
        IdentityBindingChallengeIssue::Issued(record) => record,
        other => panic!("{other:?}"),
    };
    assert_eq!(first.expires_at - first.issued_at, Duration::seconds(300));
    assert!(first.expires_at > handoff.expires_at);
    assert!(first.expires_at > handoff.lease_expires_at);
    let mut storage = PgAccountHandoffRepository::new(&mut conn);
    let lease = storage
        .lease_for_account(
            Uuid::from(handoff.local_account_id),
            &handoff.audience_id,
            false,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.expires_at, handoff.lease_expires_at);
    assert!(
        !storage
            .quota_event_exists(input.request_id.uuid(), "renewal")
            .await
            .unwrap()
    );
    assert!(
        storage
            .quota_event_exists(input.request_id.uuid(), "challenge_issuance")
            .await
            .unwrap()
    );
    let mut replay = input.clone();
    replay.handoff_grant_id = handoff.id;
    let replayed = match issue(&mut conn, replay.clone()).await {
        IdentityBindingChallengeIssue::Replay(record) => record,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        serde_json::to_value(first.wire_outcome()).unwrap(),
        serde_json::to_value(replayed.wire_outcome()).unwrap()
    );
    let mut new = replay.clone();
    new.request_id = request(4);
    new.request_digest = hash('a');
    new.challenge_id = "d".repeat(24);
    let limited = issue(&mut conn, new.clone()).await;
    assert!(
        matches!(
            limited,
            IdentityBindingChallengeIssue::RateLimited {
                retry_after_ms: 1..=60_000
            }
        ),
        "{limited:?}"
    );
    assert!(
        PgAccountHandoffRepository::new(&mut conn)
            .challenge_by_request(new.request_id.uuid())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        PgAccountHandoffRepository::new(&mut conn)
            .challenge_by_id(&first.challenge_id, false)
            .await
            .unwrap()
            .unwrap()
            .replaced_at
            .is_none()
    );
    // Reauthentication does not consume the old proof or make it grant-bound.
    let grant = PgAccountHandoffRepository::new(&mut conn)
        .handoff_by_request_uuid(handoff.request_id.uuid())
        .await
        .unwrap()
        .unwrap();
    conn.batch_execute("BEGIN").await.unwrap();
    assert!(matches!(
        PgAccountHandoffRepository::new(&mut conn)
            .registration_context(
                &grant,
                &input.lease_id,
                input.lease_fence,
                &first.challenge_id
            )
            .await
            .unwrap(),
        IdentityCreationRegistrationAdmission::Ready(_)
    ));
    conn.batch_execute("ROLLBACK").await.unwrap();
    // Expired current execution authority cannot be replaced by a live challenge.
    diesel::sql_query("UPDATE identity_creation_leases SET expires_at = clock_timestamp() WHERE local_account_id = $1")
        .bind::<SqlUuid, _>(Uuid::from(handoff.local_account_id)).execute(&mut conn).await.unwrap();
    assert!(matches!(
        issue(&mut conn, replay.clone()).await,
        IdentityBindingChallengeIssue::LeaseMismatch
    ));
    // A new acquisition changes fence, but the same holder's issuance window survives.
    handoff.id = Ulid::from(Uuid::from_u128(1052));
    handoff.request_id = request(5);
    handoff.request_digest = hash('b');
    handoff.account_handoff_grant = "s".repeat(40);
    handoff.issued_at = coauth_data::clock::SystemClock::default().now();
    handoff.expires_at = handoff.issued_at + Duration::minutes(5);
    handoff.lease_expires_at = handoff.expires_at;
    handoff.lease_id = "m".repeat(24);
    conn.batch_execute("BEGIN").await.unwrap();
    assert!(matches!(
        PgAccountHandoffRepository::new(&mut conn)
            .create_with_lease(handoff.clone())
            .await
            .unwrap(),
        AccountHandoffCreation::Active { .. }
    ));
    conn.batch_execute("COMMIT").await.unwrap();
    new.lease_id = handoff.lease_id.clone();
    new.lease_fence = 2;
    new.handoff_grant_id = handoff.id;
    assert!(matches!(
        issue(&mut conn, new).await,
        IdentityBindingChallengeIssue::RateLimited { .. }
    ));
    assert!(matches!(
        issue(&mut conn, replay).await,
        IdentityBindingChallengeIssue::LeaseMismatch
    ));
}

#[tokio::test]
async fn challenge_issuance_serializes_parallel_requests_and_rechecks_lock_wait_expiry() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let (handoff, input) = seed(&pool).await;
    let mut first_conn = pool.get().await.unwrap();
    let mut second_conn = pool.get().await.unwrap();
    let mut other = input.clone();
    other.request_id = request(6);
    other.request_digest = hash('c');
    other.challenge_id = "e".repeat(24);
    let (first, second) = tokio::join!(
        issue(&mut first_conn, input.clone()),
        issue(&mut second_conn, other)
    );
    assert_eq!(
        usize::from(matches!(first, IdentityBindingChallengeIssue::Issued(_)))
            + usize::from(matches!(second, IdentityBindingChallengeIssue::Issued(_))),
        1
    );
    assert_eq!(
        usize::from(matches!(
            first,
            IdentityBindingChallengeIssue::RateLimited { .. }
        )) + usize::from(matches!(
            second,
            IdentityBindingChallengeIssue::RateLimited { .. }
        )),
        1
    );
    // Start the issuer transaction before the holder expires and keep it waiting.
    first_conn.batch_execute("BEGIN").await.unwrap();
    PgAccountHandoffRepository::new(&mut first_conn)
        .lock_lease_quota(&input.account_subject, input.audience_id.as_str())
        .await
        .unwrap();
    second_conn.batch_execute("BEGIN").await.unwrap();
    let pending = async {
        PgAccountHandoffRepository::new(&mut second_conn)
            .reserve_and_issue_challenge(input.clone())
            .await
            .unwrap()
    };
    let expiry = async {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        diesel::sql_query("UPDATE identity_creation_leases SET expires_at = clock_timestamp() WHERE local_account_id = $1")
            .bind::<SqlUuid, _>(Uuid::from(handoff.local_account_id)).execute(&mut first_conn).await.unwrap();
        first_conn.batch_execute("COMMIT").await.unwrap();
    };
    let (outcome, ()) = tokio::join!(pending, expiry);
    assert!(matches!(
        outcome,
        IdentityBindingChallengeIssue::LeaseMismatch
    ));
    second_conn.batch_execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn challenge_terminal_states_and_invalid_canonical_window_are_distinct() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let (handoff, input) = seed(&pool).await;
    let mut conn = pool.get().await.unwrap();
    for ttl in [
        Duration::zero(),
        Duration::nanoseconds(1),
        Duration::seconds(301),
    ] {
        let mut invalid = input.clone();
        invalid.challenge_ttl = ttl;
        conn.batch_execute("BEGIN").await.unwrap();
        assert!(
            PgAccountHandoffRepository::new(&mut conn)
                .reserve_and_issue_challenge(invalid)
                .await
                .is_err()
        );
        conn.batch_execute("ROLLBACK").await.unwrap();
    }
    assert!(matches!(
        issue(&mut conn, input.clone()).await,
        IdentityBindingChallengeIssue::Issued(_)
    ));
    for other_account in [false, true] {
        let mut repo = crate::PgRepositoryFactory::new((*pool).clone())
            .create()
            .await
            .unwrap();
        let mut other = handoff.clone();
        let tag = if other_account { 2101 } else { 2100 };
        other.id = Ulid::from(Uuid::from_u128(tag));
        other.request_id = request(tag as u64);
        other.request_digest = hash(if other_account { 'c' } else { 'd' });
        other.account_handoff_grant = format!("{tag:040}");
        if other_account {
            let clock = coauth_data::clock::SystemClock::default();
            let mut rng = rand_chacha::ChaChaRng::seed_from_u64(2101);
            let user = repo
                .user()
                .add(&mut rng, &clock, "other-challenge-account".to_owned())
                .await
                .unwrap();
            other.local_account_id = user.id;
            other.account_subject = hash('c');
            other.lease_id = "o".repeat(24);
        } else {
            other.cnf_jkt = "o".repeat(43);
        }
        let outcome = repo
            .account_handoff()
            .create_with_lease(other.clone())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AccountHandoffCreation::Active { .. } | AccountHandoffCreation::Busy { .. }
        ));
        repo.save().await.unwrap();
        let mut mismatch = input.clone();
        mismatch.handoff_grant_id = other.id;
        mismatch.local_account_id = other.local_account_id;
        mismatch.account_subject = other.account_subject;
        mismatch.holder_jkt = other.cnf_jkt;
        assert!(matches!(
            issue(&mut conn, mismatch.clone()).await,
            IdentityBindingChallengeIssue::LeaseMismatch
        ));
        assert!(matches!(
            registration_admission(&mut conn, &mismatch).await,
            IdentityCreationRegistrationAdmission::ExecutionAuthorityInvalid
        ));
    }
    diesel::sql_query("UPDATE identity_binding_challenges SET consumed_at = clock_timestamp() WHERE request_id = $1")
        .bind::<SqlUuid, _>(input.request_id.uuid()).execute(&mut conn).await.unwrap();
    assert!(matches!(
        issue(&mut conn, input.clone()).await,
        IdentityBindingChallengeIssue::Consumed
    ));
    assert!(matches!(
        registration_admission(&mut conn, &input).await,
        IdentityCreationRegistrationAdmission::ChallengeConsumed
    ));
    diesel::sql_query("UPDATE identity_binding_challenges SET consumed_at = NULL, issued_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE request_id = $1")
        .bind::<SqlUuid, _>(input.request_id.uuid()).execute(&mut conn).await.unwrap();
    assert!(matches!(
        issue(&mut conn, input.clone()).await,
        IdentityBindingChallengeIssue::Expired
    ));
    assert!(matches!(
        registration_admission(&mut conn, &input).await,
        IdentityCreationRegistrationAdmission::ChallengeExpired
    ));
    diesel::sql_query("UPDATE identity_binding_challenges SET issued_at = clock_timestamp(), expires_at = clock_timestamp() + interval '299 seconds', replaced_at = clock_timestamp() WHERE request_id = $1")
        .bind::<SqlUuid, _>(input.request_id.uuid()).execute(&mut conn).await.unwrap();
    assert!(matches!(
        issue(&mut conn, input.clone()).await,
        IdentityBindingChallengeIssue::StaleRequest
    ));
    assert!(matches!(
        registration_admission(&mut conn, &input).await,
        IdentityCreationRegistrationAdmission::ChallengeReplaced
    ));
    diesel::sql_query(
        "UPDATE identity_binding_challenges SET replaced_at = NULL WHERE request_id = $1",
    )
    .bind::<SqlUuid, _>(input.request_id.uuid())
    .execute(&mut conn)
    .await
    .unwrap();
    let mut conflict = input.clone();
    conflict.request_digest = hash('e');
    assert!(matches!(
        issue(&mut conn, conflict).await,
        IdentityBindingChallengeIssue::DuplicateConflict
    ));
    diesel::sql_query(
        "UPDATE account_handoff_grants SET revoked_at = clock_timestamp() WHERE id = $1",
    )
    .bind::<SqlUuid, _>(Uuid::from(handoff.id))
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        issue(&mut conn, input.clone()).await,
        IdentityBindingChallengeIssue::LeaseMismatch
    ));
    assert!(matches!(
        registration_admission(&mut conn, &input).await,
        IdentityCreationRegistrationAdmission::ExecutionAuthorityInvalid
    ));
    diesel::sql_query("UPDATE users SET status = 'deactivated' WHERE id = $1")
        .bind::<SqlUuid, _>(Uuid::from(handoff.local_account_id))
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(matches!(
        issue(&mut conn, input.clone()).await,
        IdentityBindingChallengeIssue::RiskRejected
    ));
    assert!(matches!(
        registration_admission(&mut conn, &input).await,
        IdentityCreationRegistrationAdmission::AccountInactive
    ));
}

#[tokio::test]
async fn challenge_hour_budget_uses_durable_holder_scope_and_exact_window_boundary() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut conn = pool.get().await.unwrap();
    let subject = hash('f');
    let clock = coauth_data::clock::SystemClock::default();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    conn.batch_execute("BEGIN").await.unwrap();
    let mut storage = PgAccountHandoffRepository::new(&mut conn);
    storage
        .lock_lease_quota(&subject, "ak:did_core:webvh:zbudget")
        .await
        .unwrap();
    for n in 0..12 {
        let at = now - Duration::minutes(55 - n * 5);
        assert_eq!(
            storage
                .consume_holder_quota(
                    request(100 + n as u64).uuid(),
                    &subject,
                    "ak:did_core:webvh:zbudget",
                    "holder",
                    "challenge_issuance",
                    at
                )
                .await
                .unwrap(),
            None
        );
    }
    // The minute expires first; the hour still blocks until the oldest event leaves.
    let retry = storage
        .consume_holder_quota(
            request(200).uuid(),
            &subject,
            "ak:did_core:webvh:zbudget",
            "holder",
            "challenge_issuance",
            now + Duration::minutes(1),
        )
        .await
        .unwrap();
    assert_eq!(retry, Some(240_000));
    assert_eq!(
        storage
            .consume_holder_quota(
                request(111).uuid(),
                &subject,
                "ak:did_core:webvh:zbudget",
                "holder",
                "challenge_issuance",
                now + Duration::minutes(1)
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        storage
            .consume_holder_quota(
                request(201).uuid(),
                &subject,
                "ak:did_core:webvh:zbudget",
                "holder",
                "renewal",
                now + Duration::minutes(1)
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        storage
            .consume_holder_quota(
                request(202).uuid(),
                &subject,
                "ak:did_core:webvh:zbudget",
                "holder",
                "challenge_issuance",
                now + Duration::minutes(5)
            )
            .await
            .unwrap(),
        None
    );
    conn.batch_execute("COMMIT").await.unwrap();
}

#[tokio::test]
async fn abandonment_checks_real_authentication_and_fences_uncertain_pcr_dispatch() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let (handoff, binding) = seed(&pool).await;
    let mut conn = pool.get().await.unwrap();
    assert!(matches!(
        issue(&mut conn, binding.clone()).await,
        IdentityBindingChallengeIssue::Issued(_)
    ));
    let session_id = Uuid::from_u128(90101);
    diesel::sql_query("INSERT INTO user_sessions (id,user_id,created_at) VALUES ($1,$2,clock_timestamp() - interval '10 seconds')")
        .bind::<SqlUuid,_>(session_id).bind::<SqlUuid,_>(Uuid::from(handoff.local_account_id)).execute(&mut conn).await.unwrap();
    diesel::sql_query("INSERT INTO user_session_authentications (id,user_session_id,created_at) VALUES ($1,$2,clock_timestamp() - interval '10 seconds')")
        .bind::<SqlUuid,_>(Uuid::from_u128(90102)).bind::<SqlUuid,_>(session_id).execute(&mut conn).await.unwrap();
    diesel::sql_query("UPDATE account_handoff_grants SET browser_session_id=$1, issued_at=clock_timestamp() WHERE id=$2")
        .bind::<SqlUuid,_>(session_id).bind::<SqlUuid,_>(Uuid::from(handoff.id)).execute(&mut conn).await.unwrap();
    let input = IdentityAbandonmentCommitInput {
        request_id: request(90901),
        request_digest: hash('a'),
        confirming_handoff_grant_id: handoff.id,
        local_account_id: handoff.local_account_id,
        audience_id: binding.audience_id.clone(),
        holder_jkt: handoff.cnf_jkt.clone(),
        lease_id: handoff.lease_id.clone(),
        lease_fence: 1,
        principal_id: binding.principal_id.clone(),
        did_version_id: binding.did_version_id.clone(),
        account_subject: handoff.account_subject.clone(),
    };
    conn.batch_execute("BEGIN").await.unwrap();
    // A newer token backed by the old authentication event proves no fresh authentication.
    assert!(matches!(
        PgAccountHandoffRepository::new(&mut conn)
            .abandon_identity_creation(input.clone())
            .await
            .unwrap(),
        IdentityAbandonmentCommit::AuthenticationRequired
    ));
    conn.batch_execute("ROLLBACK").await.unwrap();
    diesel::sql_query("UPDATE identity_binding_challenges SET issued_at=statement_timestamp()-interval '2 seconds', expires_at=statement_timestamp()+interval '298 seconds' WHERE challenge_id=$1")
        .bind::<Text,_>(&binding.challenge_id).execute(&mut conn).await.unwrap();
    diesel::sql_query("UPDATE user_session_authentications SET created_at=clock_timestamp()-interval '1 second' WHERE user_session_id=$1")
        .bind::<SqlUuid,_>(session_id).execute(&mut conn).await.unwrap();
    diesel::sql_query("UPDATE account_handoff_grants SET issued_at=clock_timestamp() WHERE id=$1")
        .bind::<SqlUuid, _>(Uuid::from(handoff.id))
        .execute(&mut conn)
        .await
        .unwrap();
    conn.batch_execute("BEGIN").await.unwrap();
    // Consumer fixture: a dispatch fence survives even when no response/receipt was recorded.
    diesel::sql_query(
        "UPDATE identity_creation_leases SET pcr_dispatch_request_digest=$1 WHERE lease_id=$2",
    )
    .bind::<Text, _>(hash('b').as_str())
    .bind::<Text, _>(&handoff.lease_id)
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        PgAccountHandoffRepository::new(&mut conn)
            .abandon_identity_creation(input.clone())
            .await
            .unwrap(),
        IdentityAbandonmentCommit::DispatchUncertain
    ));
    let no_orphan = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM identity_orphan_anchor_tombstones) AS present",
    )
    .get_result::<ExistsRow>(&mut conn)
    .await
    .unwrap();
    assert!(!no_orphan.present);
    conn.batch_execute("ROLLBACK").await.unwrap();
    conn.batch_execute("BEGIN").await.unwrap();
    let outcome = match PgAccountHandoffRepository::new(&mut conn)
        .abandon_identity_creation(input.clone())
        .await
        .unwrap()
    {
        IdentityAbandonmentCommit::Abandoned(outcome) => outcome,
        other => panic!("unexpected abandonment result: {other:?}"),
    };
    conn.batch_execute("COMMIT").await.unwrap();
    conn.batch_execute("BEGIN").await.unwrap();
    let replayed = PgAccountHandoffRepository::new(&mut conn)
        .abandon_identity_creation(input.clone())
        .await
        .unwrap();
    assert!(
        matches!(&replayed, IdentityAbandonmentCommit::Replay(replay) if *replay == outcome),
        "{replayed:?} != Replay({outcome:?})"
    );
    conn.batch_execute("ROLLBACK").await.unwrap();
    let mut changed = input;
    changed.request_digest = hash('c');
    conn.batch_execute("BEGIN").await.unwrap();
    assert!(matches!(
        PgAccountHandoffRepository::new(&mut conn)
            .abandon_identity_creation(changed)
            .await
            .unwrap(),
        IdentityAbandonmentCommit::DuplicateConflict
    ));
    conn.batch_execute("ROLLBACK").await.unwrap();
}
