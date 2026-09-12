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
    // The storage boundary accepts a wrapper already verified by the handler.
    let operation = arkret_models_identity::DidOperationSubmitRequestBody {
        did: arkret_identifiers::Did::new("did:webvh:zchallengePrincipal:example.com").unwrap(),
        did_method: arkret_models_identity::DidMethodName::Webvh,
        seq: None,
        prev_event_digest: None,
        operation: std::collections::BTreeMap::from([(
            "versionId".to_owned(),
            serde_json::json!("1-test"),
        )]),
    };
    let reserved =
        arkret_models_identity::ReservedIdentityCreation::from_operation(operation.clone())
            .unwrap();
    let challenge = IdentityBindingChallengeInput {
        request_id: request(2),
        request_digest: hash('3'),
        local_account_id: user.id,
        audience_id: arkret_identifiers::DidCoreId::new(handoff.audience_id.clone()).unwrap(),
        lease_id: handoff.lease_id.clone(),
        lease_fence: 1,
        holder_jkt: handoff.cnf_jkt.clone(),
        did_operation: operation,
        principal_id: reserved.principal_id,
        did: reserved.did,
        operation_digest: reserved.operation_digest,
        account_subject: handoff.account_subject.clone(),
        did_version_id: "1-test".to_owned(),
        log_head_digest: hash('4'),
        control_key_digest: hash('5'),
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
    assert!(matches!(
        issue(&mut conn, new.clone()).await,
        IdentityBindingChallengeIssue::RateLimited {
            retry_after_ms: 1..=60_000
        }
    ));
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
    handoff.issued_at = Utc::now();
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
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
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
    assert!(
        matches!(PgAccountHandoffRepository::new(&mut conn).abandon_identity_creation(input.clone()).await.unwrap(), IdentityAbandonmentCommit::Replay(replay) if replay == outcome)
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
