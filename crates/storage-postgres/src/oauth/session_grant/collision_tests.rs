//! Actual PostgreSQL allocation-fence regressions; no alternate issuer ledger.
use std::collections::VecDeque;

use arkret_identifiers::{DeviceId, DidCoreId, EventId, SessionGrantId, SessionGrantSecret};
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantCredentialClass, SessionGrantDeviceBinding,
    SessionGrantHolderBinding, SessionGrantMetadata, SessionGrantProofKind,
};
use chrono::Duration;
use coauth_data::clock::MockClock;
use coauth_data::{Clock, LocalAccountId, RepositoryAccess as _, RepositoryFactory as _};
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use super::*;

/// Deterministic entropy injection into the real allocator, never a caller
/// supplied grant seed. Other allocation bytes still come from the seeded RNG.
struct Candidates {
    inner: ChaChaRng,
    ids: VecDeque<[u8; 10]>,
    secrets: VecDeque<[u8; 32]>,
}
impl Candidates {
    fn new(seed: u64) -> Self {
        Self {
            inner: ChaChaRng::seed_from_u64(seed),
            ids: VecDeque::new(),
            secrets: VecDeque::new(),
        }
    }
    fn colliding_id(mut self, id: &SessionGrantId) -> Self {
        self.ids
            .push_back(id.uuid().as_bytes()[6..].try_into().unwrap());
        self
    }
    fn colliding_secret(mut self, secret: &SessionGrantSecret) -> Self {
        self.secrets.push_back(
            arkret_canonical::base64url_decode(secret.as_str())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        self
    }
}
impl RngCore for Candidates {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.len() == 10
            && let Some(id) = self.ids.pop_front()
        {
            dest.copy_from_slice(&id);
        } else if dest.len() == 32
            && let Some(secret) = self.secrets.pop_front()
        {
            dest.copy_from_slice(&secret);
        } else {
            self.inner.fill_bytes(dest);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
struct NoEntropy;
impl RngCore for NoEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("exact retry must not allocate")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("exact retry must not allocate")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("exact retry must not allocate")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!("exact retry must not allocate")
    }
}
fn issuer(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap()
}
fn request<'a>(
    issuer_id: &DidCoreId,
    identity: &'a str,
    intent: &'a [u8],
    clock: &MockClock,
) -> NewSessionGrantOperation<'a> {
    NewSessionGrantOperation {
        issuer_id: issuer_id.clone(),
        operation: SessionGrantOperationDescriptor::Issue,
        proof_kind: Some(SessionGrantProofKind::AccountHandoff),
        request_identity: identity,
        canonical_intent_digest: arkret_canonical::sha256_bytes(intent),
        canonical_intent: intent,
        target_session_grant_id: None,
        grant_not_before: Some(clock.now()),
        grant_expires_at: Some(clock.now() + Duration::hours(1)),
        retained_until: clock.now() + Duration::days(7),
    }
}
async fn reserve(
    factory: &crate::PgRepositoryFactory,
    rng: &mut (dyn RngCore + Send),
    clock: &MockClock,
    issuer_id: &DidCoreId,
    identity: &str,
) -> SessionGrantOperation {
    let mut repo = factory.create().await.unwrap();
    let outcome = repo
        .oauth_session_grant()
        .reserve_operation(
            rng,
            clock,
            request(
                issuer_id,
                identity,
                br#"{"intent":"collision-test"}"#,
                clock,
            ),
        )
        .await
        .unwrap();
    let SessionGrantReserveOutcome::Reserved(operation) = outcome else {
        panic!("new operation required: {outcome:?}")
    };
    repo.save().await.unwrap();
    operation
}
fn metadata(operation: &SessionGrantOperation) -> SessionGrantMetadata {
    let holder = CanonicalSessionPublicJwk::new(
        serde_json::json!({
            "kty":"OKP", "crv":"Ed25519", "x":arkret_canonical::base64url_encode([7;32]),
        })
        .to_string(),
    )
    .unwrap();
    let device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    SessionGrantMetadata {
        id: operation.reserved_grant_id.clone().unwrap(),
        issuer_id: operation.issuer_id.clone(),
        account_id: arkret_wire::AccountId::new(issuer("principal"), issuer("station")),
        audience_id: issuer("station"),
        device_id: Some(device.clone()),
        scopes: vec!["ak.message.read".into()],
        not_before: operation.grant_not_before.unwrap(),
        expires_at: operation.grant_expires_at.unwrap(),
        session_id: operation.session_id.clone().unwrap(),
        cnf_jkt: holder.thumbprint_sha256().unwrap(),
        session_public_key: holder,
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::HumanDevice {
            device_binding: device.to_string(),
        },
        device_binding: Some(SessionGrantDeviceBinding {
            device_id: device,
            authorization_event_id: EventId::new(
                "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g",
            )
            .unwrap(),
            model_generation_ref: 1,
        }),
        proof_kind: operation.proof_kind,
        scope_details: None,
    }
}
fn material<'a>(
    metadata: &'a SessionGrantMetadata,
    secret: &'a SessionGrantSecret,
    local: &'a LocalAccountId,
) -> NewSessionGrant<'a> {
    NewSessionGrant {
        grant_id: metadata.id.clone(),
        browser_session_id: None,
        issuer_id: &metadata.issuer_id,
        subject_id: &metadata.account_id.principal_id,
        local_account_id: local,
        device_id: metadata.device_id.as_ref().map(DeviceId::as_str),
        audience_id: &metadata.audience_id,
        scope: metadata
            .scopes
            .iter()
            .map(|name| name.parse().unwrap())
            .collect(),
        session_grant: secret,
        metadata,
        session_id: &metadata.session_id,
        session_public_key: metadata.session_public_key.as_str(),
        credential_class: "standard",
        not_before: metadata.not_before,
        expires_at: metadata.expires_at,
    }
}
async fn commit(
    factory: &crate::PgRepositoryFactory,
    operation: &SessionGrantOperation,
    clock: &MockClock,
) -> SessionGrant {
    let metadata = metadata(operation);
    metadata.validate().unwrap();
    let secret = operation.reserved_session_grant.as_ref().unwrap();
    let response = arkret_canonical::canonical_json_bytes(&metadata).unwrap();
    let local = LocalAccountId::new("allocation-test-account").unwrap();
    let mut repo = factory.create().await.unwrap();
    let mut rng = ChaChaRng::from_seed(arkret_canonical::sha256_bytes(
        operation.id.to_string().as_bytes(),
    ));
    let result = repo
        .oauth_session_grant()
        .commit_issuance(
            &mut rng,
            clock,
            operation.id,
            SessionGrantProofAuthorization {
                authorization_ref: &operation.request_identity,
                checkpoint: &serde_json::json!({"kind":"allocation-test"}),
                proof_expires_at: metadata.expires_at,
            },
            SessionGrantExactOutcome {
                canonical_response: &response,
                response_digest: arkret_canonical::sha256_bytes(&response),
            },
            material(&metadata, secret, &local),
        )
        .await
        .unwrap();
    let SessionGrantCommitOutcome::Committed(grant) = result else {
        panic!("first commit required: {result:?}")
    };
    repo.save().await.unwrap();
    assert_eq!(grant.session_grant, *secret);
    assert_eq!(grant.metadata, metadata);
    assert_eq!(grant.issuance_operation_id, operation.id);
    *grant
}

#[tokio::test]
async fn pending_and_issued_allocations_fence_both_id_and_ascii_secret_digest() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let issuer = issuer("issuer");
    let original = reserve(
        &factory,
        &mut Candidates::new(1),
        &clock,
        &issuer,
        "original",
    )
    .await;
    let original_id = original.reserved_grant_id.as_ref().unwrap();
    let original_secret = original.reserved_session_grant.as_ref().unwrap();
    for committed in [false, true] {
        if committed {
            commit(&factory, &original, &clock).await;
        }
        let phase = if committed { "issued" } else { "pending" };
        let next = reserve(
            &factory,
            &mut Candidates::new(11).colliding_secret(original_secret),
            &clock,
            &issuer,
            &format!("{phase}-secret"),
        )
        .await;
        assert_ne!(next.reserved_session_grant.as_ref(), Some(original_secret));
        assert_ne!(next.reserved_grant_id.as_ref(), Some(original_id));
        let next = reserve(
            &factory,
            &mut Candidates::new(12).colliding_id(original_id),
            &clock,
            &issuer,
            &format!("{phase}-id"),
        )
        .await;
        assert_ne!(next.reserved_grant_id.as_ref(), Some(original_id));
        assert_eq!(
            next.reserved_credential_digest,
            Some(arkret_canonical::sha256_bytes(
                next.reserved_session_grant
                    .as_ref()
                    .unwrap()
                    .as_str()
                    .as_bytes()
            ))
        );
    }
}

#[tokio::test]
async fn issuer_namespaces_allow_the_same_candidate_without_changing_exact_material() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let first = reserve(
        &factory,
        &mut Candidates::new(21),
        &clock,
        &issuer("one"),
        "first",
    )
    .await;
    let second = reserve(
        &factory,
        &mut Candidates::new(22)
            .colliding_id(first.reserved_grant_id.as_ref().unwrap())
            .colliding_secret(first.reserved_session_grant.as_ref().unwrap()),
        &clock,
        &issuer("two"),
        "second",
    )
    .await;
    assert_eq!(first.reserved_grant_id, second.reserved_grant_id);
    assert_eq!(first.reserved_session_grant, second.reserved_session_grant);
    let first = commit(&factory, &first, &clock).await;
    let second = commit(&factory, &second, &clock).await;
    assert_ne!(first.metadata.issuer_id, second.metadata.issuer_id);
    assert_eq!(first.session_grant, second.session_grant);
    let mut repo = factory.create().await.unwrap();
    for grant in [&first, &second] {
        let observed = repo
            .oauth_session_grant()
            .lookup_by_secret(&grant.issuer_id, &grant.session_grant)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.metadata, grant.metadata);
    }
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn exact_pending_replay_conflict_and_evicted_retry_never_draw_new_entropy() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let issuer = issuer("issuer");
    let original = reserve(&factory, &mut Candidates::new(31), &clock, &issuer, "exact").await;
    for committed in [false, true] {
        if committed {
            commit(&factory, &original, &clock).await;
        }
        let mut repo = factory.create().await.unwrap();
        let result = repo
            .oauth_session_grant()
            .reserve_operation(
                &mut NoEntropy,
                &clock,
                request(&issuer, "exact", br#"{"intent":"collision-test"}"#, &clock),
            )
            .await
            .unwrap();
        let current = match result {
            SessionGrantReserveOutcome::Pending(value) if !committed => value,
            SessionGrantReserveOutcome::Replay(value) if committed => value,
            other => panic!("original outcome required: {other:?}"),
        };
        assert_eq!(current.reserved_grant_id, original.reserved_grant_id);
        assert_eq!(
            current.reserved_session_grant,
            original.reserved_session_grant
        );
        let result = repo
            .oauth_session_grant()
            .reserve_operation(
                &mut NoEntropy,
                &clock,
                request(&issuer, "exact", br#"{"intent":"changed"}"#, &clock),
            )
            .await
            .unwrap();
        assert!(matches!(result, SessionGrantReserveOutcome::Conflict(_)));
        repo.cancel().await.unwrap();
    }
    clock.advance(Duration::days(8));
    let mut repo = factory.create().await.unwrap();
    let result = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut NoEntropy,
            &clock,
            request(&issuer, "exact", br#"{"intent":"collision-test"}"#, &clock),
        )
        .await
        .unwrap();
    let SessionGrantReserveOutcome::Indeterminate(evicted) = result else {
        panic!("tombstone required")
    };
    assert_eq!(evicted.reserved_grant_id, original.reserved_grant_id);
    assert_eq!(
        evicted.reserved_credential_digest,
        original.reserved_credential_digest
    );
    assert!(evicted.reserved_session_grant.is_none());
    assert!(evicted.canonical_intent.is_none());
    repo.save().await.unwrap();
    // Restore only the test clock, so the old UUID timestamp is identical.
    let original_clock = MockClock::default();
    let next = reserve(
        &factory,
        &mut Candidates::new(32)
            .colliding_id(original.reserved_grant_id.as_ref().unwrap())
            .colliding_secret(original.reserved_session_grant.as_ref().unwrap()),
        &original_clock,
        &issuer,
        "after-eviction",
    )
    .await;
    assert_ne!(next.reserved_grant_id, original.reserved_grant_id);
    assert_ne!(next.reserved_session_grant, original.reserved_session_grant);
}

#[tokio::test]
async fn concurrent_new_requests_have_one_owner_per_candidate_and_exact_request() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let issuer = issuer("issuer");
    let mut left = Candidates::new(41);
    let mut right = Candidates::new(41);
    let (left, right) = tokio::join!(
        reserve(&factory, &mut left, &clock, &issuer, "race-one"),
        reserve(&factory, &mut right, &clock, &issuer, "race-two")
    );
    assert_ne!(left.reserved_grant_id, right.reserved_grant_id);
    assert_ne!(left.reserved_session_grant, right.reserved_session_grant);
    let mut conn = crate::pool::queries(&pool);
    let count: i64 = oauth_session_grant_operations::table
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 2, "only winning allocations become pending rows");
}

#[tokio::test]
async fn collision_retry_exhaustion_does_not_persist_a_poisoned_request_seed() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let issuer = issuer("issuer");
    let original = reserve(&factory, &mut Candidates::new(51), &clock, &issuer, "owner").await;
    let mut rng = Candidates::new(52);
    let bytes: [u8; 32] = arkret_canonical::base64url_decode(
        original.reserved_session_grant.as_ref().unwrap().as_str(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    rng.secrets.extend(std::iter::repeat_n(
        bytes,
        MAX_SESSION_GRANT_ALLOCATION_ATTEMPTS,
    ));
    let mut repo = factory.create().await.unwrap();
    assert!(
        repo.oauth_session_grant()
            .reserve_operation(
                &mut rng,
                &clock,
                request(
                    &issuer,
                    "exhausted",
                    br#"{"intent":"collision-test"}"#,
                    &clock
                )
            )
            .await
            .is_err()
    );
    assert!(
        repo.oauth_session_grant()
            .lookup_operation_by_identity(
                &issuer,
                SessionGrantOperationKind::Issue,
                Some(SessionGrantProofKind::AccountHandoff),
                "exhausted"
            )
            .await
            .unwrap()
            .is_none()
    );
    repo.save().await.unwrap();
    assert!(
        rng.secrets.is_empty(),
        "bounded attempts consumed only unreserved candidates"
    );
    // The failed request is not durable; new genuine entropy can still issue.
    reserve(
        &factory,
        &mut Candidates::new(53),
        &clock,
        &issuer,
        "exhausted",
    )
    .await;
}

#[tokio::test]
async fn concurrent_exact_identity_reuses_the_winning_seed_and_outcome_namespace() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let issuer = issuer("issuer");
    let issue = |seed| {
        let factory = &factory;
        let clock = &clock;
        let issuer = &issuer;
        async move {
            let mut repo = factory.create().await.unwrap();
            let result = repo
                .oauth_session_grant()
                .reserve_operation(
                    &mut Candidates::new(seed),
                    clock,
                    request(
                        issuer,
                        "same-request",
                        br#"{"intent":"collision-test"}"#,
                        clock,
                    ),
                )
                .await
                .unwrap();
            let (inserted, operation) = match result {
                SessionGrantReserveOutcome::Reserved(operation) => (true, operation),
                SessionGrantReserveOutcome::Pending(operation) => (false, operation),
                other => panic!("one original reservation required: {other:?}"),
            };
            repo.save().await.unwrap();
            (inserted, operation)
        }
    };
    let (left, right) = tokio::join!(issue(61), issue(62));
    assert_ne!(left.0, right.0);
    assert_eq!(left.1, right.1);
    let mut conn = crate::pool::queries(&pool);
    let count: i64 = oauth_session_grant_operations::table
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn every_grant_commit_remains_exactly_bound_to_its_reserved_material() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = crate::PgRepositoryFactory::new(pool.clone());
    let clock = MockClock::default();
    let issuer = issuer("issuer");
    let operation = reserve(
        &factory,
        &mut Candidates::new(71),
        &clock,
        &issuer,
        "exact-material",
    )
    .await;
    for wrong_secret in [false, true] {
        let mut metadata = metadata(&operation);
        let secret = if wrong_secret {
            SessionGrantSecret::from_bytes([99; 32])
        } else {
            operation.reserved_session_grant.clone().unwrap()
        };
        if !wrong_secret {
            metadata.id = SessionGrantId::try_from_uuid(Uuid::from(coauth_data::new_id(
                clock.now(),
                &mut Candidates::new(73),
            )))
            .unwrap();
        }
        let local = LocalAccountId::new("allocation-test-account").unwrap();
        let bytes = arkret_canonical::canonical_json_bytes(&metadata).unwrap();
        let checkpoint = serde_json::json!({"kind":"allocation-test"});
        let mut repo = factory.create().await.unwrap();
        let result = repo
            .oauth_session_grant()
            .commit_issuance(
                &mut Candidates::new(72),
                &clock,
                operation.id,
                SessionGrantProofAuthorization {
                    authorization_ref: &operation.request_identity,
                    checkpoint: &checkpoint,
                    proof_expires_at: metadata.expires_at,
                },
                SessionGrantExactOutcome {
                    canonical_response: &bytes,
                    response_digest: arkret_canonical::sha256_bytes(&bytes),
                },
                material(&metadata, &secret, &local),
            )
            .await;
        assert!(result.is_err());
        repo.save().await.unwrap();
        let mut conn = crate::pool::queries(&pool);
        let count: i64 = oauth_session_grants::table
            .count()
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "mismatched material has zero issuer-record writes"
        );
    }
    commit(&factory, &operation, &clock).await;
}

mod admission_deadlines {
    use std::sync::Arc;
    use std::time::Duration as Wait;

    use diesel_async::SimpleAsyncConnection as _;

    use super::*;

    async fn refresh_reservation(
        factory: &crate::PgRepositoryFactory,
        prior: &SessionGrant,
        clock: &MockClock,
        identity: &str,
    ) -> SessionGrantOperation {
        let mut repo = factory.create().await.unwrap();
        let intent = br#"{"intent":"native-refresh-deadline"}"#;
        let result = repo
            .oauth_session_grant()
            .reserve_operation(
                &mut Candidates::new(80),
                clock,
                NewSessionGrantOperation {
                    issuer_id: prior.issuer_id.clone(),
                    operation: SessionGrantOperationDescriptor::Refresh {
                        predecessor_grant_id: prior.grant_id.clone(),
                    },
                    proof_kind: None,
                    request_identity: identity,
                    canonical_intent_digest: arkret_canonical::sha256_bytes(intent),
                    canonical_intent: intent,
                    target_session_grant_id: Some(&prior.grant_id),
                    grant_not_before: Some(clock.now()),
                    grant_expires_at: Some(clock.now() + Duration::hours(1)),
                    retained_until: clock.now() + Duration::days(7),
                },
            )
            .await
            .unwrap();
        let SessionGrantReserveOutcome::Reserved(operation) = result else {
            panic!("fresh refresh required")
        };
        repo.save().await.unwrap();
        operation
    }
    async fn snapshot(pool: &crate::test_utils::TestDatabase) -> serde_json::Value {
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=diesel::sql_types::Jsonb)]
            value: serde_json::Value,
        }
        diesel::sql_query("SELECT jsonb_build_object('grants',COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM oauth_session_grants g),'[]'::jsonb),'ops',COALESCE((SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM oauth_session_grant_operations o),'[]'::jsonb)) AS value")
            .get_result::<Row>(&mut crate::pool::queries(pool)).await.unwrap().value
    }
    #[tokio::test]
    async fn refresh_checks_first_deadline_after_both_subject_and_predecessor_lock_waits() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = crate::PgRepositoryFactory::new(pool.clone());
        for predecessor_row_lock in [false, true] {
            let clock = Arc::new(MockClock::default());
            let issuer = issuer(if predecessor_row_lock {
                "row-issuer"
            } else {
                "subject-issuer"
            });
            let original = reserve(
                &factory,
                &mut Candidates::new(81),
                &clock,
                &issuer,
                "initial",
            )
            .await;
            let prior = commit(&factory, &original, &clock).await;
            let operation = refresh_reservation(&factory, &prior, &clock, "late-refresh").await;
            let before = snapshot(&pool).await;
            let key = crate::advisory_lock::advisory_lock_key(&format!(
                "coauth:session-grant-ledger:{}:{}",
                prior.issuer_id, prior.subject_id
            ));
            let mut blocker = crate::pool::get_connection(&pool).await.unwrap();
            blocker.batch_execute("BEGIN").await.unwrap();
            if predecessor_row_lock {
                oauth_session_grants::table
                    .find(Uuid::from(prior.id))
                    .for_update()
                    .select(oauth_session_grants::id)
                    .first::<Uuid>(&mut *blocker)
                    .await
                    .unwrap();
            } else {
                diesel::sql_query("SELECT pg_advisory_xact_lock($1),true AS acquired")
                    .bind::<diesel::sql_types::BigInt, _>(key)
                    .get_result::<crate::advisory_lock::AdvisoryLockResult>(&mut *blocker)
                    .await
                    .unwrap();
            }
            let next_clock = Arc::clone(&clock);
            let next_factory = factory.clone();
            let proof_expires_at = clock.now() + Duration::seconds(10);
            let mut waiting = tokio::spawn(async move {
                let next = metadata(&operation);
                let secret = operation.reserved_session_grant.as_ref().unwrap();
                let bytes = arkret_canonical::canonical_json_bytes(&next).unwrap();
                let checkpoint = serde_json::json!({"kind":"first-refresh-deadline"});
                let local = LocalAccountId::new("allocation-test-account").unwrap();
                let mut repo = next_factory.create().await.unwrap();
                let result = repo
                    .oauth_session_grant()
                    .commit_refresh(
                        &mut Candidates::new(82),
                        &*next_clock,
                        SessionGrantRefreshCommit {
                            operation_id: operation.id,
                            authorization: SessionGrantProofAuthorization {
                                authorization_ref: "late-refresh-proof",
                                checkpoint: &checkpoint,
                                proof_expires_at,
                            },
                            outcome: SessionGrantExactOutcome {
                                canonical_response: &bytes,
                                response_digest: arkret_canonical::sha256_bytes(&bytes),
                            },
                            predecessor_grant_id: &prior.grant_id,
                            successor: material(&next, secret, &local),
                        },
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    result,
                    SessionGrantRefreshOutcome::AuthorizationExpired(_)
                ));
                repo.save().await.unwrap();
            });
            tokio::time::timeout(Wait::from_secs(5),async {
                loop {
                    let sql=if predecessor_row_lock {
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%oauth_session_grants%') AS acquired"
                    } else {
                        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=0 AND objid::bigint=$1) AS acquired"
                    };
                    let blocked=if predecessor_row_lock {
                        diesel::sql_query(sql).get_result::<crate::advisory_lock::AdvisoryLockResult>(&mut *blocker).await.unwrap().acquired
                    } else { diesel::sql_query(sql).bind::<diesel::sql_types::BigInt,_>(key).get_result::<crate::advisory_lock::AdvisoryLockResult>(&mut *blocker).await.unwrap().acquired };
                    if blocked {break} tokio::time::sleep(Wait::from_millis(10)).await;
                }
            }).await.expect("refresh must really wait on the selected PostgreSQL lock");
            assert!(
                tokio::time::timeout(Wait::from_millis(20), &mut waiting)
                    .await
                    .is_err()
            );
            clock.advance(Duration::seconds(20));
            blocker.batch_execute("ROLLBACK").await.unwrap();
            drop(blocker);
            tokio::time::timeout(Wait::from_secs(10), waiting)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                before,
                snapshot(&pool).await,
                "first expiry causes zero issuer/operation writes"
            );
        }
    }

    #[tokio::test]
    async fn accepted_refresh_replay_keeps_the_original_inner_proof_and_exact_outcome() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = crate::PgRepositoryFactory::new(pool.clone());
        let clock = MockClock::default();
        let original = reserve(
            &factory,
            &mut Candidates::new(91),
            &clock,
            &issuer("issuer"),
            "initial",
        )
        .await;
        let prior = commit(&factory, &original, &clock).await;
        let operation = refresh_reservation(&factory, &prior, &clock, "accepted-refresh").await;
        let next = metadata(&operation);
        let secret = operation.reserved_session_grant.as_ref().unwrap();
        let bytes = arkret_canonical::canonical_json_bytes(&next).unwrap();
        let checkpoint = serde_json::json!({"kind":"accepted-refresh"});
        let local = LocalAccountId::new("allocation-test-account").unwrap();
        let proof_expires_at = clock.now() + Duration::seconds(5);
        for replay in [false, true] {
            if replay {
                clock.advance(Duration::seconds(10));
            }
            let before = snapshot(&pool).await;
            let mut repo = factory.create().await.unwrap();
            let result = repo
                .oauth_session_grant()
                .commit_refresh(
                    &mut Candidates::new(92),
                    &clock,
                    SessionGrantRefreshCommit {
                        operation_id: operation.id,
                        authorization: SessionGrantProofAuthorization {
                            authorization_ref: "accepted-refresh-proof",
                            checkpoint: &checkpoint,
                            proof_expires_at,
                        },
                        outcome: SessionGrantExactOutcome {
                            canonical_response: &bytes,
                            response_digest: arkret_canonical::sha256_bytes(&bytes),
                        },
                        predecessor_grant_id: &prior.grant_id,
                        successor: material(&next, secret, &local),
                    },
                )
                .await
                .unwrap();
            if replay {
                let SessionGrantRefreshOutcome::Replay(stored) = result else {
                    panic!("accepted historical inner proof must remain accepted")
                };
                assert_eq!(stored.canonical_outcome.as_deref(), Some(bytes.as_slice()));
            } else {
                assert!(matches!(
                    result,
                    SessionGrantRefreshOutcome::Committed { .. }
                ));
            }
            repo.save().await.unwrap();
            if replay {
                assert_eq!(before, snapshot(&pool).await);
            }
        }
    }
}
