use arkret_identifiers::{DeviceId, DidCoreId, EventId};
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantCredentialClass, SessionGrantDeviceBinding,
    SessionGrantHolderBinding, SessionGrantMetadata, SessionGrantProofKind,
};
use chrono::Duration;
use coauth_data::clock::MockClock;
use coauth_data::oauth::{
    NewSessionGrant, OAuthDeviceCodeGrantParams, OAuthSessionFilter, OAuthSessionRepository,
};
use coauth_data::{
    AuthorizationCode, Clock, LocalAccountId, Pagination, RefreshTokenState, RepositoryAccess,
    RepositoryFactory as _,
};
use coauth_oauth_types::requests::{GrantType, ResponseMode};
use coauth_oauth_types::scope::{EMAIL, OPENID, PROFILE, Scope};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use ulid::Ulid;

use crate::PgRepositoryFactory;

const TEST_SESSION_GRANT_ISSUER: &str = "ak:did_core:web:issuer_id.example";
const TEST_SESSION_GRANT_SUBJECT: &str = "ak:did_core:web:subject_id.example";
const TEST_SESSION_GRANT_AUDIENCE: &str = "ak:did_core:web:audience_id.example";
/// Accepted device-authorization Event the fixture device binding cites.
///
/// `account-lifecycle.md` §2 only lets the origin Station sign a Standard
/// grant that carries `device_binding`, and the SDK enforces it: a Standard +
/// `HumanDevice` grant without one is rejected as
/// "standard human session grant requires a signed device_binding". The
/// fixture used to omit it, which only ever surfaced with a database attached.
const TEST_DEVICE_AUTHORIZE_EVENT_ID: &str =
    "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g";

/// Closed inputs a test needs to land one committed session grant.
///
/// The UUIDv7 record ID and independent 32-byte secret are allocated once;
/// commit checks every query projection against the sole metadata record.
struct TestSessionGrantSeed<'a> {
    request_identity: &'a str,
    browser_session_id: Option<Ulid>,
    device_id: &'a str,
    holder_seed: u8,
    scope: Scope,
}

/// Ed25519 public JWK used as the holder-bound session key.
fn test_session_public_key(seed: u8) -> CanonicalSessionPublicJwk {
    CanonicalSessionPublicJwk::new(
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": arkret_canonical::base64url_encode([seed; 32]),
        })
        .to_string(),
    )
    .unwrap()
}

/// Persist a real opaque credential through the production reservation and
/// atomic issuer-record commit; no signed-token parser or synthetic signature.
async fn commit_test_session_grant<R>(
    repo: &mut R,
    rng: &mut ChaChaRng,
    clock: &MockClock,
    seed: TestSessionGrantSeed<'_>,
) -> coauth_data::SessionGrant
where
    R: RepositoryAccess + ?Sized,
    R::Error: std::fmt::Debug,
{
    let not_before = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let expires_at = not_before + Duration::hours(1);
    let issuer = DidCoreId::new(TEST_SESSION_GRANT_ISSUER).unwrap();
    let id = arkret_identifiers::SessionGrantId::new_v7_at(
        u64::try_from(not_before.timestamp_millis()).unwrap(),
    );
    let key = test_session_public_key(seed.holder_seed);
    let mut scopes = seed
        .scope
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes.dedup();
    let mut metadata = SessionGrantMetadata {
        id: id.clone(),
        issuer_id: issuer.clone(),
        account_id: arkret_wire::AccountId::new(
            DidCoreId::new(TEST_SESSION_GRANT_SUBJECT).unwrap(),
            DidCoreId::new(TEST_SESSION_GRANT_AUDIENCE).unwrap(),
        ),
        device_id: Some(DeviceId::new(seed.device_id).unwrap()),
        audience_id: DidCoreId::new(TEST_SESSION_GRANT_AUDIENCE).unwrap(),
        scopes,
        not_before,
        expires_at,
        session_id: "unallocated-test-template".into(),
        cnf_jkt: key.thumbprint_sha256().unwrap(),
        session_public_key: key,
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::HumanDevice {
            device_binding: seed.device_id.into(),
        },
        device_binding: Some(SessionGrantDeviceBinding {
            device_id: DeviceId::new(seed.device_id).unwrap(),
            authorization_event_id: EventId::new(TEST_DEVICE_AUTHORIZE_EVENT_ID).unwrap(),
            model_generation_ref: 1,
        }),
        proof_kind: Some(SessionGrantProofKind::AccountHandoff),
        scope_details: None,
    };
    metadata.validate().unwrap();
    let canonical_intent = arkret_canonical::canonical_json_bytes(&metadata).unwrap();
    let intent_digest = arkret_canonical::sha256_bytes(&canonical_intent);
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            rng,
            clock,
            coauth_data::NewSessionGrantOperation {
                issuer_id: issuer.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: metadata.proof_kind,
                request_identity: seed.request_identity,
                canonical_intent_digest: intent_digest,
                canonical_intent: &canonical_intent,
                target_session_grant_id: None,
                grant_not_before: Some(not_before),
                grant_expires_at: Some(expires_at),
                retained_until: clock.now() + Duration::days(7),
            },
        )
        .await
        .unwrap();
    let operation = match reserved {
        coauth_data::SessionGrantReserveOutcome::Reserved(o) => o,
        other => panic!("fresh reservation expected: {other:?}"),
    };
    let id = operation.reserved_grant_id.clone().unwrap();
    let secret = operation.reserved_session_grant.clone().unwrap();
    metadata.id = id.clone();
    metadata.session_id = operation.session_id.clone().unwrap();
    metadata.not_before = operation.grant_not_before.unwrap();
    metadata.expires_at = operation.grant_expires_at.unwrap();
    metadata.validate().unwrap();
    let canonical_response = arkret_canonical::canonical_json_bytes(&metadata).unwrap();
    assert!(
        repo.oauth_session_grant()
            .lookup_by_secret(&issuer, &secret)
            .await
            .unwrap()
            .is_none(),
        "a pending reservation cannot authorize its reserved secret"
    );
    let checkpoint = serde_json::json!({"kind":"storage_test_verified_issue","grant_id":id});
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            rng,
            clock,
            operation.id,
            coauth_data::SessionGrantProofAuthorization {
                authorization_ref: seed.request_identity,
                checkpoint: &checkpoint,
                proof_expires_at: expires_at,
            },
            coauth_data::SessionGrantExactOutcome {
                canonical_response: &canonical_response,
                response_digest: arkret_canonical::sha256_bytes(&canonical_response),
            },
            NewSessionGrant {
                grant_id: id.clone(),
                browser_session_id: seed.browser_session_id,
                issuer_id: &issuer,
                subject_id: &metadata.account_id.principal_id,
                local_account_id: &LocalAccountId::new("test-account").unwrap(),
                device_id: Some(seed.device_id),
                audience_id: &metadata.audience_id,
                scope: seed.scope,
                session_grant: &secret,
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
    let committed = match committed {
        coauth_data::SessionGrantCommitOutcome::Committed(grant) => *grant,
        other => panic!("first commit expected: {other:?}"),
    };
    let mut wrong_bytes: [u8; 32] = arkret_canonical::base64url_decode(secret.as_str())
        .unwrap()
        .try_into()
        .unwrap();
    wrong_bytes[0] ^= 1;
    let wrong_secret = arkret_identifiers::SessionGrantSecret::from_bytes(wrong_bytes);
    assert!(
        repo.oauth_session_grant()
            .lookup_by_secret(&issuer, &wrong_secret)
            .await
            .unwrap()
            .is_none(),
        "metadata or a grant ID cannot substitute for the exact opaque bytes"
    );
    assert_eq!(committed.session_grant, secret);
    assert_eq!(committed.metadata, metadata);
    let wrong_issuer = DidCoreId::new("ak:did_core:web:other-issuer.example").unwrap();
    assert!(
        repo.oauth_session_grant()
            .lookup_by_grant_id(&wrong_issuer, &id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.oauth_session_grant()
            .lookup_by_secret(&wrong_issuer, &secret)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.oauth_session_grant()
            .lookup_by_secret(&issuer, &secret)
            .await
            .unwrap()
            .unwrap()
            .grant_id,
        id
    );
    committed
}

fn exact_scope_record<'a>(
    metadata: &'a SessionGrantMetadata,
    secret: &'a arkret_identifiers::SessionGrantSecret,
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
            .map(|scope| scope.parse().unwrap())
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

async fn exact_scope_ledger_snapshot(pool: &crate::test_utils::TestDatabase) -> serde_json::Value {
    use horme::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut connection = crate::pool::queries(pool);
    diesel::sql_query("SELECT jsonb_build_object(
        'grants', COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM oauth_session_grants g), '[]'::jsonb),
        'operations', COALESCE((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM oauth_session_grant_operations o), '[]'::jsonb)
    ) AS value")
        .get_result::<Snapshot>(&mut connection).await.unwrap().value
}

#[tokio::test]
async fn opaque_refresh_rejects_every_changed_ceiling_with_zero_post_reservation_writes() {
    use arkret_identifiers::{RealmId, SessionGrantId, StrandId};
    use arkret_models_identity::{
        AgentParticipationView, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope, SessionGrantScope, SessionGrantScopeConstraints,
        SessionGrantScopeResources,
    };
    use coauth_data::{
        NewSessionGrantOperation, SessionGrantCommitOutcome, SessionGrantExactOutcome,
        SessionGrantOperationDescriptor, SessionGrantProofAuthorization, SessionGrantRefreshCommit,
        SessionGrantRefreshOutcome, SessionGrantReserveOutcome,
    };
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = PgRepositoryFactory::new(pool.clone());
    let mut rng = ChaChaRng::seed_from_u64(93);
    let clock = MockClock::default();
    let event = |byte| EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32]);
    let realms = vec![
        RealmId::from_event_id(&event(1)),
        RealmId::from_event_id(&event(2)),
    ];
    let strands = vec![
        StrandId::from_event_id(&event(3)),
        StrandId::from_event_id(&event(4)),
    ];
    let holder = test_session_public_key(7);
    let account = arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        DidCoreId::new(TEST_SESSION_GRANT_AUDIENCE).unwrap(),
    );
    let local = LocalAccountId::new("exact-scope-test-account").unwrap();
    let mut metadata = SessionGrantMetadata {
        id: SessionGrantId::new_v7_at(clock.now().timestamp_millis().try_into().unwrap()),
        issuer_id: DidCoreId::new(TEST_SESSION_GRANT_ISSUER).unwrap(),
        account_id: account.clone(),
        device_id: None,
        audience_id: account.station_id.clone(),
        scopes: vec!["ak.message.create".into(), "ak.message.read".into()],
        not_before: clock.now(),
        expires_at: clock.now() + Duration::hours(1),
        session_id: "exact-refresh-ceiling-chain".into(),
        cnf_jkt: holder.thumbprint_sha256().unwrap(),
        session_public_key: holder,
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::AgentRuntime {
            agent_id: account.principal_id.clone(),
            agent_key_authorization_ref: event(5),
            verification_method: arkret_wire::DidUrl::new("did:web:agent.example#runtime").unwrap(),
        },
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AgentKeyProof),
        scope_details: Some(SessionGrantScope {
            controller_principal_id: TEST_SESSION_GRANT_SUBJECT.parse().unwrap(),
            agent_key_authorization_ref: event(5),
            realm_ids: realms.clone(),
            strand_ids: strands.clone(),
            resources: SessionGrantScopeResources {
                realm_ids: realms.clone(),
                strand_ids: strands.clone(),
            },
            constraints: SessionGrantScopeConstraints {
                allowed_tracks: vec!["chat".into(), "files".into()],
                allowed_data_labels: vec!["internal".into(), "private".into()],
                allowed_endpoints: vec!["https://one.example".into(), "https://two.example".into()],
                allowed_strand_ids: Some(strands),
            },
            capability_grant_refs: vec![
                arkret_identifiers::GrantId::from_event_id(&event(6)).to_string(),
                arkret_identifiers::GrantId::from_event_id(&event(7)).to_string(),
            ],
            policy_refs: vec![event(8).to_string(), event(9).to_string()],
            participations: None,
        }),
    };
    metadata.validate().unwrap();
    let intent = arkret_canonical::canonical_json_bytes(&metadata).unwrap();
    let mut repo = factory.create().await.unwrap();
    let initial = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &clock,
            NewSessionGrantOperation {
                issuer_id: metadata.issuer_id.clone(),
                operation: SessionGrantOperationDescriptor::Issue,
                proof_kind: metadata.proof_kind,
                request_identity: "exact-scope-initial",
                canonical_intent_digest: arkret_canonical::sha256_bytes(&intent),
                canonical_intent: &intent,
                target_session_grant_id: None,
                grant_not_before: Some(metadata.not_before),
                grant_expires_at: Some(metadata.expires_at),
                retained_until: clock.now() + Duration::days(7),
            },
        )
        .await
        .unwrap();
    let SessionGrantReserveOutcome::Reserved(initial) = initial else {
        panic!("initial reservation required");
    };
    metadata.id = initial.reserved_grant_id.clone().unwrap();
    metadata.session_id = initial.session_id.clone().unwrap();
    metadata.not_before = initial.grant_not_before.unwrap();
    metadata.expires_at = initial.grant_expires_at.unwrap();
    let old_secret = initial.reserved_session_grant.clone().unwrap();
    let intent = arkret_canonical::canonical_json_bytes(&metadata).unwrap();
    let checkpoint = serde_json::json!({"kind":"verified_storage_issue"});
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            &mut rng,
            &clock,
            initial.id,
            SessionGrantProofAuthorization {
                authorization_ref: "exact-scope-initial-proof",
                checkpoint: &checkpoint,
                proof_expires_at: metadata.expires_at,
            },
            SessionGrantExactOutcome {
                canonical_response: &intent,
                response_digest: arkret_canonical::sha256_bytes(&intent),
            },
            exact_scope_record(&metadata, &old_secret, &local),
        )
        .await
        .unwrap();
    assert!(matches!(committed, SessionGrantCommitOutcome::Committed(_)));
    repo.save().await.unwrap();

    for case in 0..13 {
        let identity = format!("exact-refresh-ceiling-{case}");
        let intent =
            arkret_canonical::canonical_json_bytes(&serde_json::json!({"case":case})).unwrap();
        let mut repo = factory.create().await.unwrap();
        let reserved = repo
            .oauth_session_grant()
            .reserve_operation(
                &mut rng,
                &clock,
                NewSessionGrantOperation {
                    issuer_id: metadata.issuer_id.clone(),
                    operation: SessionGrantOperationDescriptor::Refresh {
                        predecessor_grant_id: metadata.id.clone(),
                    },
                    proof_kind: None,
                    request_identity: &identity,
                    canonical_intent_digest: arkret_canonical::sha256_bytes(&intent),
                    canonical_intent: &intent,
                    target_session_grant_id: Some(&metadata.id),
                    grant_not_before: Some(clock.now()),
                    grant_expires_at: Some(clock.now() + Duration::hours(1)),
                    retained_until: clock.now() + Duration::days(7),
                },
            )
            .await
            .unwrap();
        let SessionGrantReserveOutcome::Reserved(operation) = reserved else {
            panic!("fresh refresh reservation required");
        };
        repo.save().await.unwrap();
        let before = exact_scope_ledger_snapshot(&pool).await;
        let secret = operation.reserved_session_grant.as_ref().unwrap();
        let mut next = metadata.clone();
        next.id = operation.reserved_grant_id.clone().unwrap();
        next.not_before = operation.grant_not_before.unwrap();
        next.expires_at = operation.grant_expires_at.unwrap();
        let scope = next.scope_details.as_mut().unwrap();
        match case {
            0 => {
                next.scopes.pop();
            }
            1 => {
                next.scopes.push("ak.message.write".into());
            }
            2 => {
                scope.realm_ids.pop();
                scope.resources.realm_ids = scope.realm_ids.clone();
            }
            3 => {
                scope.strand_ids.pop();
                scope.resources.strand_ids = scope.strand_ids.clone();
                scope.constraints.allowed_strand_ids = Some(scope.strand_ids.clone());
            }
            4 => {
                scope.constraints.allowed_tracks.pop();
            }
            5 => {
                scope.constraints.allowed_tracks.clear();
            }
            6 => {
                scope.constraints.allowed_data_labels.clear();
            }
            7 => {
                scope.constraints.allowed_endpoints.clear();
            }
            8 => {
                scope.constraints.allowed_strand_ids = None;
            }
            9 => {
                scope.realm_ids.push(RealmId::from_event_id(&event(10)));
                scope.resources.realm_ids = scope.realm_ids.clone();
            }
            10 => {
                scope.capability_grant_refs.pop();
            }
            11 => {
                scope.policy_refs.pop();
            }
            _ => {
                scope.participations = Some(vec![AgentParticipationView {
                    target_scope: ParticipationScope::Realm {
                        realm_id: realms[0].clone(),
                    },
                    selection: ParticipationBits::NONE,
                    version: 1,
                    next_replace_input: Some(ParticipationNextReplaceInput {
                        expected_version: 1,
                    }),
                }]);
            }
        }
        next.validate().unwrap();
        let outcome = arkret_models_identity::SessionGrantResponseBody {
            account_id: next.account_id.clone(),
            issuer_id: next.issuer_id.clone(),
            device_id: None,
            session_grant: secret.clone(),
            expires_at: next.expires_at,
            session_grant_id: next.id.clone(),
            session_public_key: next.session_public_key.clone(),
            audience_id: next.audience_id.clone(),
            granted_scope: next.scopes.clone(),
            previous_session_grant_id: Some(metadata.id.clone()),
        };
        let bytes = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
        let mut repo = factory.create().await.unwrap();
        let result = repo
            .oauth_session_grant()
            .commit_refresh(
                &mut rng,
                &clock,
                SessionGrantRefreshCommit {
                    operation_id: operation.id,
                    authorization: SessionGrantProofAuthorization {
                        authorization_ref: &identity,
                        checkpoint: &checkpoint,
                        proof_expires_at: metadata.expires_at,
                    },
                    outcome: SessionGrantExactOutcome {
                        canonical_response: &bytes,
                        response_digest: arkret_canonical::sha256_bytes(&bytes),
                    },
                    predecessor_grant_id: &metadata.id,
                    successor: exact_scope_record(&next, secret, &local),
                },
            )
            .await;
        if case < 12 {
            assert!(
                result.is_err(),
                "changed refresh ceiling was accepted: case {case}"
            );
            repo.save().await.unwrap();
            assert!(
                before == exact_scope_ledger_snapshot(&pool).await,
                "refused refresh changed predecessor, successor, proof/checkpoint or operation: case {case}"
            );
        } else {
            assert!(
                matches!(result, Ok(SessionGrantRefreshOutcome::Committed { .. })),
                "current participation observation must not rewrite the frozen ceiling"
            );
            repo.save().await.unwrap();
            let mut repo = factory.read().await.unwrap();
            let predecessor = repo
                .oauth_session_grant()
                .lookup_by_grant_id(&metadata.issuer_id, &metadata.id)
                .await
                .unwrap()
                .unwrap();
            let successor = repo
                .oauth_session_grant()
                .lookup_by_secret(&metadata.issuer_id, secret)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                predecessor.lifecycle_state,
                coauth_data::SessionGrantLifecycleState::Superseded
            );
            assert_eq!(successor.metadata, next);
            repo.cancel().await.unwrap();
        }
    }
}

#[tokio::test]
async fn test_repositories() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();

    // Lookup a non-existing client
    let client = repo.oauth_client().lookup(Ulid::nil()).await.unwrap();
    assert_eq!(client, None);

    // Find a non-existing client by client id
    let client = repo
        .oauth_client()
        .find_by_client_id("some-client-id")
        .await
        .unwrap();
    assert_eq!(client, None);

    // Create a client
    let client = repo
        .oauth_client()
        .add(
            &mut rng,
            &clock,
            vec!["https://example.com/redirect".parse().unwrap()],
            None,
            None,
            None,
            vec![GrantType::AuthorizationCode],
            Some("Test client".to_owned()),
            Some("https://example.com/logo.png".parse().unwrap()),
            Some("https://example.com/".parse().unwrap()),
            Some("https://example.com/policy".parse().unwrap()),
            Some("https://example.com/tos".parse().unwrap()),
            Some("https://example.com/jwks.json".parse().unwrap()),
            None,
            None,
            None,
            None,
            None,
            Some("https://example.com/login".parse().unwrap()),
        )
        .await
        .unwrap();

    // Lookup the same client by id
    let client_lookup = repo
        .oauth_client()
        .lookup(client.id)
        .await
        .unwrap()
        .expect("client not found");
    assert_eq!(client, client_lookup);

    // Find the same client by client id
    let client_lookup = repo
        .oauth_client()
        .find_by_client_id(&client.client_id)
        .await
        .unwrap()
        .expect("client not found");
    assert_eq!(client, client_lookup);

    // Lookup a non-existing grant
    let grant = repo
        .oauth_authorization_grant()
        .lookup(Ulid::nil())
        .await
        .unwrap();
    assert_eq!(grant, None);

    // Find a non-existing grant by code
    let grant = repo
        .oauth_authorization_grant()
        .find_by_code("code")
        .await
        .unwrap();
    assert_eq!(grant, None);

    // Create an authorization grant
    let grant = repo
        .oauth_authorization_grant()
        .add(
            &mut rng,
            &clock,
            &client,
            "https://example.com/redirect".parse().unwrap(),
            Scope::from_iter([OPENID]),
            Some(AuthorizationCode {
                code: "code".to_owned(),
                pkce: None,
            }),
            Some("state".to_owned()),
            Some("nonce".to_owned()),
            ResponseMode::Query,
            true,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(grant.is_pending());

    // Lookup the same grant by id
    let grant_lookup = repo
        .oauth_authorization_grant()
        .lookup(grant.id)
        .await
        .unwrap()
        .expect("grant not found");
    assert_eq!(grant, grant_lookup);

    // Find the same grant by code
    let grant_lookup = repo
        .oauth_authorization_grant()
        .find_by_code("code")
        .await
        .unwrap()
        .expect("grant not found");
    assert_eq!(grant, grant_lookup);

    // Create a user and a start a user session
    let user = repo
        .user()
        .add(&mut rng, &clock, "john".to_owned())
        .await
        .unwrap();
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, None)
        .await
        .unwrap();

    // Lookup a non-existing session
    let session = repo.oauth_session().lookup(Ulid::nil()).await.unwrap();
    assert_eq!(session, None);

    // Create an OAuth session
    let session = repo
        .oauth_session()
        .add_from_browser_session(
            &mut rng,
            &clock,
            &client,
            &user_session,
            grant.scope.clone(),
        )
        .await
        .unwrap();

    // Mark the grant as fulfilled
    let grant = repo
        .oauth_authorization_grant()
        .fulfill(&clock, &session, grant)
        .await
        .unwrap();
    assert!(grant.is_fulfilled());

    // Lookup the same session by id
    let session_lookup = repo
        .oauth_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("session not found");
    assert_eq!(session, session_lookup);

    // Mark the grant as exchanged
    let grant = repo
        .oauth_authorization_grant()
        .exchange(&clock, grant)
        .await
        .unwrap();
    assert!(grant.is_exchanged());

    // Lookup a non-existing token
    let token = repo.oauth_access_token().lookup(Ulid::nil()).await.unwrap();
    assert_eq!(token, None);

    // Find a non-existing token
    let token = repo
        .oauth_access_token()
        .find_by_token("aabbcc")
        .await
        .unwrap();
    assert_eq!(token, None);

    // Create an access token
    let access_token = repo
        .oauth_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            "aabbcc".to_owned(),
            Some(Duration::try_minutes(5).unwrap()),
        )
        .await
        .unwrap();

    // Lookup the same token by id
    let access_token_lookup = repo
        .oauth_access_token()
        .lookup(access_token.id)
        .await
        .unwrap()
        .expect("token not found");
    assert_eq!(access_token, access_token_lookup);

    // Find the same token by token
    let access_token_lookup = repo
        .oauth_access_token()
        .find_by_token("aabbcc")
        .await
        .unwrap()
        .expect("token not found");
    assert_eq!(access_token, access_token_lookup);

    // Lookup a non-existing refresh token
    let refresh_token = repo
        .oauth_refresh_token()
        .lookup(Ulid::nil())
        .await
        .unwrap();
    assert_eq!(refresh_token, None);

    // Find a non-existing refresh token
    let refresh_token = repo
        .oauth_refresh_token()
        .find_by_token("aabbcc")
        .await
        .unwrap();
    assert_eq!(refresh_token, None);

    // Create a refresh token
    let refresh_token = repo
        .oauth_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token,
            "aabbcc".to_owned(),
        )
        .await
        .unwrap();

    // Lookup the same refresh token by id
    let refresh_token_lookup = repo
        .oauth_refresh_token()
        .lookup(refresh_token.id)
        .await
        .unwrap()
        .expect("refresh token not found");
    assert_eq!(refresh_token, refresh_token_lookup);

    // Find the same refresh token by token
    let refresh_token_lookup = repo
        .oauth_refresh_token()
        .find_by_token("aabbcc")
        .await
        .unwrap()
        .expect("refresh token not found");
    assert_eq!(refresh_token, refresh_token_lookup);

    assert!(access_token.is_valid(clock.now()));
    clock.advance(Duration::try_minutes(6).unwrap());
    assert!(!access_token.is_valid(clock.now()));

    // TODO: we might want to create a new access token
    clock.advance(Duration::try_minutes(-6).unwrap()); // Go back in time
    assert!(access_token.is_valid(clock.now()));

    // Create a new refresh token to be able to consume the old one
    let new_refresh_token = repo
        .oauth_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token,
            "ddeeff".to_owned(),
        )
        .await
        .unwrap();

    // Mark the access token as revoked
    let access_token = repo
        .oauth_access_token()
        .revoke(&clock, access_token)
        .await
        .unwrap();
    assert!(!access_token.is_valid(clock.now()));

    // Mark the refresh token as consumed
    assert!(refresh_token.is_valid());
    let refresh_token = repo
        .oauth_refresh_token()
        .consume(&clock, refresh_token, &new_refresh_token)
        .await
        .unwrap();
    assert!(!refresh_token.is_valid());

    // Record the user-agent on the session
    assert!(session.user_agent.is_none());
    let session = repo
        .oauth_session()
        .record_user_agent(session, "Mozilla/5.0".to_owned())
        .await
        .unwrap();
    assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));

    // Reload the session and check the user-agent
    let session = repo
        .oauth_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("session not found");
    assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));

    // Mark the session as finished
    assert!(session.is_valid());
    let session = repo.oauth_session().finish(&clock, session).await.unwrap();
    assert!(!session.is_valid());
}

#[tokio::test]
async fn refresh_token_chain_root_and_bulk_revoke() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut rng = ChaChaRng::seed_from_u64(43);
    let clock = MockClock::default();
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();

    let client = repo
        .oauth_client()
        .add(
            &mut rng,
            &clock,
            vec!["https://example.com/redirect".parse().unwrap()],
            None,
            None,
            None,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            Some("Refresh client".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let user = repo
        .user()
        .add(&mut rng, &clock, "refresh-chain-user".to_owned())
        .await
        .unwrap();
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, None)
        .await
        .unwrap();
    let scope = Scope::from_iter([OPENID]);
    let session = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &clock, &client, &user_session, scope.clone())
        .await
        .unwrap();

    let session_grant = commit_test_session_grant(
        &mut repo,
        &mut rng,
        &clock,
        TestSessionGrantSeed {
            request_identity: "refresh-chain-issue",
            browser_session_id: Some(user_session.id),
            device_id: "ak:device:019a0000-0000-7000-8000-000000000001",
            holder_seed: 0x11,
            scope: scope.clone(),
        },
    )
    .await;

    let access_token_1 = repo
        .oauth_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            "access-token-1".to_owned(),
            Some(Duration::try_minutes(5).unwrap()),
        )
        .await
        .unwrap();
    let refresh_token_1 = repo
        .oauth_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token_1,
            "refresh-token-1".to_owned(),
        )
        .await
        .unwrap();

    let access_token_2 = repo
        .oauth_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            "access-token-2".to_owned(),
            Some(Duration::try_minutes(5).unwrap()),
        )
        .await
        .unwrap();
    let refresh_token_2 = repo
        .oauth_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token_2,
            "refresh-token-2".to_owned(),
        )
        .await
        .unwrap();

    let consumed_1 = repo
        .oauth_refresh_token()
        .consume(&clock, refresh_token_1.clone(), &refresh_token_2)
        .await
        .unwrap();
    assert_eq!(
        consumed_1.state.next_refresh_token_id(),
        Some(refresh_token_2.id)
    );

    let refresh_token_2 = repo
        .oauth_refresh_token()
        .lookup(refresh_token_2.id)
        .await
        .unwrap()
        .expect("second refresh token should exist");
    assert_eq!(refresh_token_2.chain_root_id, refresh_token_1.id);
    assert_eq!(
        refresh_token_2.chain_created_at,
        refresh_token_1.chain_created_at
    );

    let access_token_3 = repo
        .oauth_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            "access-token-3".to_owned(),
            Some(Duration::try_minutes(5).unwrap()),
        )
        .await
        .unwrap();
    let refresh_token_3 = repo
        .oauth_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token_3,
            "refresh-token-3".to_owned(),
        )
        .await
        .unwrap();

    repo.oauth_refresh_token()
        .consume(&clock, refresh_token_2.clone(), &refresh_token_3)
        .await
        .unwrap();

    let outcome = repo
        .oauth_refresh_token()
        .revoke_chain_by_root(&clock, refresh_token_1.id)
        .await
        .unwrap();
    assert_eq!(outcome.refresh_tokens, 3);
    assert_eq!(outcome.access_tokens, 3);
    assert_eq!(outcome.session_grants, 1);

    for id in [refresh_token_1.id, refresh_token_2.id, refresh_token_3.id] {
        let token = repo
            .oauth_refresh_token()
            .lookup(id)
            .await
            .unwrap()
            .expect("refresh token should exist");
        assert!(matches!(token.state, RefreshTokenState::Revoked { .. }));
    }

    for id in [access_token_1.id, access_token_2.id, access_token_3.id] {
        let token = repo
            .oauth_access_token()
            .lookup(id)
            .await
            .unwrap()
            .expect("access token should exist");
        assert!(token.state.is_revoked());
    }

    let session_grant = repo
        .oauth_session_grant()
        .lookup(session_grant.id)
        .await
        .unwrap()
        .expect("session grant should exist");
    assert!(session_grant.revoked_at.is_some());

    let second_outcome = repo
        .oauth_refresh_token()
        .revoke_chain_by_root(&clock, refresh_token_1.id)
        .await
        .unwrap();
    assert_eq!(second_outcome.refresh_tokens, 0);
    assert_eq!(second_outcome.access_tokens, 0);
    assert_eq!(second_outcome.session_grants, 0);
}

/// `revoke_if_active` is the single-use rotation CAS: it consumes a grant
/// exactly once. The first call wins (`true` + sets `revoked_at`); a second
/// call against the now-consumed grant returns `false` and does NOT move
/// the timestamp. This is what makes two concurrent rotations of one parent
/// resolve to exactly one winner (account-lifecycle §4.1).
#[tokio::test]
async fn revoke_if_active_consumes_a_grant_exactly_once() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut rng = ChaChaRng::seed_from_u64(7);
    let clock = MockClock::default();
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();

    let user = repo
        .user()
        .add(&mut rng, &clock, "cas-user".to_owned())
        .await
        .unwrap();
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, None)
        .await
        .unwrap();
    let scope = Scope::from_iter([OPENID]);
    let grant = commit_test_session_grant(
        &mut repo,
        &mut rng,
        &clock,
        TestSessionGrantSeed {
            request_identity: "revoke-if-active-issue",
            browser_session_id: Some(browser_session.id),
            device_id: "ak:device:019a0000-0000-7000-8000-00000000ca50",
            holder_seed: 0x22,
            scope,
        },
    )
    .await;

    // First consume wins.
    let first = repo
        .oauth_session_grant()
        .revoke_if_active(&clock, grant.id)
        .await
        .unwrap();
    assert!(first, "first revoke_if_active should consume the grant");

    let after_first = repo
        .oauth_session_grant()
        .lookup(grant.id)
        .await
        .unwrap()
        .unwrap();
    let revoked_at = after_first.revoked_at.expect("grant should be revoked");

    // Second consume loses — the grant is already revoked.
    let second = repo
        .oauth_session_grant()
        .revoke_if_active(&clock, grant.id)
        .await
        .unwrap();
    assert!(
        !second,
        "second revoke_if_active must report already-consumed"
    );

    let after_second = repo
        .oauth_session_grant()
        .lookup(grant.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_second.revoked_at,
        Some(revoked_at),
        "a losing CAS must not move revoked_at"
    );
}

/// Test the [`OAuthSessionRepository::list`] and
/// [`OAuthSessionRepository::count`] methods.
#[tokio::test]
async fn test_list_sessions() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();

    // Create two users and their corresponding browser sessions
    let user1 = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();
    let user1_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user1, None)
        .await
        .unwrap();

    let user2 = repo
        .user()
        .add(&mut rng, &clock, "bob".to_owned())
        .await
        .unwrap();
    let user2_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user2, None)
        .await
        .unwrap();

    // Create two clients
    let client1 = repo
        .oauth_client()
        .add(
            &mut rng,
            &clock,
            vec!["https://first.example.com/redirect".parse().unwrap()],
            None,
            None,
            None,
            vec![GrantType::AuthorizationCode],
            Some("First client".to_owned()),
            Some("https://first.example.com/logo.png".parse().unwrap()),
            Some("https://first.example.com/".parse().unwrap()),
            Some("https://first.example.com/policy".parse().unwrap()),
            Some("https://first.example.com/tos".parse().unwrap()),
            Some("https://first.example.com/jwks.json".parse().unwrap()),
            None,
            None,
            None,
            None,
            None,
            Some("https://first.example.com/login".parse().unwrap()),
        )
        .await
        .unwrap();
    let client2 = repo
        .oauth_client()
        .add(
            &mut rng,
            &clock,
            vec!["https://second.example.com/redirect".parse().unwrap()],
            None,
            None,
            None,
            vec![GrantType::AuthorizationCode],
            Some("Second client".to_owned()),
            Some("https://second.example.com/logo.png".parse().unwrap()),
            Some("https://second.example.com/".parse().unwrap()),
            Some("https://second.example.com/policy".parse().unwrap()),
            Some("https://second.example.com/tos".parse().unwrap()),
            Some("https://second.example.com/jwks.json".parse().unwrap()),
            None,
            None,
            None,
            None,
            None,
            Some("https://second.example.com/login".parse().unwrap()),
        )
        .await
        .unwrap();

    let scope = Scope::from_iter([OPENID, EMAIL]);
    let scope2 = Scope::from_iter([OPENID, PROFILE]);

    // Create two sessions for each user, one with each client
    // We're moving the clock forward by 1 minute between each session to ensure
    // we're getting consistent ordering in lists.
    let session11 = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &clock, &client1, &user1_session, scope.clone())
        .await
        .unwrap();
    clock.advance(Duration::try_minutes(1).unwrap());

    let session12 = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &clock, &client1, &user2_session, scope.clone())
        .await
        .unwrap();
    clock.advance(Duration::try_minutes(1).unwrap());

    let session21 = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &clock, &client2, &user1_session, scope2.clone())
        .await
        .unwrap();
    clock.advance(Duration::try_minutes(1).unwrap());

    let session22 = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &clock, &client2, &user2_session, scope2.clone())
        .await
        .unwrap();
    clock.advance(Duration::try_minutes(1).unwrap());

    // We're also finishing two of the sessions
    let session11 = repo
        .oauth_session()
        .finish(&clock, session11)
        .await
        .unwrap();
    let session22 = repo
        .oauth_session()
        .finish(&clock, session22)
        .await
        .unwrap();

    let pagination = Pagination::first(10);

    // First, list all the sessions
    let filter = OAuthSessionFilter::new().for_any_user();
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 4);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(list.edges[1].node, session12);
    assert_eq!(list.edges[2].node, session21);
    assert_eq!(list.edges[3].node, session22);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 4);

    // Now filter for only one user
    let filter = OAuthSessionFilter::new().for_user(&user1);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 2);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(list.edges[1].node, session21);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 2);

    // Filter for only one client
    let filter = OAuthSessionFilter::new().for_client(&client1);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 2);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(list.edges[1].node, session12);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 2);

    // Filter for both a user and a client
    let filter = OAuthSessionFilter::new()
        .for_user(&user2)
        .for_client(&client2);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node, session22);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 1);

    // Filter for active sessions
    let filter = OAuthSessionFilter::new().active_only();
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 2);
    assert_eq!(list.edges[0].node, session12);
    assert_eq!(list.edges[1].node, session21);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 2);

    // Filter for finished sessions
    let filter = OAuthSessionFilter::new().finished_only();
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 2);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(list.edges[1].node, session22);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 2);

    // Combine the finished filter with the user filter
    let filter = OAuthSessionFilter::new().finished_only().for_user(&user2);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node, session22);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 1);

    // Combine the finished filter with the client filter
    let filter = OAuthSessionFilter::new()
        .finished_only()
        .for_client(&client2);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node, session22);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 1);

    // Combine the active filter with the user filter
    let filter = OAuthSessionFilter::new().active_only().for_user(&user2);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node, session12);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 1);

    // Combine the active filter with the client filter
    let filter = OAuthSessionFilter::new().active_only().for_client(&client2);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node, session21);

    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 1);

    // Try the scope filter. We should get all sessions with the "openid" scope
    let scope = Scope::from_iter([OPENID]);
    let filter = OAuthSessionFilter::new().with_scope(&scope);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 4);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(list.edges[1].node, session12);
    assert_eq!(list.edges[2].node, session21);
    assert_eq!(list.edges[3].node, session22);
    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 4);

    // We should get all sessions with the "openid" and "email" scope
    let scope = Scope::from_iter([OPENID, EMAIL]);
    let filter = OAuthSessionFilter::new().with_scope(&scope);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert!(!list.has_next_page);
    assert_eq!(list.edges.len(), 2);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(list.edges[1].node, session12);
    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 2);

    // Try combining the scope filter with the user filter
    let filter = OAuthSessionFilter::new()
        .with_scope(&scope)
        .for_user(&user1);
    let list = repo.oauth_session().list(filter, pagination).await.unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node, session11);
    assert_eq!(repo.oauth_session().count(filter).await.unwrap(), 1);

    // Finish all sessions of a client in batch
    let affected = repo
        .oauth_session()
        .finish_bulk(
            &clock,
            OAuthSessionFilter::new().for_client(&client1).active_only(),
        )
        .await
        .unwrap();
    assert_eq!(affected, 1);

    // We should have 3 finished sessions
    assert_eq!(
        repo.oauth_session()
            .count(OAuthSessionFilter::new().finished_only())
            .await
            .unwrap(),
        3
    );

    // We should have 1 active sessions
    assert_eq!(
        repo.oauth_session()
            .count(OAuthSessionFilter::new().active_only())
            .await
            .unwrap(),
        1
    );
}

/// Test the [`OAuthDeviceCodeGrantRepository`] implementation
#[tokio::test]
async fn test_device_code_grant_repository() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();

    // Provision a client
    let client = repo
        .oauth_client()
        .add(
            &mut rng,
            &clock,
            vec!["https://example.com/redirect".parse().unwrap()],
            None,
            None,
            None,
            vec![GrantType::AuthorizationCode],
            Some("Example".to_owned()),
            Some("https://example.com/logo.png".parse().unwrap()),
            Some("https://example.com/".parse().unwrap()),
            Some("https://example.com/policy".parse().unwrap()),
            Some("https://example.com/tos".parse().unwrap()),
            Some("https://example.com/jwks.json".parse().unwrap()),
            None,
            None,
            None,
            None,
            None,
            Some("https://example.com/login".parse().unwrap()),
        )
        .await
        .unwrap();

    // Provision a user
    let user = repo
        .user()
        .add(&mut rng, &clock, "john".to_owned())
        .await
        .unwrap();

    // Provision a browser session
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, None)
        .await
        .unwrap();

    let user_code = "usercode";
    let device_code = "devicecode";
    let scope = Scope::from_iter([OPENID, EMAIL]);

    // Create a device code grant
    let grant = repo
        .oauth_device_code_grant()
        .add(
            &mut rng,
            &clock,
            OAuthDeviceCodeGrantParams {
                client: &client,
                scope: scope.clone(),
                device_code: device_code.to_owned(),
                user_code: user_code.to_owned(),
                expires_in: Duration::try_minutes(5).unwrap(),
                ip_address: None,
                user_agent: None,
            },
        )
        .await
        .unwrap();

    assert!(grant.is_pending());

    // Check that we can find the grant by ID
    let id = grant.id;
    let lookup = repo.oauth_device_code_grant().lookup(id).await.unwrap();
    assert_eq!(lookup.as_ref(), Some(&grant));

    // Check that we can find the grant by device code
    let lookup = repo
        .oauth_device_code_grant()
        .find_by_device_code(device_code)
        .await
        .unwrap();
    assert_eq!(lookup.as_ref(), Some(&grant));

    // Check that we can find the grant by user code
    let lookup = repo
        .oauth_device_code_grant()
        .find_by_user_code(user_code)
        .await
        .unwrap();
    assert_eq!(lookup.as_ref(), Some(&grant));

    // Let's mark it as fulfilled
    let grant = repo
        .oauth_device_code_grant()
        .fulfill(&clock, grant, &browser_session)
        .await
        .unwrap();
    assert!(!grant.is_pending());
    assert!(grant.is_fulfilled());

    // Check that we can't mark it as rejected now
    let res = repo
        .oauth_device_code_grant()
        .reject(&clock, grant, &browser_session)
        .await;
    assert!(res.is_err());

    // Look it up again
    let grant = repo
        .oauth_device_code_grant()
        .lookup(id)
        .await
        .unwrap()
        .unwrap();

    // We can't mark it as fulfilled again
    let res = repo
        .oauth_device_code_grant()
        .fulfill(&clock, grant, &browser_session)
        .await;
    assert!(res.is_err());

    // Look it up again
    let grant = repo
        .oauth_device_code_grant()
        .lookup(id)
        .await
        .unwrap()
        .unwrap();

    // Create an OAuth session
    let session = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &clock, &client, &browser_session, scope.clone())
        .await
        .unwrap();

    // We can mark it as exchanged
    let grant = repo
        .oauth_device_code_grant()
        .exchange(&clock, grant, &session)
        .await
        .unwrap();
    assert!(!grant.is_pending());
    assert!(!grant.is_fulfilled());
    assert!(grant.is_exchanged());

    // We can't mark it as exchanged again
    let res = repo
        .oauth_device_code_grant()
        .exchange(&clock, grant, &session)
        .await;
    assert!(res.is_err());

    // Do a new grant to reject it
    let grant = repo
        .oauth_device_code_grant()
        .add(
            &mut rng,
            &clock,
            OAuthDeviceCodeGrantParams {
                client: &client,
                scope: scope.clone(),
                device_code: "second_devicecode".to_owned(),
                user_code: "second_usercode".to_owned(),
                expires_in: Duration::try_minutes(5).unwrap(),
                ip_address: None,
                user_agent: None,
            },
        )
        .await
        .unwrap();

    let id = grant.id;

    // We can mark it as rejected
    let grant = repo
        .oauth_device_code_grant()
        .reject(&clock, grant, &browser_session)
        .await
        .unwrap();
    assert!(!grant.is_pending());
    assert!(grant.is_rejected());

    // We can't mark it as rejected again
    let res = repo
        .oauth_device_code_grant()
        .reject(&clock, grant, &browser_session)
        .await;
    assert!(res.is_err());

    // Look it up again
    let grant = repo
        .oauth_device_code_grant()
        .lookup(id)
        .await
        .unwrap()
        .unwrap();

    // We can't mark it as fulfilled
    let res = repo
        .oauth_device_code_grant()
        .fulfill(&clock, grant, &browser_session)
        .await;
    assert!(res.is_err());

    // Look it up again
    let grant = repo
        .oauth_device_code_grant()
        .lookup(id)
        .await
        .unwrap()
        .unwrap();

    // We can't mark it as exchanged
    let res = repo
        .oauth_device_code_grant()
        .exchange(&clock, grant, &session)
        .await;
    assert!(res.is_err());
}
