//! A module containing the PostgreSQL implementations of the OAuth-related
//! repositories

mod access_token;
mod authorization_grant;
mod client;
mod device_code_grant;
mod refresh_token;
mod session;
mod session_grant;

pub use self::access_token::PgOAuthAccessTokenRepository;
pub use self::authorization_grant::PgOAuthAuthorizationGrantRepository;
pub use self::client::PgOAuthClientRepository;
pub use self::device_code_grant::PgOAuthDeviceCodeGrantRepository;
pub use self::refresh_token::PgOAuthRefreshTokenRepository;
pub use self::session::PgOAuthSessionRepository;
pub use self::session_grant::PgOAuthSessionGrantRepository;

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::clock::MockClock;
    use coauth_data::oauth::{
        NewSessionGrant, OAuthDeviceCodeGrantParams, OAuthSessionFilter, OAuthSessionRepository,
    };
    use coauth_data::{
        AuthorizationCode, Clock, Pagination, RefreshTokenState, RepositoryAccess,
        RepositoryFactory as _,
    };
    use coauth_oauth_types::requests::{GrantType, ResponseMode};
    use coauth_oauth_types::scope::{EMAIL, OPENID, PROFILE, Scope};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use crate::PgRepositoryFactory;

    /// Closed inputs a test needs to land one committed session grant.
    struct TestSessionGrantSeed<'a> {
        request_identity: &'a str,
        grant_id: &'a str,
        browser_session_id: Option<Ulid>,
        device_id: &'a str,
        session_id: &'a str,
        grant_jwt: &'a str,
        session_public_key: &'a str,
        issuance_digest: [u8; 32],
        scope: Scope,
    }

    /// Reserve then commit one grant through the issuer-ledger saga.
    ///
    /// The repository has no single-call `add`: a grant only becomes durable as
    /// the committed outcome of a reserved operation, so tests that need a
    /// persisted grant must walk the same two steps production does.
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
        let issuer = "did:web:issuer.example";
        let not_before = clock.now();
        let expires_at = clock.now() + Duration::try_hours(1).unwrap();
        let canonical_intent = b"{\"schema\":\"ak.session_grant.issuance.v1\"}";

        let reserved = repo
            .oauth_session_grant()
            .reserve_operation(
                rng,
                clock,
                coauth_data::NewSessionGrantOperation {
                    issuer,
                    operation_kind: coauth_data::SessionGrantOperationKind::Issue,
                    proof_kind: None,
                    request_identity: seed.request_identity,
                    canonical_intent_digest: seed.issuance_digest,
                    canonical_intent,
                    operation_selector: None,
                    target_grant_id: None,
                    issuance_nonce: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
                    session_id: Some(seed.session_id),
                    grant_not_before: Some(not_before),
                    grant_expires_at: Some(expires_at),
                    signing_key_id: Some("test-signing-key"),
                    retained_until: clock.now() + Duration::try_days(7).unwrap(),
                },
            )
            .await
            .unwrap();
        let operation_id = match reserved {
            coauth_data::SessionGrantReserveOutcome::Reserved(operation) => operation.id,
            other => panic!("expected a fresh reservation, got {other:?}"),
        };

        let checkpoint = serde_json::json!({"kind": "test"});
        let committed = repo
            .oauth_session_grant()
            .commit_issuance(
                rng,
                clock,
                operation_id,
                coauth_data::SessionGrantProofAuthorization {
                    authorization_ref: seed.request_identity,
                    checkpoint: &checkpoint,
                    proof_expires_at: clock.now() + Duration::try_minutes(5).unwrap(),
                },
                coauth_data::SessionGrantExactOutcome {
                    canonical_response: canonical_intent,
                    response_digest: seed.issuance_digest,
                },
                NewSessionGrant {
                    grant_id: arkret_identifiers::SessionGrantId::new(seed.grant_id.to_owned())
                        .unwrap(),
                    browser_session_id: seed.browser_session_id,
                    issuer,
                    subject: "did:web:subject.example",
                    device_id: Some(seed.device_id),
                    applet_id: None,
                    effective_scope: None,
                    registration_epoch: None,
                    service_id: None,
                    capability_grant_refs: Vec::new(),
                    audience: "did:web:audience.example",
                    scope: seed.scope,
                    grant_jwt: seed.grant_jwt,
                    session_id: seed.session_id,
                    issuance_nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                    issuance_preimage: canonical_intent,
                    issuance_digest: seed.issuance_digest,
                    signing_key_id: "test-signing-key",
                    session_public_key: seed.session_public_key,
                    credential_class: "standard",
                    not_before,
                    expires_at,
                },
            )
            .await
            .unwrap();

        match committed {
            coauth_data::SessionGrantCommitOutcome::Committed(grant) => grant,
            other => panic!("expected a first commit, got {other:?}"),
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
                grant_id: "ak:session_grant:AVBgYTmzSkzTSd1dlFH4ZADaQRkVcx_iTAvXdxlTfxrg",
                browser_session_id: Some(user_session.id),
                device_id: "device-1",
                session_id: "session-chain-1",
                grant_jwt: "session-grant-jwt",
                session_public_key: "session-public-key",
                issuance_digest: [0x11; 32],
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
                grant_id: "ak:session_grant:AUiTFJVo328Rc7lc2Le2mjzL_ELZ-uQUn1Fq-C1QNAbh",
                browser_session_id: Some(browser_session.id),
                device_id: "device-cas",
                session_id: "session-chain-cas",
                grant_jwt: "cas-grant-jwt",
                session_public_key: "cas-public-key",
                issuance_digest: [0x22; 32],
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
}
