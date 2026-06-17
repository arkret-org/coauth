//! Tests for the token-service grant-type handlers.

#![allow(clippy::items_after_test_module)]

use std::sync::Arc;

use chrono::Duration;
use coauth_data::clock::MockClock;
use coauth_data::oauth::{LocalizedClientMetadata, NewSessionGrant};
use coauth_data::{
    Client, PgRepositoryFactory, RefreshToken, RefreshTokenState, RepositoryFactory as _,
    SiteConfig, TokenType,
};
use coauth_iana::oauth::{OAuthClientAuthenticationMethod, PkceCodeChallengeMethod};
use oauth_types::requests::{AccessTokenResponse, GrantType, RefreshTokenGrant};
use oauth_types::scope::{OPENID, Scope};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use ulid::Ulid;
use url::Url;

use super::*;
use crate::handlers::{ActivityTracker, BoundActivityTracker};

fn client_with_auth_method(method: Option<OAuthClientAuthenticationMethod>) -> Client {
    Client {
        id: Ulid::new(),
        client_id: "client".to_owned(),
        metadata_digest: None,
        encrypted_client_secret: None,
        application_type: None,
        redirect_uris: vec![Url::parse("https://client.example/callback").unwrap()],
        grant_types: vec![GrantType::AuthorizationCode],
        client_name: None,
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        localized_metadata: LocalizedClientMetadata::default(),
        jwks: None,
        id_token_signed_response_alg: None,
        userinfo_signed_response_alg: None,
        token_endpoint_auth_method: method,
        token_endpoint_auth_signing_alg: None,
        initiate_login_uri: None,
    }
}

#[test]
fn public_authorization_code_clients_require_s256_pkce() {
    let client = client_with_auth_method(Some(OAuthClientAuthenticationMethod::None));
    assert!(authorization_code_pkce_required(&client));
    assert!(required_pkce_method_is_allowed(
        &PkceCodeChallengeMethod::S256
    ));
    assert!(!required_pkce_method_is_allowed(
        &PkceCodeChallengeMethod::Plain
    ));
}

#[test]
fn confidential_authorization_code_clients_do_not_require_pkce() {
    let client = client_with_auth_method(Some(OAuthClientAuthenticationMethod::ClientSecretBasic));
    assert!(!authorization_code_pkce_required(&client));
}

struct RefreshFixture {
    factory: PgRepositoryFactory,
    clock: Arc<MockClock>,
    activity_tracker: BoundActivityTracker,
    client: Client,
    site_config: SiteConfig,
    initial_refresh_token: RefreshToken,
    initial_access_token_id: Ulid,
    session_grant_id: Ulid,
    cancellation_token: CancellationToken,
    _task_tracker: TaskTracker,
}

impl RefreshFixture {
    fn shutdown(&self) {
        self.cancellation_token.cancel();
    }
}

async fn make_refresh_fixture(seed: u64, handle: &str) -> Option<RefreshFixture> {
    let pool = coauth_data::test_utils::setup_test_pool().await?;

    let factory = PgRepositoryFactory::new(pool);
    let clock = Arc::new(MockClock::default());
    let task_tracker = TaskTracker::new();
    let cancellation_token = CancellationToken::new();
    let activity_tracker = ActivityTracker::new(
        factory.clone().boxed(),
        std::time::Duration::from_mins(1),
        &task_tracker,
        cancellation_token.clone(),
    )
    .bind(None);
    let site_config = crate::handlers::test_utils::test_site_config();
    let mut rng = ChaChaRng::seed_from_u64(seed);
    let mut repo = factory.create().await.unwrap();

    let client = repo
        .oauth_client()
        .add(
            &mut rng,
            &*clock,
            vec!["https://client.example/callback".parse().unwrap()],
            None,
            None,
            None,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            Some(format!("{handle} client")),
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
        .add(&mut rng, &*clock, handle.to_owned())
        .await
        .unwrap();
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &*clock, &user, None)
        .await
        .unwrap();
    let scope = Scope::from_iter([OPENID]);
    let session = repo
        .oauth_session()
        .add_from_browser_session(&mut rng, &*clock, &client, &browser_session, scope.clone())
        .await
        .unwrap();
    let session_grant = repo
        .oauth_session_grant()
        .add(
            &mut rng,
            &*clock,
            NewSessionGrant {
                browser_session_id: browser_session.id,
                issuer: "did:web:issuer.example",
                subject: "did:web:subject.example",
                device_id: Some("device-1"),
                audience: "did:web:audience.example",
                scope,
                grant_jwt: "session-grant-jwt",
                session_public_key: "session-public-key",
                expires_at: clock.now() + Duration::try_hours(1).unwrap(),
            },
        )
        .await
        .unwrap();
    let access_token_value = TokenType::AccessToken.generate(&mut rng);
    let access_token = repo
        .oauth_access_token()
        .add(
            &mut rng,
            &*clock,
            &session,
            access_token_value,
            Some(site_config.access_token_ttl),
        )
        .await
        .unwrap();
    let refresh_token_value = TokenType::RefreshToken.generate(&mut rng);
    let refresh_token = repo
        .oauth_refresh_token()
        .add(
            &mut rng,
            &*clock,
            &session,
            &access_token,
            refresh_token_value,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    Some(RefreshFixture {
        factory,
        clock,
        activity_tracker,
        client,
        site_config,
        initial_refresh_token: refresh_token,
        initial_access_token_id: access_token.id,
        session_grant_id: session_grant.id,
        cancellation_token,
        _task_tracker: task_tracker,
    })
}

async fn redeem_refresh_token(
    fixture: &RefreshFixture,
    refresh_token: String,
    rng_seed: u64,
) -> Result<AccessTokenResponse, RefreshTokenExchangeError> {
    let mut rng = ChaChaRng::seed_from_u64(rng_seed);
    let repo = fixture.factory.create().await.unwrap();
    let grant = RefreshTokenGrant {
        refresh_token,
        scope: None,
    };
    let (reply, repo) = handle_refresh_token(
        &mut rng,
        &fixture.clock,
        &fixture.activity_tracker,
        &grant,
        &fixture.client,
        &fixture.site_config,
        repo,
        None,
    )
    .await?;
    repo.save().await?;
    Ok(reply)
}

async fn find_refresh_token(fixture: &RefreshFixture, token: &str) -> RefreshToken {
    let mut repo = fixture.factory.create().await.unwrap();
    let refresh_token = repo
        .oauth_refresh_token()
        .find_by_token(token)
        .await
        .unwrap()
        .expect("refresh token should exist");
    repo.cancel().await.unwrap();
    refresh_token
}

async fn assert_refresh_tokens_revoked(fixture: &RefreshFixture, ids: &[Ulid]) {
    let mut repo = fixture.factory.create().await.unwrap();
    for id in ids {
        let token = repo
            .oauth_refresh_token()
            .lookup(*id)
            .await
            .unwrap()
            .expect("refresh token should exist");
        assert!(
            matches!(token.state, RefreshTokenState::Revoked { .. }),
            "refresh token {id} should be revoked, got {:?}",
            token.state
        );
    }
    repo.cancel().await.unwrap();
}

async fn assert_access_token_revoked(fixture: &RefreshFixture, id: Ulid) {
    let mut repo = fixture.factory.create().await.unwrap();
    let token = repo
        .oauth_access_token()
        .lookup(id)
        .await
        .unwrap()
        .expect("access token should exist");
    assert!(
        token.state.is_revoked(),
        "access token {id} should be revoked"
    );
    repo.cancel().await.unwrap();
}

async fn assert_session_grant_revoked(fixture: &RefreshFixture) {
    let mut repo = fixture.factory.create().await.unwrap();
    let grant = repo
        .oauth_session_grant()
        .lookup(fixture.session_grant_id)
        .await
        .unwrap()
        .expect("session grant should exist");
    assert!(grant.revoked_at.is_some());
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn refresh_handler_revokes_chain_on_old_token_reuse() {
    let Some(fixture) = make_refresh_fixture(101, "refresh-reuse-user").await else {
        return;
    };

    let first_reply = redeem_refresh_token(
        &fixture,
        fixture.initial_refresh_token.refresh_token.clone(),
        102,
    )
    .await
    .expect("first refresh should succeed");
    let successor = find_refresh_token(
        &fixture,
        first_reply
            .refresh_token
            .as_deref()
            .expect("successor refresh token should be returned"),
    )
    .await;

    let error = redeem_refresh_token(
        &fixture,
        fixture.initial_refresh_token.refresh_token.clone(),
        103,
    )
    .await
    .expect_err("old refresh token reuse should be rejected");
    assert!(matches!(
        error,
        RefreshTokenExchangeError::RefreshTokenInvalid(id)
            if id == fixture.initial_refresh_token.id
    ));

    assert_refresh_tokens_revoked(&fixture, &[fixture.initial_refresh_token.id, successor.id])
        .await;
    assert_access_token_revoked(&fixture, fixture.initial_access_token_id).await;
    assert_session_grant_revoked(&fixture).await;
    fixture.shutdown();
}

#[tokio::test]
async fn refresh_handler_revokes_chain_when_reused_successor_was_already_used() {
    let Some(fixture) = make_refresh_fixture(201, "refresh-next-used-user").await else {
        return;
    };

    let second_token_value = redeem_refresh_token(
        &fixture,
        fixture.initial_refresh_token.refresh_token.clone(),
        202,
    )
    .await
    .expect("first refresh should succeed")
    .refresh_token
    .expect("second refresh token should be returned");
    let second_token = find_refresh_token(&fixture, &second_token_value).await;
    let third_token_value = redeem_refresh_token(&fixture, second_token_value.clone(), 203)
        .await
        .expect("second refresh should succeed")
        .refresh_token
        .expect("third refresh token should be returned");
    let third_token = find_refresh_token(&fixture, &third_token_value).await;

    let error = redeem_refresh_token(&fixture, second_token_value, 204)
        .await
        .expect_err("reusing an already-used successor should be rejected");
    assert!(matches!(
        error,
        RefreshTokenExchangeError::RefreshTokenInvalid(id) if id == second_token.id
    ));

    assert_refresh_tokens_revoked(
        &fixture,
        &[
            fixture.initial_refresh_token.id,
            second_token.id,
            third_token.id,
        ],
    )
    .await;
    assert_session_grant_revoked(&fixture).await;
    fixture.shutdown();
}

#[tokio::test]
async fn refresh_handler_revokes_chain_when_idle_window_expired() {
    let Some(fixture) = make_refresh_fixture(301, "refresh-idle-user").await else {
        return;
    };
    fixture
        .clock
        .advance(Duration::try_hours(13).unwrap() + Duration::try_seconds(1).unwrap());

    let error = redeem_refresh_token(
        &fixture,
        fixture.initial_refresh_token.refresh_token.clone(),
        302,
    )
    .await
    .expect_err("idle refresh token should be rejected");
    assert!(matches!(
        error,
        RefreshTokenExchangeError::RefreshTokenInvalid(id)
            if id == fixture.initial_refresh_token.id
    ));

    assert_refresh_tokens_revoked(&fixture, &[fixture.initial_refresh_token.id]).await;
    assert_access_token_revoked(&fixture, fixture.initial_access_token_id).await;
    assert_session_grant_revoked(&fixture).await;
    fixture.shutdown();
}

#[tokio::test]
async fn refresh_handler_revokes_chain_when_rotation_window_expired() {
    let Some(fixture) = make_refresh_fixture(401, "refresh-rotation-user").await else {
        return;
    };
    fixture
        .clock
        .advance(Duration::try_hours(25).unwrap() + Duration::try_seconds(1).unwrap());

    let error = redeem_refresh_token(
        &fixture,
        fixture.initial_refresh_token.refresh_token.clone(),
        402,
    )
    .await
    .expect_err("expired rotation window should be rejected");
    assert!(matches!(
        error,
        RefreshTokenExchangeError::RefreshTokenInvalid(id)
            if id == fixture.initial_refresh_token.id
    ));

    assert_refresh_tokens_revoked(&fixture, &[fixture.initial_refresh_token.id]).await;
    assert_access_token_revoked(&fixture, fixture.initial_access_token_id).await;
    assert_session_grant_revoked(&fixture).await;
    fixture.shutdown();
}

#[tokio::test]
async fn device_logout_chain_revoke_blocks_current_refresh_token() {
    let Some(fixture) = make_refresh_fixture(501, "refresh-device-logout-user").await else {
        return;
    };
    let current_token_value = redeem_refresh_token(
        &fixture,
        fixture.initial_refresh_token.refresh_token.clone(),
        502,
    )
    .await
    .expect("first refresh should succeed")
    .refresh_token
    .expect("current refresh token should be returned");
    let current_token = find_refresh_token(&fixture, &current_token_value).await;

    let mut repo = fixture.factory.create().await.unwrap();
    let outcome = repo
        .oauth_refresh_token()
        .revoke_chain_by_root(&fixture.clock, current_token.chain_root_id)
        .await
        .unwrap();
    assert_eq!(outcome.refresh_tokens, 2);
    repo.save().await.unwrap();

    let error = redeem_refresh_token(&fixture, current_token_value, 503)
        .await
        .expect_err("device logout chain revoke should block refresh");
    assert!(matches!(
        error,
        RefreshTokenExchangeError::RefreshTokenInvalid(id) if id == current_token.id
    ));
    assert_refresh_tokens_revoked(
        &fixture,
        &[fixture.initial_refresh_token.id, current_token.id],
    )
    .await;
    assert_session_grant_revoked(&fixture).await;
    fixture.shutdown();
}

#[tokio::test]
async fn concurrent_refresh_only_one_exchange_succeeds() {
    let Some(fixture) = make_refresh_fixture(601, "refresh-concurrent-user").await else {
        return;
    };

    async fn redeem_with_owned_inputs(
        factory: PgRepositoryFactory,
        clock: Arc<MockClock>,
        activity_tracker: BoundActivityTracker,
        client: Client,
        site_config: SiteConfig,
        refresh_token: String,
        rng_seed: u64,
    ) -> Result<AccessTokenResponse, RefreshTokenExchangeError> {
        let mut rng = ChaChaRng::seed_from_u64(rng_seed);
        let repo = factory.create().await.unwrap();
        let grant = RefreshTokenGrant {
            refresh_token,
            scope: None,
        };
        let (reply, repo) = handle_refresh_token(
            &mut rng,
            &clock,
            &activity_tracker,
            &grant,
            &client,
            &site_config,
            repo,
            None,
        )
        .await?;
        repo.save().await?;
        Ok(reply)
    }

    let first = tokio::spawn(redeem_with_owned_inputs(
        fixture.factory.clone(),
        Arc::clone(&fixture.clock),
        fixture.activity_tracker.clone(),
        fixture.client.clone(),
        fixture.site_config.clone(),
        fixture.initial_refresh_token.refresh_token.clone(),
        602,
    ));
    let second = tokio::spawn(redeem_with_owned_inputs(
        fixture.factory.clone(),
        Arc::clone(&fixture.clock),
        fixture.activity_tracker.clone(),
        fixture.client.clone(),
        fixture.site_config.clone(),
        fixture.initial_refresh_token.refresh_token.clone(),
        603,
    ));

    let results = [first.await.unwrap(), second.await.unwrap()];
    let success_count = results.iter().filter(|result| result.is_ok()).count();
    let failure_count = results.iter().filter(|result| result.is_err()).count();

    assert_eq!(success_count, 1);
    assert_eq!(failure_count, 1);

    let mut repo = fixture.factory.create().await.unwrap();
    let original = repo
        .oauth_refresh_token()
        .lookup(fixture.initial_refresh_token.id)
        .await
        .unwrap()
        .expect("original refresh token should exist");
    assert!(matches!(original.state, RefreshTokenState::Consumed { .. }));
    repo.cancel().await.unwrap();
    fixture.shutdown();
}
