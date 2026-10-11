use coauth_data::clock::MockClock;
use coauth_data::upstream_oauth::UpstreamOAuthProviderParams;
use coauth_data::{RepositoryFactory as _, SystemClock};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_oauth_types::scope::{OPENID, Scope};
use coauth_storage_postgres::test_utils::{TestDatabase, setup_test_pool};
use hyper::{Request, StatusCode};
use rand_core::SeedableRng as _;

use super::*;
use crate::handlers::test_utils::{CookieHelper, TestState, setup};
use crate::handlers::upstream_oauth::UpstreamSessionsCookie;
use crate::salvo_utils::SessionInfoExt;
use crate::salvo_utils::cookies::TimedCookie as _;

struct Fixture {
    _database: TestDatabase,
    state: TestState,
    link: UpstreamOAuthLink,
    upstream: UpstreamOAuthAuthorizationSession,
    browser: BrowserSession,
}

impl Fixture {
    async fn new() -> Self {
        setup();
        let database = setup_test_pool()
            .await
            .expect("isolated PostgreSQL required");
        let mut state = TestState::from_pool(database.clone()).await.unwrap();
        state.clock = std::sync::Arc::new(MockClock::new(SystemClock::default().now()));
        let clock = state.clock.clone();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(906);
        let mut repo = state.repository_factory.create().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &clock,
                UpstreamOAuthProviderParams {
                    oidc_issuer_uri: Some("https://provider.example/".to_owned()),
                    human_name: None,
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: provider::TokenAuthMethod::None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Ed25519,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    token_endpoint_signing_alg: None,
                    client_id: "r06-link".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: provider::ClaimsImports::default(),
                    token_endpoint_override: None,
                    authorization_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: provider::DiscoveryMode::Oidc,
                    pkce_mode: provider::PkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: provider::OnBackchannelLogout::DoNothing,
                    source: provider::ProviderSource::Config,
                },
            )
            .await
            .unwrap();
        let user = repo
            .user()
            .add(&mut rng, &clock, "linkuser".to_owned())
            .await
            .unwrap();
        let browser = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(&mut rng, &clock, &provider, "subject".to_owned(), None)
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .lookup(link.id)
            .await
            .unwrap()
            .unwrap();
        let upstream = repo
            .upstream_oauth_session()
            .add(&mut rng, &clock, &provider, "state".to_owned(), None, None)
            .await
            .unwrap();
        let upstream = repo
            .upstream_oauth_session()
            .complete_with_link(&clock, upstream, &link, None, None, None, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        Self {
            _database: database,
            state,
            link,
            upstream,
            browser,
        }
    }

    fn input(&self) -> UpstreamLinkContextInput {
        UpstreamLinkContextInput {
            link_id: self.link.id,
            upstream_session_id: self.upstream.id,
            browser_session_id: Some(self.browser.id),
            post_auth_action: Some(PostAuthAction::ChangePassword),
        }
    }

    fn cookies(&self) -> CookieHelper {
        let cookies = CookieHelper::new();
        let upstream = UpstreamSessionsCookie::default()
            .add(
                self.upstream.id,
                self.upstream.provider_id,
                "state".to_owned(),
                Some(PostAuthAction::ChangePassword),
            )
            .add_link_to_session(self.upstream.id, self.link.id)
            .unwrap();
        cookies.import(upstream.save(
            self.state.cookie_jar().set_session(&self.browser),
            &self.state.clock,
        ));
        cookies
    }
}

#[tokio::test]
async fn context_checks_ownership_before_loading_active_browser_session() {
    let fixture = Fixture::new().await;
    let mut repo = fixture.state.repository().await.unwrap();
    let mut input = fixture.input();
    input.link_id = Ulid::from(1_u128);
    input.upstream_session_id = Ulid::from(2_u128);
    assert!(matches!(
        load_upstream_link_context(&mut repo, input).await,
        Err(UpstreamLinkWorkflowError::LinkNotFound)
    ));
    let mut input = fixture.input();
    input.upstream_session_id = Ulid::from(2_u128);
    assert!(matches!(
        load_upstream_link_context(&mut repo, input).await,
        Err(UpstreamLinkWorkflowError::SessionNotFound)
    ));
    let provider = repo
        .upstream_oauth_provider()
        .lookup(fixture.upstream.provider_id)
        .await
        .unwrap()
        .unwrap();
    let mut rng = fixture.state.rng();
    let other = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &*fixture.state.clock,
            &provider,
            "other".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();
    let mut input = fixture.input();
    input.upstream_session_id = other.id;
    assert!(matches!(
        load_upstream_link_context(&mut repo, input).await,
        Err(UpstreamLinkWorkflowError::SessionNotFound)
    ));
    repo.browser_session()
        .finish(&*fixture.state.clock, fixture.browser.clone())
        .await
        .unwrap();
    let context = load_upstream_link_context(&mut repo, fixture.input())
        .await
        .unwrap();
    assert!(context.browser_session.is_none());
    repo.upstream_oauth_session()
        .consume(
            &*fixture.state.clock,
            fixture.upstream.clone(),
            &fixture.browser,
        )
        .await
        .unwrap();
    assert!(matches!(
        load_upstream_link_context(&mut repo, fixture.input()).await,
        Err(UpstreamLinkWorkflowError::SessionConsumed)
    ));
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn authentication_and_one_shot_consumption_roll_back_with_the_caller_transaction() {
    let fixture = Fixture::new().await;
    let mut repo = fixture.state.repository().await.unwrap();
    let context = load_upstream_link_context(&mut repo, fixture.input())
        .await
        .unwrap();
    let mut rng = fixture.state.rng();
    let mut policy = fixture.state.policy_factory.instantiate().await.unwrap();
    let outcome = load_upstream_link_state(
        &mut repo,
        &mut rng,
        &*fixture.state.clock,
        crate::services::upstream_link::UpstreamLinkEnvironment {
            url_builder: &fixture.state.url_builder,
            station: &*fixture.state.station_admin,
            policy: &mut policy,
            site_config: &fixture.state.site_config,
            user_agent: None,
            ip_address: None,
        },
        context,
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        LoadUpstreamLinkOutcome::Authenticated { .. }
    ));
    assert!(
        repo.upstream_oauth_session()
            .lookup(fixture.upstream.id)
            .await
            .unwrap()
            .unwrap()
            .is_consumed()
    );
    assert!(
        repo.browser_session()
            .get_last_authentication(&fixture.browser)
            .await
            .unwrap()
            .is_some()
    );
    repo.cancel().await.unwrap();
    let mut repo = fixture.state.repository().await.unwrap();
    assert!(
        !repo
            .upstream_oauth_session()
            .lookup(fixture.upstream.id)
            .await
            .unwrap()
            .unwrap()
            .is_consumed()
    );
    assert!(
        repo.browser_session()
            .get_last_authentication(&fixture.browser)
            .await
            .unwrap()
            .is_none()
    );
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn http_cookie_guard_commit_and_replay_preserve_the_domain_boundary() {
    let fixture = Fixture::new().await;
    let path = format!("/_coauth/self/upstream-oauth/link/{}", fixture.link.id);
    for method in ["GET", "POST"] {
        let request = Request::builder()
            .method(method)
            .uri(&path)
            .header("Content-Type", "application/json")
            .body(
                if method == "POST" {
                    r#"{"action":"link"}"#
                } else {
                    ""
                }
                .to_owned(),
            )
            .unwrap();
        let response = fixture.state.request(request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.body().contains("missing upstream session cookie"));
    }
    let cookies = fixture.cookies();
    let request = cookies.with_cookies(Request::get(&path).body(String::new()).unwrap());
    let response = fixture.state.request(request).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", response.body());
    let body: serde_json::Value = serde_json::from_str(response.body()).unwrap();
    assert_eq!(body["redirect_url"], "/account/password/change");
    let mut repo = fixture.state.repository().await.unwrap();
    assert!(
        repo.upstream_oauth_session()
            .lookup(fixture.upstream.id)
            .await
            .unwrap()
            .unwrap()
            .is_consumed()
    );
    assert!(
        repo.browser_session()
            .get_last_authentication(&fixture.browser)
            .await
            .unwrap()
            .is_some()
    );
    repo.cancel().await.unwrap();
    let replay = fixture
        .state
        .request(cookies.with_cookies(Request::get(&path).body(String::new()).unwrap()))
        .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(replay.body().contains("session already consumed"));
}
