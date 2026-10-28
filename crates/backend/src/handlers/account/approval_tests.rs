//! Real cookie, transaction and callback regressions for authorization consent.

use coauth_data::oauth::{
    OAuthAuthorizationGrantRepository as _, OAuthClientRepository as _, OAuthSessionFilter,
    OAuthSessionRepository as _,
};
use coauth_data::user::{
    BrowserSessionRepository as _, UserPasswordRepository as _, UserRepository as _,
};
use coauth_data::{AuthorizationGrantStage, BrowserSession, Client, RepositoryAccess as _};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_jose::constraints::Constrainable as _;
use cookie_store::{CookieStore, RawCookie};
use hyper::header::{COOKIE, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use rand_core::SeedableRng as _;
use serde_json::{Value, json};
use ulid::Ulid;

use crate::handlers::test_utils::{
    RequestBuilderExt as _, ResponseExt as _, TestState, setup, unique_test_nonce,
};
use crate::salvo_utils::SessionInfoExt as _;

#[derive(Clone, Default)]
struct Browser(CookieStore);

impl Browser {
    fn session(state: &TestState, session: &BrowserSession) -> Self {
        let mut browser = Self::default();
        browser.import(state.cookie_jar().set_session(session));
        browser
    }

    fn import(&mut self, jar: crate::salvo_utils::cookies::CookieJar) {
        self.0.store_response_cookies(
            jar.pending_cookies()
                .iter()
                .map(|cookie| RawCookie::parse(cookie.to_string()).unwrap()),
            &"https://example.com/".parse().unwrap(),
        );
    }

    fn request(&self, mut request: Request<String>) -> Request<String> {
        let cookies = self
            .0
            .get_request_values(&"https://example.com/".parse().unwrap())
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        request
            .headers_mut()
            .insert(COOKIE, cookies.parse().unwrap());
        request
    }

    async fn send(&mut self, state: &TestState, request: Request<String>) -> Response<String> {
        let response = state.request(self.request(request)).await;
        let cookies = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| RawCookie::parse(value.to_str().unwrap().to_owned()).unwrap())
            .collect::<Vec<_>>();
        self.0.store_response_cookies(
            cookies.into_iter(),
            &"https://example.com/".parse().unwrap(),
        );
        response
    }

    fn pending(
        &self,
        state: &TestState,
    ) -> crate::handlers::oauth::authorization::consent_cookie::PendingConsents {
        use crate::salvo_utils::cookies::TimedCookie as _;
        let mut raw = cookie::CookieJar::new();
        for (name, value) in self
            .0
            .get_request_values(&"https://example.com/".parse().unwrap())
        {
            raw.add_original(
                cookie::Cookie::parse_encoded(format!("{name}={value}"))
                    .unwrap()
                    .into_owned(),
            );
        }
        crate::handlers::oauth::authorization::consent_cookie::PendingConsents::load(
            &state.cookie_manager.cookie_jar_from_request(&raw),
        )
    }
}

struct Fixture {
    state: TestState,
    client: Client,
    session: BrowserSession,
    other: BrowserSession,
    browser: Browser,
    _database: coauth_storage_postgres::test_utils::TestDatabase,
}

impl Fixture {
    async fn finish(self) {
        let Self {
            state,
            _database: database,
            ..
        } = self;
        state.shutdown().await;
        drop(database);
    }

    async fn new() -> Self {
        setup();
        let pool = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .expect("consent regressions require real PostgreSQL");
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(unique_test_nonce());
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(
                &mut rng,
                &state.clock,
                format!("consent-{}", Ulid::generate().to_string().to_lowercase()),
            )
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        let other_user = repo
            .user()
            .add(
                &mut rng,
                &state.clock,
                format!("other-{}", Ulid::generate().to_string().to_lowercase()),
            )
            .await
            .unwrap();
        let other = repo
            .browser_session()
            .add(&mut rng, &state.clock, &other_user, None)
            .await
            .unwrap();
        let client = repo
            .oauth_client()
            .upsert_static(
                Ulid::generate(),
                None,
                OAuthClientAuthenticationMethod::None,
                None,
                None,
                None,
                vec![
                    "https://client.example/callback?registered=yes"
                        .parse()
                        .unwrap(),
                ],
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        let browser = Browser::session(&state, &session);
        Self {
            state,
            client,
            session,
            other,
            browser,
            _database: pool,
        }
    }

    fn authorization_url(&self, mode: &str) -> url::Url {
        let mut url = self.state.url_builder.absolute_url("/authorize");
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", self.client.client_id.as_str()),
            ("redirect_uri", self.client.redirect_uris[0].as_str()),
            ("scope", "openid"),
            ("state", "opaque&state=<safe>"),
            ("response_mode", mode),
            ("code_challenge_method", "S256"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
        ]);
        url
    }

    async fn authenticate_at(&self, session: &BrowserSession, clock: &dyn coauth_data::Clock) {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(unique_test_nonce());
        let mut repo = self.state.repository().await.unwrap();
        let password = repo
            .user_password()
            .add(
                &mut rng,
                clock,
                &session.user,
                1,
                "fixture-password-hash".to_owned(),
                None,
            )
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_password(&mut rng, clock, session, &password)
            .await
            .unwrap();
        repo.save().await.unwrap();
    }

    fn signed_hint(&self, claims: Value, alg: coauth_iana::jose::JsonWebSignatureAlg) -> String {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(unique_test_nonce());
        let key = self.state.keyring.signing_key_for_algorithm(&alg).unwrap();
        let signer = self.state.keyring.signer_for_algorithm(&alg).unwrap();
        let header =
            coauth_jose::jwt::JsonWebSignatureHeader::new(alg).with_kid(key.kid().unwrap());
        let claims: std::collections::HashMap<String, Value> =
            serde_json::from_value(claims).unwrap();
        coauth_jose::jwt::Jwt::sign_with_rng(&mut rng, header, claims, &*signer)
            .unwrap()
            .into_string()
    }

    fn hint_claims(&self, subject: &str) -> Value {
        use coauth_data::Clock as _;
        let now = coauth_data::SystemClock::default().now().timestamp();
        json!({
            "iss": self.state.url_builder.oidc_issuer().to_string(),
            "aud": self.client.client_id,
            "sub": subject,
            "iat": now - 7200,
            "exp": now - 3600,
        })
    }

    async fn start(&mut self, mode: &str) -> (Ulid, String) {
        let url = self.authorization_url(mode);
        let response = self
            .browser
            .send(&self.state, Request::get(url.as_str()).empty())
            .await;
        assert!(response.status().is_redirection(), "{}", response.body());
        let returned_cookies = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| {
                RawCookie::parse(value.to_str().unwrap())
                    .unwrap()
                    .name()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert!(returned_cookies.iter().any(|name| name == "session"));
        assert!(
            returned_cookies
                .iter()
                .any(|name| name == "oauth-authorization-consents")
        );
        assert!(
            self.browser
                .0
                .get("example.com", "/", "oauth-authorization-consents")
                .is_some(),
            "authorization must set its continuation cookie"
        );
        let location = response.headers()["location"].to_str().unwrap();
        let grant: Ulid = location.rsplit('/').next().unwrap().parse().unwrap();
        let consent = self
            .browser
            .send(
                &self.state,
                Request::get(format!(
                    "/_coauth/self/oauth/authorization-grants/{grant}/decision"
                ))
                .empty(),
            )
            .await;
        consent.assert_status(StatusCode::OK);
        let body: Value = consent.json();
        (grant, body["csrf_token"].as_str().unwrap().to_owned())
    }

    fn decision(grant: Ulid, csrf: &str, action: &str) -> Request<String> {
        Request::post(format!(
            "/_coauth/self/oauth/authorization-grants/{grant}/decision"
        ))
        .header("origin", "https://example.com")
        .json(json!({"action": action, "csrf_token": csrf}))
    }

    async fn stage(&self, grant: Ulid) -> AuthorizationGrantStage {
        let mut repo = self.state.repository().await.unwrap();
        let grant = repo
            .oauth_authorization_grant()
            .lookup(grant)
            .await
            .unwrap()
            .unwrap();
        repo.cancel().await.unwrap();
        grant.stage
    }

    async fn sessions(&self) -> usize {
        let mut repo = self.state.repository().await.unwrap();
        let count = repo
            .oauth_session()
            .count(OAuthSessionFilter::new().for_client(&self.client))
            .await
            .unwrap();
        repo.cancel().await.unwrap();
        count
    }
}

#[tokio::test]
async fn denial_commits_query_and_form_post_without_credentials_and_replays_fail() {
    for mode in ["query", "form_post"] {
        let mut fixture = Fixture::new().await;
        let (grant, csrf) = fixture.start(mode).await;
        let stale = fixture.browser.clone();
        let response = fixture
            .browser
            .send(&fixture.state, Fixture::decision(grant, &csrf, "deny"))
            .await;
        response.assert_status(StatusCode::OK);
        let body: Value = response.json();
        let callback: url::Url = body["redirect_url"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            callback.origin().ascii_serialization(),
            "https://client.example"
        );
        assert_eq!(
            callback
                .query_pairs()
                .find(|(key, _)| key == "registered")
                .unwrap()
                .1,
            "yes"
        );
        let params: Vec<(String, String)> = if mode == "form_post" {
            assert_eq!(callback.as_str(), fixture.client.redirect_uris[0].as_str());
            serde_json::from_value(body["form_parameters"].clone()).unwrap()
        } else {
            callback.query_pairs().into_owned().collect()
        };
        assert!(params.contains(&("error".to_owned(), "access_denied".to_owned())));
        assert!(params.contains(&("state".to_owned(), "opaque&state=<safe>".to_owned())));
        assert!(
            !params
                .iter()
                .any(|(key, _)| matches!(key.as_str(), "code" | "id_token" | "access_token"))
        );
        assert!(matches!(
            fixture.stage(grant).await,
            AuthorizationGrantStage::Cancelled { .. }
        ));
        for action in ["deny", "approve"] {
            let replay = fixture
                .state
                .request(stale.request(Fixture::decision(grant, &csrf, action)))
                .await;
            replay.assert_status(StatusCode::BAD_REQUEST);
            assert!(
                !replay
                    .json::<Value>()
                    .as_object()
                    .unwrap()
                    .contains_key("redirect_url")
            );
        }
        assert_eq!(fixture.sessions().await, 0);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn browser_form_denial_uses_exact_callback_and_rendered_script_csp() {
    use base64ct::{Base64, Encoding as _};
    use sha2::{Digest as _, Sha256};

    let mut escaping = minijinja::Environment::new();
    escaping.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
    let escaped_redirect = escaping
        .render_str(
            "{{ value }}",
            minijinja::context! { value => "https://client.example/callback?registered=yes" },
        )
        .unwrap();

    let mut fixture = Fixture::new().await;
    let (grant, csrf) = fixture.start("form_post").await;
    let response = fixture
        .browser
        .send(
            &fixture.state,
            Request::post(format!(
                "/_coauth/self/oauth/authorization-grants/{grant}/decision"
            ))
            .header("origin", "https://example.com")
            .form(json!({"action":"deny", "csrf_token":csrf})),
        )
        .await;
    response.assert_status(StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert!(policy.contains("form-action https://client.example;"));
    assert!(!policy.contains("'unsafe-inline'"));
    assert!(policy.contains("default-src 'none'"));
    let script = response
        .body()
        .split_once("<script>")
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    let normalized = script.replace("\r\n", "\n").replace('\r', "\n");
    let hash = Base64::encode_string(&Sha256::digest(normalized.as_bytes()));
    assert!(policy.contains(&format!("script-src 'sha256-{hash}';")));
    assert!(
        response
            .body()
            .contains(&format!("action=\"{escaped_redirect}\""))
    );
    assert!(
        response
            .body()
            .contains("value=\"opaque&amp;state=&lt;safe&gt;\"")
    );
    assert!(response.body().contains("value=\"access_denied\""));
    assert!(matches!(
        fixture.stage(grant).await,
        AuthorizationGrantStage::Cancelled { .. }
    ));
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn browser_form_with_expired_session_returns_to_login_without_consumption() {
    let mut fixture = Fixture::new().await;
    let (grant, csrf) = fixture.start("form_post").await;
    let mut repo = fixture.state.repository().await.unwrap();
    repo.browser_session()
        .finish(&fixture.state.clock, fixture.session.clone())
        .await
        .unwrap();
    repo.save().await.unwrap();
    let response = fixture
        .browser
        .send(
            &fixture.state,
            Request::post(format!(
                "/_coauth/self/oauth/authorization-grants/{grant}/decision"
            ))
            .header("origin", "https://example.com")
            .form(json!({"action":"deny", "csrf_token":csrf})),
        )
        .await;
    assert!(response.status().is_redirection());
    let destination: url::Url = fixture
        .state
        .url_builder
        .absolute_url("/")
        .join(response.headers()["location"].to_str().unwrap())
        .unwrap();
    assert_eq!(
        destination.origin().ascii_serialization(),
        "https://example.com"
    );
    assert_eq!(destination.path(), "/login");
    assert!(
        destination
            .query_pairs()
            .any(|(key, value)| key == "id" && value == grant.to_string())
    );
    assert_eq!(fixture.stage(grant).await, AuthorizationGrantStage::Pending);
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn wrong_user_nonce_origin_and_redirect_override_do_not_consume_grant() {
    let mut fixture = Fixture::new().await;
    let (grant, csrf) = fixture.start("query").await;
    let mut other = fixture.browser.clone();
    other.import(fixture.state.cookie_jar().set_session(&fixture.other));
    let response = fixture
        .state
        .request(other.request(Fixture::decision(grant, &csrf, "deny")))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    let mut wrong_origin = Fixture::decision(grant, &csrf, "deny");
    wrong_origin
        .headers_mut()
        .insert("origin", "https://attacker.example".parse().unwrap());
    for request in [
        Fixture::decision(grant, "invalid-csrf", "deny"),
        wrong_origin,
    ] {
        fixture
            .state
            .request(fixture.browser.request(request))
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }
    let injected = Request::post(format!(
        "/_coauth/self/oauth/authorization-grants/{grant}/decision"
    ))
    .header("origin", "https://example.com")
    .json(json!({"action":"deny","csrf_token":csrf,"redirect_uri":"https://attacker.example"}));
    fixture
        .state
        .request(fixture.browser.request(injected))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let injected_form = Request::post(format!(
        "/_coauth/self/oauth/authorization-grants/{grant}/decision"
    ))
    .header("origin", "https://example.com")
    .form(json!({"action":"deny","csrf_token":csrf,"redirect_uri":"https://attacker.example"}));
    fixture
        .state
        .request(fixture.browser.request(injected_form))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(fixture.stage(grant).await, AuthorizationGrantStage::Pending);
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn withdrawn_redirect_registration_never_consumes_or_redirects_the_request() {
    let mut fixture = Fixture::new().await;
    let (grant, csrf) = fixture.start("query").await;
    let mut repo = fixture.state.repository().await.unwrap();
    let updated = repo
        .oauth_client()
        .upsert_static(
            fixture.client.client_id.parse().unwrap(),
            None,
            OAuthClientAuthenticationMethod::None,
            None,
            None,
            None,
            vec!["https://replacement.example/callback".parse().unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(updated.id, fixture.client.id);
    repo.save().await.unwrap();
    let response = fixture
        .browser
        .send(&fixture.state, Fixture::decision(grant, &csrf, "deny"))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(
        !response
            .json::<Value>()
            .as_object()
            .unwrap()
            .contains_key("redirect_url")
    );
    assert_eq!(fixture.stage(grant).await, AuthorizationGrantStage::Pending);
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn independent_pending_requests_can_approve_and_deny_concurrently() {
    let mut fixture = Fixture::new().await;
    let (a, csrf_a) = fixture.start("query").await;
    let (b, csrf_b) = fixture.start("query").await;
    assert_ne!(csrf_a, csrf_b);
    let (approved, denied) = tokio::join!(
        fixture.state.request(
            fixture
                .browser
                .request(Fixture::decision(a, &csrf_a, "approve"))
        ),
        fixture.state.request(
            fixture
                .browser
                .request(Fixture::decision(b, &csrf_b, "deny"))
        ),
    );
    approved.assert_status(StatusCode::OK);
    denied.assert_status(StatusCode::OK);
    assert!(matches!(
        fixture.stage(a).await,
        AuthorizationGrantStage::Fulfilled { .. }
    ));
    assert!(matches!(
        fixture.stage(b).await,
        AuthorizationGrantStage::Cancelled { .. }
    ));
    assert_eq!(fixture.sessions().await, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn competing_decisions_consume_one_pending_grant_once() {
    let mut fixture = Fixture::new().await;
    let (grant, csrf) = fixture.start("query").await;
    let (approved, denied) = tokio::join!(
        fixture.state.request(
            fixture
                .browser
                .request(Fixture::decision(grant, &csrf, "approve"))
        ),
        fixture.state.request(
            fixture
                .browser
                .request(Fixture::decision(grant, &csrf, "deny"))
        ),
    );
    assert_eq!(
        [approved.status(), denied.status()]
            .iter()
            .filter(|&&status| status == StatusCode::OK)
            .count(),
        1
    );
    match fixture.stage(grant).await {
        AuthorizationGrantStage::Fulfilled { .. } => assert_eq!(fixture.sessions().await, 1),
        AuthorizationGrantStage::Cancelled { .. } => assert_eq!(fixture.sessions().await, 0),
        stage => panic!("unexpected terminal consent: {stage:?}"),
    }
    fixture.finish().await;
}

#[tokio::test]
async fn expired_browser_continuation_cannot_consume_a_pending_grant() {
    use crate::handlers::oauth::authorization::consent_cookie::PendingConsents;
    let fixture = Fixture::new().await;
    let clock = coauth_data::clock::MockClock::new(chrono::Utc::now() - chrono::Duration::hours(2));
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(unique_test_nonce());
    let mut repo = fixture.state.repository().await.unwrap();
    let grant = repo
        .oauth_authorization_grant()
        .add(
            &mut rng,
            &clock,
            &fixture.client,
            fixture.client.redirect_uris[0].clone(),
            "openid".parse().unwrap(),
            Some(coauth_data::AuthorizationCode {
                code: Ulid::generate().to_string(),
                pkce: None,
            }),
            Some("expired-state".to_owned()),
            None,
            coauth_oauth_types::requests::ResponseMode::Query,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    repo.save().await.unwrap();
    let mut pending = PendingConsents::default();
    pending.add(grant.id, Some(&fixture.session), &mut rng);
    let csrf = pending.bind(grant.id, &fixture.session).unwrap();
    let mut browser = Browser::default();
    browser.import(pending.write(
        fixture.state.cookie_jar().set_session(&fixture.session),
        &clock,
    ));
    let response = browser
        .send(&fixture.state, Fixture::decision(grant.id, &csrf, "deny"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        fixture.stage(grant.id).await,
        AuthorizationGrantStage::Pending
    );
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

fn authorization_error(response: &Response<String>) -> String {
    let location: url::Url = response.headers()["location"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let params = location
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(params["state"], "opaque&state=<safe>");
    assert!(!params.contains_key("code"));
    params["error"].to_string()
}

#[tokio::test]
async fn silent_authorization_reuses_only_current_client_scope_and_active_consent() {
    let mut fixture = Fixture::new().await;
    let clock = coauth_data::SystemClock::default();
    fixture.authenticate_at(&fixture.session, &clock).await;
    let mut silent = fixture.authorization_url("query");
    silent.query_pairs_mut().append_pair("prompt", "none");
    let no_consent = fixture
        .browser
        .send(&fixture.state, Request::get(silent.as_str()).empty())
        .await;
    assert_eq!(authorization_error(&no_consent), "consent_required");
    assert_eq!(fixture.sessions().await, 0);
    let (grant, csrf) = fixture.start("query").await;
    fixture
        .browser
        .send(&fixture.state, Fixture::decision(grant, &csrf, "approve"))
        .await
        .assert_status(StatusCode::OK);
    let accepted = fixture
        .browser
        .send(&fixture.state, Request::get(silent.as_str()).empty())
        .await;
    let redirect: url::Url = accepted.headers()["location"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let parameters = redirect
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert!(parameters.contains_key("code"));
    assert_eq!(parameters["state"], "opaque&state=<safe>");
    assert!(!parameters.contains_key("error"));
    // Replace rather than duplicate the original scope field.
    let mut wider = silent.clone();
    wider
        .query_pairs_mut()
        .clear()
        .extend_pairs(silent.query_pairs().filter(|(key, _)| key != "scope"))
        .append_pair("scope", "openid profile");
    let refused = fixture
        .browser
        .send(&fixture.state, Request::get(wider.as_str()).empty())
        .await;
    assert_eq!(authorization_error(&refused), "consent_required");
    fixture.authenticate_at(&fixture.other, &clock).await;
    let mut other_browser = Browser::session(&fixture.state, &fixture.other);
    let other = other_browser
        .send(&fixture.state, Request::get(silent.as_str()).empty())
        .await;
    assert_eq!(authorization_error(&other), "consent_required");
    let mut repo = fixture.state.repository().await.unwrap();
    let other_client = repo
        .oauth_client()
        .upsert_static(
            Ulid::generate(),
            None,
            OAuthClientAuthenticationMethod::None,
            None,
            None,
            None,
            fixture.client.redirect_uris.clone(),
        )
        .await
        .unwrap();
    repo.save().await.unwrap();
    let mut foreign = silent.clone();
    foreign
        .query_pairs_mut()
        .clear()
        .extend_pairs(silent.query_pairs().filter(|(key, _)| key != "client_id"))
        .append_pair("client_id", &other_client.client_id);
    let no_other_client_consent = fixture
        .browser
        .send(&fixture.state, Request::get(foreign.as_str()).empty())
        .await;
    assert_eq!(
        authorization_error(&no_other_client_consent),
        "consent_required"
    );
    let AuthorizationGrantStage::Fulfilled { session_id, .. } = fixture.stage(grant).await else {
        panic!("approved authorization must be fulfilled");
    };
    let mut repo = fixture.state.repository().await.unwrap();
    let prior = repo
        .oauth_session()
        .lookup(session_id)
        .await
        .unwrap()
        .unwrap();
    repo.oauth_session().finish(&clock, prior).await.unwrap();
    // Revoke the silent continuation as well: no active consent remains.
    let filter = OAuthSessionFilter::new()
        .for_client(&fixture.client)
        .active_only();
    repo.oauth_session()
        .finish_bulk(&clock, filter)
        .await
        .unwrap();
    repo.save().await.unwrap();
    let revoked = fixture
        .browser
        .send(&fixture.state, Request::get(silent.as_str()).empty())
        .await;
    assert_eq!(authorization_error(&revoked), "consent_required");
    fixture.finish().await;
}

#[tokio::test]
async fn silent_requests_without_authentication_or_with_conflicting_prompts_never_issue_codes() {
    let mut fixture = Fixture::new().await;
    for (prompt, expected) in [
        ("none", "login_required"),
        ("none login", "invalid_request"),
        ("none consent", "invalid_request"),
    ] {
        let mut url = fixture.authorization_url("query");
        url.query_pairs_mut().append_pair("prompt", prompt);
        let response = fixture
            .browser
            .send(&fixture.state, Request::get(url.as_str()).empty())
            .await;
        assert_eq!(authorization_error(&response), expected);
    }
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn requested_reauthentication_cannot_be_bypassed_at_the_approval_api() {
    let mut fixture = Fixture::new().await;
    let old = coauth_data::clock::MockClock::default();
    fixture.authenticate_at(&fixture.session, &old).await;
    let mut grants = Vec::new();
    for (parameter, value) in [("max_age", "1"), ("max_age", "0"), ("prompt", "login")] {
        let mut url = fixture.authorization_url("query");
        url.query_pairs_mut().append_pair(parameter, value);
        let response = fixture
            .browser
            .send(&fixture.state, Request::get(url.as_str()).empty())
            .await;
        let location: url::Url = response.headers()["location"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(location.path(), "/login");
        let grant: Ulid = location
            .query_pairs()
            .find(|(key, _)| key == "id")
            .unwrap()
            .1
            .parse()
            .unwrap();
        let get = format!("/_coauth/self/oauth/authorization-grants/{grant}/decision");
        fixture
            .browser
            .send(&fixture.state, Request::get(get.as_str()).empty())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        // Possession of the encrypted cookie and a valid nonce is still not
        // fresh authentication, including a direct same-origin POST.
        let csrf = fixture
            .browser
            .pending(&fixture.state)
            .bind(grant, &fixture.session)
            .unwrap();
        fixture
            .browser
            .send(&fixture.state, Fixture::decision(grant, &csrf, "approve"))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        let denied = fixture
            .browser
            .send(
                &fixture.state,
                Request::post(get.as_str())
                    .header("origin", "https://example.com")
                    .form(json!({"action":"deny", "csrf_token":csrf})),
            )
            .await;
        assert!(denied.status().is_redirection());
        assert!(
            denied.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("https://example.com/login?")
        );
        assert_eq!(fixture.stage(grant).await, AuthorizationGrantStage::Pending);
        grants.push((grant, csrf));
    }
    assert_eq!(fixture.sessions().await, 0);
    fixture
        .authenticate_at(&fixture.session, &coauth_data::SystemClock::default())
        .await;
    for (grant, csrf) in grants {
        fixture
            .browser
            .send(
                &fixture.state,
                Request::get(format!(
                    "/_coauth/self/oauth/authorization-grants/{grant}/decision",
                ))
                .empty(),
            )
            .await
            .assert_status(StatusCode::OK);
        fixture
            .browser
            .send(&fixture.state, Fixture::decision(grant, &csrf, "approve"))
            .await
            .assert_status(StatusCode::OK);
        assert!(fixture.stage(grant).await.is_fulfilled());
    }
    fixture.finish().await;
}

#[tokio::test]
async fn invalid_id_token_hints_are_rejected_without_issuing_credentials() {
    use coauth_data::Clock as _;
    use coauth_iana::jose::JsonWebSignatureAlg;
    let mut fixture = Fixture::new().await;
    let subject = crate::handlers::arkret::oidc_subject_for_user(
        &fixture.state.arkret_config,
        &fixture.session.user,
    );
    let baseline = fixture.hint_claims(&subject);
    let mut hints = Vec::new();
    for (field, value) in [
        ("iss", json!("https://other-issuer.example")),
        ("aud", json!("different-client")),
        (
            "iat",
            json!(coauth_data::SystemClock::default().now().timestamp() + 60),
        ),
        ("sub", Value::Null),
        ("exp", Value::Null),
    ] {
        let mut claims = baseline.clone();
        claims[field] = value;
        hints.push(fixture.signed_hint(claims, JsonWebSignatureAlg::Rs256));
    }
    hints.push(fixture.signed_hint(baseline.clone(), JsonWebSignatureAlg::Ed25519));
    let valid = fixture.signed_hint(baseline, JsonWebSignatureAlg::Rs256);
    let (prefix, signature) = valid.rsplit_once('.').unwrap();
    let changed = if signature.starts_with('A') { "B" } else { "A" };
    hints.push(format!("{prefix}.{changed}{}", &signature[1..]));
    hints.push("not-a-jwt".to_owned());
    for hint in hints {
        let mut url = fixture.authorization_url("query");
        url.query_pairs_mut().append_pair("id_token_hint", &hint);
        let response = fixture
            .browser
            .send(&fixture.state, Request::get(url.as_str()).empty())
            .await;
        assert_eq!(authorization_error(&response), "invalid_request");
    }
    assert_eq!(fixture.sessions().await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn expired_signed_hint_binds_the_eventual_subject_without_logging_a_browser_in() {
    use coauth_iana::jose::JsonWebSignatureAlg;
    let mut fixture = Fixture::new().await;
    let subject = crate::handlers::arkret::oidc_subject_for_user(
        &fixture.state.arkret_config,
        &fixture.session.user,
    );
    let hint = fixture.signed_hint(fixture.hint_claims(&subject), JsonWebSignatureAlg::Rs256);
    let mut url = fixture.authorization_url("query");
    url.query_pairs_mut().append_pair("id_token_hint", &hint);
    let mut wrong_user = Browser::session(&fixture.state, &fixture.other);
    let mismatch = wrong_user
        .send(&fixture.state, Request::get(url.as_str()).empty())
        .await;
    assert_eq!(authorization_error(&mismatch), "login_required");
    let mut anonymous = Browser::default();
    let response = anonymous
        .send(&fixture.state, Request::get(url.as_str()).empty())
        .await;
    let location: url::Url = response.headers()["location"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(location.path(), "/login");
    let grant: Ulid = location
        .query_pairs()
        .find(|(key, _)| key == "id")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let approval = format!("/_coauth/self/oauth/authorization-grants/{grant}/decision");
    anonymous
        .send(&fixture.state, Request::get(approval.as_str()).empty())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    anonymous.import(fixture.state.cookie_jar().set_session(&fixture.other));
    anonymous
        .send(&fixture.state, Request::get(approval.as_str()).empty())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    let csrf = anonymous
        .pending(&fixture.state)
        .bind(grant, &fixture.other)
        .unwrap();
    anonymous
        .send(&fixture.state, Fixture::decision(grant, &csrf, "approve"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(fixture.stage(grant).await, AuthorizationGrantStage::Pending);
    assert_eq!(fixture.sessions().await, 0);
    anonymous.import(fixture.state.cookie_jar().set_session(&fixture.session));
    let response = anonymous
        .send(&fixture.state, Request::get(approval.as_str()).empty())
        .await;
    response.assert_status(StatusCode::OK);
    let csrf = response.json::<Value>()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    anonymous
        .send(&fixture.state, Fixture::decision(grant, &csrf, "approve"))
        .await
        .assert_status(StatusCode::OK);
    assert!(fixture.stage(grant).await.is_fulfilled());
    fixture.finish().await;
}

#[tokio::test]
async fn recent_real_authentication_satisfies_nonzero_max_age_without_a_new_login() {
    let mut fixture = Fixture::new().await;
    fixture
        .authenticate_at(&fixture.session, &coauth_data::SystemClock::default())
        .await;
    let mut url = fixture.authorization_url("query");
    url.query_pairs_mut().append_pair("max_age", "10000");
    let response = fixture
        .browser
        .send(&fixture.state, Request::get(url.as_str()).empty())
        .await;
    let location: url::Url = response.headers()["location"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(location.path().starts_with("/oauth/approval/"));
    let grant: Ulid = location.path().rsplit('/').next().unwrap().parse().unwrap();
    fixture
        .browser
        .send(
            &fixture.state,
            Request::get(format!(
                "/_coauth/self/oauth/authorization-grants/{grant}/decision",
            ))
            .empty(),
        )
        .await
        .assert_status(StatusCode::OK);
    fixture.finish().await;
}
