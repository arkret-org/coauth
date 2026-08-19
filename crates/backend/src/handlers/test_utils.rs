// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Duration;
use coauth_config::{ArkretConfig, RateLimitingConfig};
use coauth_data::clock::MockClock;
use coauth_data::personal::session::PersonalSessionOwner;
use coauth_data::personal::{PersonalAccessTokenRepository, PersonalSessionRepository};
use coauth_data::user::UserRepository;
use coauth_data::{
    AppVersion, BoxRepository, RepositoryAccess, RepositoryError, RepositoryFactory, SiteConfig,
    SystemClock, TokenType, UrlBuilder,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_keystore::{Encrypter, JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use coauth_messaging::NotificationCenter;
use coauth_messaging::email::{Mailer, Transport as MailTransport};
use coauth_oauth_types::scope::Scope;
use coauth_policy::PolicyFactory;
use coauth_principal::ConnectorAdmin;
use coauth_storage_postgres::PgRepositoryFactory;
use coauth_tasks::QueueWorker;
use coauth_templates::{SiteConfigExt, Templates};
use cookie_store::{CookieStore, RawCookie};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use headers::{Authorization, ContentType, HeaderMapExt, HeaderValue};
use hyper::header::{CONTENT_TYPE, COOKIE};
use hyper::{Request, Response, StatusCode};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::prelude::*;
use salvo::test::{ResponseExt as SalvoResponseExt, TestClient};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;
use ulid::Ulid;
use url::Url;

use crate::handlers::passwords::{Hasher, PasswordManager};
use crate::handlers::upstream_oauth::cache::MetadataCache;
use crate::handlers::upstream_oauth::jwks_cache::JwksCache;
use crate::handlers::{ActivityTracker, Limiter};
use crate::salvo_utils::cookies::{CookieJar, CookieManager};
use crate::services::account_claims::account_claims_service;
use crate::services::did_resolver::default_did_resolver_service;
use crate::services::invite_quarantine::invite_quarantine_service;
use crate::services::principal_facade::DbConnectorAdmin;
use crate::services::risk_action_proposals::risk_action_proposals_service;
use crate::services::risk_action_state::default_risk_action_state_service;
use crate::services::upstream_oidc::default_upstream_oidc_service;

static UNIQUE_TEST_NONCE: AtomicU64 = AtomicU64::new(0);

/// Setup rustcrypto and tracing for tests.
#[allow(unused_must_use)]
pub(crate) fn setup() {
    rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
}

pub(crate) fn unique_test_nonce() -> u64 {
    let epoch_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_millis() as u64;
    let counter = UNIQUE_TEST_NONCE.fetch_add(1, Ordering::Relaxed) % 1_000_000;
    let time_component = epoch_millis % 1_000_000;
    let pid_component = (u64::from(process::id()) % 1_000) * 1_000_000;

    pid_component + time_component + counter
}

#[cfg(feature = "cedar")]
pub(crate) async fn policy_factory(
    _server_name: &str,
    _data: serde_json::Value,
) -> Result<Arc<PolicyFactory>, anyhow::Error> {
    let workspace_root = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let cedar_path = workspace_root
        .join("policies")
        .join("cedar")
        .join("default.cedar");

    let policy_factory = PolicyFactory::load_cedar_from_file(cedar_path.as_str()).await?;
    let policy_factory = Arc::new(policy_factory);
    Ok(policy_factory)
}

#[cfg(not(feature = "cedar"))]
pub(crate) async fn policy_factory(
    _server_name: &str,
    _data: serde_json::Value,
) -> Result<Arc<PolicyFactory>, anyhow::Error> {
    anyhow::bail!("tests require the `cedar` feature to be enabled")
}

#[derive(Clone)]
pub(crate) struct TestState {
    pub repository_factory: PgRepositoryFactory,
    pub templates: Templates,
    pub arkret_config: ArkretConfig,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub metadata_cache: MetadataCache,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub principal_server_admin: Arc<DbConnectorAdmin>,
    pub policy_factory: Arc<PolicyFactory>,
    pub password_manager: PasswordManager,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub limiter: Limiter,
    pub clock: Arc<MockClock>,
    pub rng: Arc<Mutex<ChaChaRng>>,
    pub http_client: reqwest::Client,
    // Keep-alive handles: never read, held so the spawned worker/tasks they
    // own outlive the `TestState` that started them.
    #[allow(dead_code)]
    pub task_tracker: TaskTracker,
    #[allow(dead_code)]
    queue_worker: Arc<tokio::sync::Mutex<QueueWorker>>,

    #[allow(dead_code)] // It is used, as it will cancel the CancellationToken when dropped
    cancellation_drop_guard: Arc<DropGuard>,
}

fn workspace_root() -> camino::Utf8PathBuf {
    camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize_utf8()
        .unwrap()
}

pub fn test_site_config() -> SiteConfig {
    SiteConfig {
        access_token_ttl: Duration::try_minutes(5).unwrap(),
        server_name: "example.com".to_owned(),
        policy_uri: Some("https://example.com/policy".parse().unwrap()),
        tos_uri: Some("https://example.com/tos".parse().unwrap()),
        imprint: None,
        password_login_enabled: true,
        password_registration_enabled: true,
        registration_token_required: false,
        bootstrap_admin_token: None,
        email_change_allowed: true,
        displayname_change_allowed: true,
        password_change_allowed: true,
        password_registration_contact_required: true,
        registration_email_delivery_bypass_allowed: true,
        account_recovery_allowed: true,
        account_deactivation_allowed: true,
        captcha: None,
        minimum_password_complexity: 1,
        session_expiration: None,
        login_with_email_allowed: true,
        admin_portal_url: None,
        plan_management_iframe_uri: None,
        session_limit: None,
        phone_verification_enabled: true,
    }
}

/// Assert that `value` is an RFC 3339 instant stamped no earlier than `since`.
///
/// Handlers stamp lifecycle instants from the process wall clock, so a test can
/// only bracket them: sample the clock before the request and require the
/// response instant to be at or after that sample.
///
/// # Panics
///
/// Panics when `value` is not an RFC 3339 string or predates `since`.
pub(crate) fn assert_stamped_since(
    value: &serde_json::Value,
    since: chrono::DateTime<chrono::Utc>,
    field: &str,
) {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{field} must carry an instant, got {value}"));
    let stamped = chrono::DateTime::parse_from_rfc3339(text)
        .unwrap_or_else(|error| panic!("{field} must be RFC 3339: {error}"))
        .with_timezone(&chrono::Utc);
    assert!(
        stamped >= since,
        "{field} must be stamped at request time, got {stamped} before {since}"
    );
}

/// Return a copy of `value` with every server-minted identifier and timestamp
/// replaced by a stable placeholder.
///
/// Handlers mint ULIDs from the process RNG and read `created_at` from the
/// wall clock, so those bytes are not reproducible and are not part of any
/// response contract. Mapping each distinct value to `[id-N]` / `[timestamp-N]`
/// in first-seen order keeps a snapshot asserting the document shape *and*
/// which fields share a value, without pinning bytes the server is free to
/// choose. Identifiers embedded in `links` are rewritten too, so a self link
/// still has to agree with the resource id.
pub(crate) fn stable_json(value: &serde_json::Value) -> serde_json::Value {
    let mut placeholders = std::collections::HashMap::new();
    stabilize_value(value, &mut placeholders)
}

fn stabilize_value(
    value: &serde_json::Value,
    placeholders: &mut std::collections::HashMap<String, String>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => {
            serde_json::Value::String(stabilize_text(text, placeholders))
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|item| stabilize_value(item, placeholders))
                .collect(),
        ),
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(key, field)| (key.clone(), stabilize_value(field, placeholders)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn placeholder_for(
    original: &str,
    prefix: &str,
    placeholders: &mut std::collections::HashMap<String, String>,
) -> String {
    if let Some(existing) = placeholders.get(original) {
        return existing.clone();
    }
    let next = placeholders
        .values()
        .filter(|value| value.starts_with(&format!("[{prefix}-")))
        .count()
        + 1;
    let placeholder = format!("[{prefix}-{next}]");
    placeholders.insert(original.to_owned(), placeholder.clone());
    placeholder
}

fn stabilize_text(
    text: &str,
    placeholders: &mut std::collections::HashMap<String, String>,
) -> String {
    if chrono::DateTime::parse_from_rfc3339(text).is_ok() {
        return placeholder_for(text, "timestamp", placeholders);
    }

    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if !is_crockford_char(chars[index]) {
            out.push(chars[index]);
            index += 1;
            continue;
        }
        let mut end = index;
        while end < chars.len() && chars[end].is_ascii_alphanumeric() {
            end += 1;
        }
        let run: String = chars[index..end].iter().collect();
        if run.len() == 26 && run.chars().all(is_crockford_char) {
            out.push_str(&placeholder_for(&run, "id", placeholders));
        } else {
            out.push_str(&run);
        }
        index = end;
    }
    out
}

/// Crockford base32 alphabet used by ULID string form (`I`, `L`, `O` and `U`
/// are excluded).
fn is_crockford_char(value: char) -> bool {
    value.is_ascii_digit()
        || (value.is_ascii_uppercase() && !matches!(value, 'I' | 'L' | 'O' | 'U'))
}

/// Salvo handler that injects `TestState` components into the Depot.
#[derive(Clone)]
struct InjectTestState(TestState);

#[salvo::async_trait]
impl Handler for InjectTestState {
    async fn handle(
        &self,
        req: &mut salvo::Request,
        depot: &mut Depot,
        res: &mut salvo::Response,
        ctrl: &mut FlowCtrl,
    ) {
        let state = &self.0;
        depot.insert("pg_pool", state.repository_factory.pool().clone());
        depot.insert(
            "box_repository_factory",
            state.repository_factory.clone().boxed(),
        );
        depot.insert("templates", state.templates.clone());
        depot.insert("translator", state.templates.translator());
        depot.insert("arkret_config", state.arkret_config.clone());
        depot.insert("keystore", state.key_store.clone());
        depot.insert("encrypter", state.encrypter.clone());
        depot.insert("url_builder", state.url_builder.clone());
        depot.insert("http_client", state.http_client.clone());
        depot.insert("password_manager", state.password_manager.clone());
        depot.insert("cookie_manager", state.cookie_manager.clone());
        depot.insert("metadata_cache", state.metadata_cache.clone());
        depot.insert("jwks_cache", JwksCache::new());
        depot.insert("site_config", state.site_config.clone());
        depot.insert("limiter", state.limiter.clone());
        depot.insert("policy_factory", state.policy_factory.clone());
        depot.insert(
            "principal_server_admin",
            Arc::clone(&state.principal_server_admin) as Arc<dyn ConnectorAdmin>,
        );
        depot.insert("app_version", AppVersion("v0.0.0-test"));
        depot.insert("activity_tracker", state.activity_tracker.clone());
        depot.insert("trusted_proxies", Vec::<ipnetwork::IpNetwork>::new());
        depot.insert(
            "risk_action_state_service",
            default_risk_action_state_service(),
        );
        depot.insert(
            "risk_action_proposals_service",
            risk_action_proposals_service(state.repository_factory.pool().clone()),
        );
        depot.insert(
            "account_claims_service",
            account_claims_service(state.repository_factory.pool().clone()),
        );
        depot.insert(
            "invite_quarantine_service",
            invite_quarantine_service(state.repository_factory.pool().clone()),
        );
        depot.insert("upstream_oidc_service", default_upstream_oidc_service());
        depot.insert(
            "did_resolver_service",
            default_did_resolver_service(&state.arkret_config),
        );
        depot.insert("frontend_script_src", String::new());
        depot.insert("development_mode", false);
        depot.insert(
            "dpop_verifier",
            crate::services::dpop::DpopVerifier::with_store(Arc::new(
                crate::services::dpop::RepositoryJtiStore::new(state.repository_factory.clone()),
            )),
        );
        depot.insert(
            crate::services::did_binding::DEPOT_KEY,
            crate::services::did_binding::shared_verified_did_binding_store(),
        );
        ctrl.call_next(req, depot, res).await;
    }
}

/// Principal Server core DID used by [`TestState::from_pool_with_principal_server`].
///
/// Account-status publication and principal-DID resolution both require a
/// single configured Principal Server whose audience is a `did_core_id`, so
/// the tests that exercise those paths must configure one.
pub(crate) const TEST_PRINCIPAL_SERVER_AUDIENCE: &str = "ak:did_core:webvh:zTestPrincipalServer";

fn test_arkret_config(
    principal_servers: Vec<coauth_config::PrincipalServerConfig>,
) -> ArkretConfig {
    // Seed the runtime identity fixture so DID-shaped assertions stay
    // stable without introducing a configuration-level service DID.
    ArkretConfig {
        runtime_service_identity: coauth_config::RuntimeServiceIdentity::fixture(
            "did:web:example.com",
        ),
        principal_servers,
        ..ArkretConfig::default()
    }
}

impl TestState {
    /// Create a new test state from the given database pool
    pub async fn from_pool(pool: DieselPool<AsyncPgConnection>) -> Result<Self, anyhow::Error> {
        Self::from_pool_with_site_config(pool, test_site_config()).await
    }

    /// Create a new test state whose Arkret config carries exactly one
    /// Principal Server, the destination required by account-status
    /// publication and principal-DID resolution.
    pub async fn from_pool_with_principal_server(
        pool: DieselPool<AsyncPgConnection>,
    ) -> Result<Self, anyhow::Error> {
        Self::build(
            pool,
            test_site_config(),
            test_arkret_config(vec![coauth_config::PrincipalServerConfig {
                name: "principal-test".to_owned(),
                endpoint: "https://principal.example/".parse()?,
                service_id: Some(arkret_identifiers::DidCoreId::new(
                    TEST_PRINCIPAL_SERVER_AUDIENCE,
                )?),
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }]),
        )
        .await
    }

    /// Create a new test state from the given database pool and site config
    pub async fn from_pool_with_site_config(
        pool: DieselPool<AsyncPgConnection>,
        site_config: SiteConfig,
    ) -> Result<Self, anyhow::Error> {
        Self::build(pool, site_config, test_arkret_config(Vec::new())).await
    }

    async fn build(
        pool: DieselPool<AsyncPgConnection>,
        site_config: SiteConfig,
        arkret_config: ArkretConfig,
    ) -> Result<Self, anyhow::Error> {
        let workspace_root = workspace_root();

        let task_tracker = TaskTracker::new();
        let shutdown_token = CancellationToken::new();

        let url_builder = UrlBuilder::new("https://example.com/".parse()?, None, None);

        let templates = Templates::load(
            workspace_root.join("templates"),
            url_builder.clone(),
            workspace_root.join("translations"),
            site_config.templates_branding(),
            site_config.templates_features(),
            // Strict mode in testing
            true,
        )
        .await?;

        let http_client = crate::outbound_http::reqwest_client_for_tests();

        let rsa = PrivateKey::load_pem(include_str!("../../../keystore/tests/keys/rsa.pkcs1.pem"))
            .unwrap();
        let rsa = JsonWebKey::new(rsa).with_kid("test-rsa");
        let ed25519 = JsonWebKey::new(PrivateKey::generate_ed25519(ChaChaRng::seed_from_u64(43)))
            .with_kid("test-ed25519")
            .with_alg(JsonWebSignatureAlg::Ed25519);
        // Server-to-server payloads (account-status records, peer requests) are
        // signed with the explicitly designated service-identity key, so a
        // deployment without one cannot publish at all.
        // Deliberately carries no `alg`: the service identity is selected by
        // its `kid`, and advertising a second Ed25519 signing key would make
        // the algorithm-only selector ambiguous.
        let service_identity =
            JsonWebKey::new(PrivateKey::generate_ed25519(ChaChaRng::seed_from_u64(44)))
                .with_kid(coauth_keystore::SERVICE_IDENTITY_KEY_ID);
        let jwks = JsonWebKeySet::new(vec![rsa, ed25519, service_identity]);
        let key_store = Keystore::new(jwks);

        let encrypter = Encrypter::new(&[0x42; 32]);
        let cookie_manager = CookieManager::derive_from(url_builder.http_base(), &[0x42; 32]);

        let metadata_cache = MetadataCache::new();

        let password_manager = if site_config.password_login_enabled {
            PasswordManager::new(
                site_config.minimum_password_complexity,
                [(1, Hasher::argon2id(None, false))],
            )?
        } else {
            PasswordManager::disabled()
        };

        let policy_factory =
            policy_factory(&site_config.server_name, serde_json::json!({})).await?;

        let principal_server_admin = Arc::new(DbConnectorAdmin::new(
            site_config.server_name.clone(),
            PgRepositoryFactory::new(pool.clone()).boxed(),
            arkret_config.clone(),
            crate::reqwest_client(),
        ));

        let clock = Arc::new(MockClock::default());
        let rng = Arc::new(Mutex::new(ChaChaRng::seed_from_u64(42)));

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        let activity_tracker = ActivityTracker::new(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            std::time::Duration::from_mins(1),
            &task_tracker,
            shutdown_token.child_token(),
        );

        let mailer = Mailer::new(
            templates.clone(),
            MailTransport::blackhole(),
            "hello@example.com".parse().unwrap(),
            "hello@example.com".parse().unwrap(),
        );
        let notifications = NotificationCenter::email_only(mailer);
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for handler tests");

        let queue_worker = coauth_tasks::init(
            PgRepositoryFactory::new(pool.clone()),
            database_url,
            Arc::clone(&clock),
            &notifications,
            principal_server_admin.clone(),
            url_builder.clone(),
            &site_config,
            shutdown_token.child_token(),
        )
        .await
        .unwrap();

        let queue_worker = Arc::new(tokio::sync::Mutex::new(queue_worker));

        Ok(Self {
            repository_factory: PgRepositoryFactory::new(pool),
            templates,
            arkret_config,
            key_store,
            cookie_manager,
            metadata_cache,
            encrypter,
            url_builder,
            principal_server_admin,
            policy_factory,
            password_manager,
            site_config,
            activity_tracker,
            limiter,
            clock,
            rng,
            http_client,
            task_tracker,
            queue_worker,
            cancellation_drop_guard: Arc::new(shutdown_token.drop_guard()),
        })
    }

    /// Build a Salvo router for the in-process test client.
    ///
    /// The route table is **not** duplicated here: it is mounted from the same
    /// `server::routers` builders production uses, so a route added or moved in
    /// production can never silently 404/405 in these tests. Only the state
    /// injection hoop and the two `.well-known` OIDC documents (which
    /// `server::mod` mounts outside the resource builders) are test-local.
    fn build_test_router(&self) -> Router {
        use crate::server::routers::{
            build_account_api_routes, build_admin_routes, build_human_router, build_oauth_router,
        };

        let router = Router::new()
            .hoop(InjectTestState(self.clone()))
            .push(Router::with_path("/health").get(crate::handlers::health::get))
            .push(Router::with_path("/livez").get(crate::handlers::health::livez))
            .push(Router::with_path("/healthz").get(crate::handlers::health::get))
            .push(Router::with_path("/readyz").get(crate::handlers::health::readyz))
            .push(
                Router::with_path("/.well-known/openid-configuration")
                    .get(crate::handlers::oauth::discovery::get),
            )
            .push(
                Router::with_path("/.well-known/webfinger")
                    .get(crate::handlers::oauth::webfinger::get),
            );

        // `/_coauth/admin` first so it is matched before the broader
        // `/_coauth` account router, mirroring the production deployment where
        // each resource owns its own listener.
        let router = build_admin_routes(router);
        let router = build_account_api_routes(router);
        let router = build_oauth_router(router);
        build_human_router(router, self.templates.clone())
    }

    pub async fn request(&self, request: Request<String>) -> Response<String> {
        let router = self.build_test_router();
        let service = salvo::Service::new(router);

        let (parts, body) = request.into_parts();
        let uri = parts.uri;
        let url = format!(
            "https://example.com{}",
            uri.path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str)
        );

        let mut test_req = match parts.method {
            hyper::Method::GET => TestClient::get(&url),
            hyper::Method::POST => TestClient::post(&url),
            hyper::Method::PUT => TestClient::put(&url),
            hyper::Method::DELETE => TestClient::delete(&url),
            hyper::Method::PATCH => TestClient::patch(&url),
            hyper::Method::HEAD => TestClient::head(&url),
            hyper::Method::OPTIONS => TestClient::options(&url),
            other => panic!("Unsupported HTTP method: {other}"),
        };

        for (name, value) in &parts.headers {
            test_req = test_req.add_header(name, value, true);
        }

        if !body.is_empty() {
            test_req = test_req.bytes(body.into_bytes());
        }

        let mut salvo_res = test_req.send(&service).await;
        let status = salvo_res.status_code.unwrap_or(StatusCode::OK);
        let response_headers = salvo_res.headers().clone();
        let body_str = salvo_res.take_string().await.unwrap_or_default();

        let mut builder = Response::builder().status(status);
        *builder.headers_mut().unwrap() = response_headers;
        builder.body(body_str).unwrap()
    }

    /// Create an OAuth access token with the given scope for admin API
    /// tests.
    pub async fn token_with_scope(&mut self, scope: &str) -> String {
        let parsed_scope: Scope = if scope.is_empty() {
            std::iter::empty().collect()
        } else {
            scope.parse().expect("test scope must parse")
        };

        let mut repo = self.repository().await.unwrap();
        let unique = unique_test_nonce();
        let clock = SystemClock::default();
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let user = repo
            .user()
            .add(
                &mut rng,
                &clock,
                format!("admin{}", Ulid::new().to_string().to_lowercase()),
            )
            .await
            .unwrap();

        let session = repo
            .personal_session()
            .add(
                &mut rng,
                &clock,
                PersonalSessionOwner::User(user.id),
                &user,
                "Admin test token".to_owned(),
                parsed_scope,
            )
            .await
            .unwrap();

        let access_token = TokenType::PersonalAccessToken.generate(&mut rng);
        repo.personal_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                Some(self.site_config.access_token_ttl),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        access_token
    }

    /// Mint an OAuth client-credentials session plus its access token and
    /// return `(bearer, session_id)`.
    ///
    /// [`Self::token_with_scope`] issues a *personal* access token, which the
    /// `oauth_sessions` admin endpoints do not operate on. Tests covering
    /// those endpoints need a real OAuth session to authenticate with and to
    /// act on.
    ///
    /// # Panics
    ///
    /// Panics when the session or token cannot be persisted.
    pub async fn oauth_token_with_scope(&mut self, scope: &str) -> (String, Ulid) {
        use coauth_data::oauth::{
            OAuthAccessTokenRepository as _, OAuthClientRepository as _,
            OAuthSessionRepository as _,
        };

        let parsed_scope: Scope = if scope.is_empty() {
            std::iter::empty().collect()
        } else {
            scope.parse().expect("test scope must parse")
        };

        let mut repo = self.repository().await.unwrap();
        let clock = SystemClock::default();
        let mut rng = ChaChaRng::seed_from_u64(unique_test_nonce());
        let client = repo
            .oauth_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://client.example/callback".parse().unwrap()],
                None,
                None,
                None,
                vec![coauth_oauth_types::requests::GrantType::AuthorizationCode],
                Some("admin test client".to_owned()),
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
        // `oauth_sessions.user_id` is NOT NULL, so the session has to come
        // from a browser session rather than client credentials.
        let user = repo
            .user()
            .add(
                &mut rng,
                &clock,
                format!("oauth{}", Ulid::new().to_string().to_lowercase()),
            )
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();
        let session = repo
            .oauth_session()
            .add_from_browser_session(&mut rng, &clock, &client, &browser_session, parsed_scope)
            .await
            .unwrap();
        let access_token = TokenType::AccessToken.generate(&mut rng);
        repo.oauth_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                access_token.clone(),
                Some(self.site_config.access_token_ttl),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        (access_token, session.id)
    }

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        self.repository_factory.create().await
    }

    /// Persist an accepted principal-DID binding for `user` against
    /// [`TEST_PRINCIPAL_SERVER_AUDIENCE`] and return the bound principal core
    /// DID.
    ///
    /// Every admin path that touches account status, risk actions, or the DID
    /// inventory resolves the account's principal DID through this binding, so
    /// tests for those paths have to seed it.
    ///
    /// # Panics
    ///
    /// Panics when the binding cannot be persisted.
    pub async fn seed_principal_binding(&self, user: &coauth_data::User, label: &str) -> String {
        use coauth_data::user::PrincipalDidRepository as _;

        let (principal_id, key_log_head) =
            coauth_storage_postgres::test_utils::principal_binding_test_material(label);
        // Account-status publication requires the binding to have been accepted
        // by this deployment's own runtime service identity.
        let account_authority_full_id =
            crate::handlers::arkret::issuer_did_for(&self.arkret_config).to_string();
        let input = coauth_storage_postgres::test_utils::verified_principal_binding_input(
            &account_authority_full_id,
            TEST_PRINCIPAL_SERVER_AUDIENCE,
            principal_id.clone(),
            key_log_head,
        );

        let mut rng = self.rng();
        let mut repo = self.repository().await.unwrap();
        let binding = repo
            .principal_did()
            .add_verified(&mut rng, self.clock.as_ref(), user, input)
            .await
            .unwrap();

        // A registered account's issuer ledger opens with an active genesis
        // record; without it every later transition is rejected as a ledger
        // that does not begin at `active`.
        crate::services::account_status_publication::author_transition_plan(
            &mut repo,
            self.principal_server_admin.as_ref(),
            &self.key_store,
            crate::handlers::arkret::service_id_for(&self.arkret_config).as_str(),
            user,
            &binding,
            arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            chrono::Utc::now(),
            &mut rng,
        )
        .await
        .unwrap();
        repo.save().await.unwrap();

        principal_id
    }

    /// Returns a new random number generator.
    ///
    /// # Panics
    ///
    /// Panics if the RNG is already locked.
    pub fn rng(&self) -> ChaChaRng {
        let mut parent_rng = self.rng.try_lock().expect("Failed to lock RNG");
        ChaChaRng::from_rng(&mut *parent_rng).unwrap()
    }

    /// Get an empty cookie jar
    pub fn cookie_jar(&self) -> CookieJar {
        self.cookie_manager.cookie_jar()
    }
}

pub(crate) trait RequestBuilderExt {
    /// Builds the request with the given JSON value as body.
    fn json<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Builds the request with the given form value as body.
    fn form<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Sets the request Authorization header to the given bearer token.
    fn bearer(self, token: &str) -> Self;

    /// Builds the request with an empty body.
    fn empty(self) -> hyper::Request<String>;
}

impl RequestBuilderExt for hyper::http::request::Builder {
    fn json<T: Serialize>(mut self, body: T) -> hyper::Request<String> {
        self.headers_mut()
            .unwrap()
            .typed_insert(ContentType::json());

        self.body(serde_json::to_string(&body).unwrap()).unwrap()
    }

    fn form<T: Serialize>(mut self, body: T) -> hyper::Request<String> {
        self.headers_mut()
            .unwrap()
            .typed_insert(ContentType::form_url_encoded());

        self.body(serde_urlencoded::to_string(&body).unwrap())
            .unwrap()
    }

    fn bearer(mut self, token: &str) -> Self {
        self.headers_mut()
            .unwrap()
            .typed_insert(Authorization::bearer(token).unwrap());
        self
    }

    fn empty(self) -> hyper::Request<String> {
        self.body(String::new()).unwrap()
    }
}

pub(crate) trait ResponseExt {
    /// Asserts that the response has the given status code.
    ///
    /// # Panics
    ///
    /// Panics if the response has a different status code.
    fn assert_status(&self, status: StatusCode);

    /// Get the response body as JSON.
    ///
    /// # Panics
    ///
    /// Panics if the response is missing the `Content-Type: application/json`,
    /// or if the body is not valid JSON.
    fn json<T: DeserializeOwned>(&self) -> T;
}

impl ResponseExt for Response<String> {
    #[track_caller]
    fn assert_status(&self, status: StatusCode) {
        assert_eq!(
            self.status(),
            status,
            "HTTP status code mismatch: got {}, expected {}. Body: {}",
            self.status(),
            status,
            self.body()
        );
    }

    #[track_caller]
    fn json<T: DeserializeOwned>(&self) -> T {
        let content_type = self
            .headers()
            .get(CONTENT_TYPE)
            .unwrap_or_else(|| panic!("Missing header {CONTENT_TYPE}"))
            .to_str()
            .expect("Content-Type header is not valid ASCII");

        assert!(
            content_type.starts_with("application/json"),
            "Header mismatch: got {:?}, expected content type starting with \"application/json\"",
            self.headers().get(CONTENT_TYPE)
        );
        serde_json::from_str(self.body()).expect("JSON deserialization failed")
    }
}

/// A helper for storing and retrieving cookies in tests.
#[derive(Clone, Debug, Default)]
pub struct CookieHelper {
    store: Arc<RwLock<CookieStore>>,
}

impl CookieHelper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject the cookies from the store into the request.
    pub fn with_cookies<B>(&self, mut request: Request<B>) -> Request<B> {
        let url = Url::options()
            .base_url(Some(&"https://example.com/".parse().unwrap()))
            .parse(&request.uri().to_string())
            .expect("Failed to parse URL");

        let store = self.store.read().unwrap();
        let value = store
            .get_request_values(&url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");

        request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&value).expect("Invalid cookie value"),
        );
        request
    }

    /// Import cookies from a `CookieJar` into the store.
    pub fn import(&self, cookie_jar: CookieJar) {
        let url = "https://example.com/".parse().unwrap();
        let mut store = self.store.write().unwrap();
        store.store_response_cookies(
            cookie_jar
                .pending_cookies()
                .iter()
                .map(|c| RawCookie::parse(c.to_string()).expect("Invalid cookie from CookieJar")),
            &url,
        );
    }
}
