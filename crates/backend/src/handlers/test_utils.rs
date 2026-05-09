// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    process,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::Duration;
use coauth_config::ContrixConfig;
use coauth_config::RateLimitingConfig;
use coauth_data::{
    AppVersion, BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, PgRepositoryFactory,
    RepositoryAccess, RepositoryError, RepositoryFactory, SiteConfig, SystemClock, TokenType,
    UrlBuilder,
    clock::MockClock,
    personal::{
        PersonalAccessTokenRepository, PersonalSessionRepository, session::PersonalSessionOwner,
    },
    user::UserRepository,
};
use coauth_i18n::Translator;
use coauth_keystore::{Encrypter, JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use coauth_matrix::{HomeserverAdmin, MockHomeserverAdmin};
use coauth_messaging::{MailTransport, Mailer, NotificationCenter};
use coauth_policy::{InstantiateError, Policy, PolicyFactory};
use coauth_tasks::QueueWorker;
use coauth_templates::{SiteConfigExt, Templates};
use cookie_store::{CookieStore, RawCookie};
use diesel_async::{AsyncPgConnection, pooled_connection::deadpool::Pool as DieselPool};
use headers::{Authorization, ContentType, HeaderMapExt, HeaderName, HeaderValue};
use hyper::{
    Request, Response, StatusCode,
    header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
};
use oauth2_types::scope::Scope;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::{
    prelude::*,
    test::{ResponseExt as SalvoResponseExt, TestClient},
};
use serde::{Serialize, de::DeserializeOwned};
use tokio_util::{
    sync::{CancellationToken, DropGuard},
    task::TaskTracker,
};
use ulid::Ulid;
use url::Url;

use crate::{
    handlers::{
        ActivityTracker, BoundActivityTracker, Limiter, RequesterFingerprint,
        passwords::{Hasher, PasswordManager},
        upstream_oauth2::cache::MetadataCache,
    },
    salvo_utils::cookies::{CookieJar, CookieManager},
    services::{
        account_claims::account_claims_service, did_resolver::default_did_resolver_service,
        invite_quarantine::invite_quarantine_service,
        principal_cache::default_principal_cache_service,
        risk_action_proposals::risk_action_proposals_service,
        risk_action_state::default_risk_action_state_service,
        upstream_oidc::default_upstream_oidc_service,
    },
};

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
    let pid_component = (process::id() as u64 % 1_000) * 1_000_000;

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
    pub contrix_config: ContrixConfig,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub metadata_cache: MetadataCache,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub homeserver_admin: Arc<MockHomeserverAdmin>,
    pub policy_factory: Arc<PolicyFactory>,
    pub password_manager: PasswordManager,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub limiter: Limiter,
    pub clock: Arc<MockClock>,
    pub rng: Arc<Mutex<ChaChaRng>>,
    pub http_client: reqwest::Client,
    pub task_tracker: TaskTracker,
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
        account_recovery_allowed: true,
        account_deactivation_allowed: true,
        captcha: None,
        minimum_password_complexity: 1,
        session_expiration: None,
        login_with_email_allowed: true,
        admin_portal_url: None,
        plan_management_iframe_uri: None,
        session_limit: None,
        flow_engine_enabled: false,
        phone_verification_enabled: true,
    }
}

/// Salvo handler that injects TestState components into the Depot.
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
        depot.insert(
            "box_repository_factory",
            state.repository_factory.clone().boxed(),
        );
        depot.insert("templates", state.templates.clone());
        depot.insert("translator", state.templates.translator());
        depot.insert("contrix_config", state.contrix_config.clone());
        depot.insert("keystore", state.key_store.clone());
        depot.insert("encrypter", state.encrypter.clone());
        depot.insert("url_builder", state.url_builder.clone());
        depot.insert("http_client", state.http_client.clone());
        depot.insert("password_manager", state.password_manager.clone());
        depot.insert("cookie_manager", state.cookie_manager.clone());
        depot.insert("metadata_cache", state.metadata_cache.clone());
        depot.insert("site_config", state.site_config.clone());
        depot.insert("limiter", state.limiter.clone());
        depot.insert("policy_factory", state.policy_factory.clone());
        depot.insert(
            "homeserver_admin",
            Arc::clone(&state.homeserver_admin) as Arc<dyn HomeserverAdmin>,
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
        depot.insert("principal_cache_service", default_principal_cache_service());
        depot.insert(
            "account_claims_service",
            account_claims_service(state.repository_factory.pool().clone()),
        );
        depot.insert(
            "invite_quarantine_service",
            invite_quarantine_service(state.repository_factory.pool().clone()),
        );
        depot.insert("upstream_oidc_service", default_upstream_oidc_service());
        depot.insert("did_resolver_service", default_did_resolver_service());
        ctrl.call_next(req, depot, res).await;
    }
}

impl TestState {
    /// Create a new test state from the given database pool
    pub async fn from_pool(pool: DieselPool<AsyncPgConnection>) -> Result<Self, anyhow::Error> {
        Self::from_pool_with_site_config(pool, test_site_config()).await
    }

    /// Create a new test state from the given database pool and site config
    pub async fn from_pool_with_site_config(
        pool: DieselPool<AsyncPgConnection>,
        site_config: SiteConfig,
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

        let http_client = crate::reqwest_client();

        // TODO: add more test keys to the store
        let rsa = PrivateKey::load_pem(include_str!("../../../keystore/tests/keys/rsa.pkcs1.pem"))
            .unwrap();
        let rsa = JsonWebKey::new(rsa).with_kid("test-rsa");

        let jwks = JsonWebKeySet::new(vec![rsa]);
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

        let homeserver_admin = Arc::new(MockHomeserverAdmin::new(&site_config.server_name));

        let clock = Arc::new(MockClock::default());
        let rng = Arc::new(Mutex::new(ChaChaRng::seed_from_u64(42)));

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        let activity_tracker = ActivityTracker::new(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            std::time::Duration::from_secs(60),
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
            homeserver_admin.clone(),
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
            contrix_config: ContrixConfig::default(),
            key_store,
            cookie_manager,
            metadata_cache,
            encrypter,
            url_builder,
            homeserver_admin,
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

    /// Run all the available jobs in the queue.
    ///
    /// Panics if it fails to run the jobs (but not on job failures!)
    pub async fn run_jobs_in_queue(&self) {
        let mut queue = self.queue_worker.lock().await;
        queue.process_all_jobs_in_tests().await.unwrap();
    }

    /// Reset the test utils to a fresh state, with the same configuration.
    pub async fn reset(self) -> Self {
        let site_config = self.site_config.clone();
        let pool = self.repository_factory.pool().clone();
        let task_tracker = self.task_tracker.clone();

        // This should trigger the cancellation drop guard
        drop(self);

        // Wait for tasks to complete
        task_tracker.close();
        task_tracker.wait().await;

        Self::from_pool_with_site_config(pool, site_config)
            .await
            .unwrap()
    }

    /// Build a Salvo router with all test routes and state injection.
    fn build_test_router(&self) -> Router {
        use crate::handlers::admin::v1::{
            account_dids, accounts, audit_feed, claims, connector_health, devices,
            notification_channels, notification_templates, oauth2_sessions, personal_sessions,
            policy_checks, policy_data, site_config, upstream_oauth_links,
            upstream_oauth_providers, user_emails, user_registration_tokens, user_sessions, users,
            version,
        };

        Router::new()
            .hoop(InjectTestState(self.clone()))
            // Health
            .push(Router::with_path("/health").get(crate::handlers::health::get))
            .push(
                Router::with_path("/webhooks/email/{provider}")
                    .post(crate::handlers::email_webhooks::post),
            )
            // OAuth2 discovery
            .push(
                Router::with_path("/.well-known/openid-configuration")
                    .get(crate::handlers::oauth2::discovery::get),
            )
            .push(
                Router::with_path("/.well-known/webfinger")
                    .get(crate::handlers::oauth2::webfinger::get),
            )
            .push(
                Router::with_path("/.well-known/did.json")
                    .get(crate::handlers::contrix::service_did_json),
            )
            .push(
                Router::with_path("/did.json")
                    .get(crate::handlers::contrix::service_did_json),
            )
            .push(
                Router::with_path("/users/{id}/did.json")
                    .get(crate::handlers::contrix::user_did_json),
            )
            // OAuth2 endpoints
            .push(
                Router::with_path("/oauth2/keys.json").get(crate::handlers::oauth2::keys::get),
            )
            .push(
                Router::with_path("/oauth2/userinfo")
                    .get(crate::handlers::oauth2::userinfo::get)
                    .post(crate::handlers::oauth2::userinfo::get),
            )
            .push(
                Router::with_path("/oauth2/introspect")
                    .post(crate::handlers::oauth2::introspection::post),
            )
            .push(
                Router::with_path("/oauth2/revoke")
                    .post(crate::handlers::oauth2::revoke::post),
            )
            .push(
                Router::with_path("/oauth2/token")
                    .post(crate::handlers::oauth2::token::post),
            )
            .push(
                Router::with_path("/oauth2/registration")
                    .post(crate::handlers::oauth2::registration::post),
            )
            .push(
                Router::with_path("/oauth2/device")
                    .post(crate::handlers::oauth2::device::authorize::post),
            )
            // REST API
            .push(Router::with_path("/api/v1/server/describe").get(crate::handlers::contrix::server_describe))
            .push(Router::with_path("/api/v1/identity/describe").get(crate::handlers::contrix::identity_describe))
            .push(Router::with_path("/api/v1/identity/resolve").post(crate::handlers::contrix::identity_resolve))
            .push(Router::with_path("/api/v1/identity/document").get(crate::handlers::contrix::identity_document))
            .push(Router::with_path("/api/v1/directory/describe").get(crate::handlers::contrix::directory_describe))
            .push(Router::with_path("/api/v1/directory/resolve-handle").post(crate::handlers::contrix::directory_resolve_handle))
            .push(
                Router::with_path("/api/v1/session-grants")
                    .get(crate::handlers::contrix::list_session_grants)
                    .push(
                        Router::with_path("introspect")
                            .post(crate::handlers::contrix::introspect_session_grant),
                    )
                    .push(
                        Router::with_path("{id}/revoke")
                            .post(crate::handlers::contrix::revoke_session_grant),
                    ),
            )
            .push(Router::with_path("/api/v1/viewer").get(crate::handlers::account::viewer::get_viewer))
            .push(Router::with_path("/api/v1/site-config").get(crate::handlers::account::site_config::get))
            .push(
                Router::with_path("/api/v1/sessions/{id}").get(crate::handlers::account::sessions::get_session),
            )
            .push(
                Router::with_path("/api/v1/browser-sessions/{id}")
                    .delete(crate::handlers::account::sessions::end_browser_session),
            )
            .push(
                Router::with_path("/api/v1/oauth2-sessions/{id}")
                    .delete(crate::handlers::account::sessions::end_oauth2_session),
            )
            .push(
                Router::with_path("/api/v1/oauth2-sessions/{id}/name")
                    .put(crate::handlers::account::sessions::set_oauth2_session_name),
            )
            .push(
                Router::with_path("/api/v1/oauth2-clients/{id}")
                    .get(crate::handlers::account::oauth2_clients::get_client),
            )
            .push(
                Router::with_path("/api/v1/viewer/password")
                    .post(crate::handlers::account::password::set_password),
            )
            .push(
                Router::with_path("/api/v1/password-recovery/{ticket}")
                    .get(crate::handlers::account::password::get_recovery_ticket_status),
            )
            .push(
                Router::with_path("/api/v1/password-recovery/set")
                    .post(crate::handlers::account::password::set_password_by_recovery),
            )
            .push(
                Router::with_path("/api/v1/password-recovery/resend")
                    .post(crate::handlers::account::password::resend_recovery_email),
            )
            .push(
                Router::with_path("/api/v1/viewer/profile")
                    .patch(crate::handlers::account::users::patch_profile),
            )
            .push(
                Router::with_path("/api/v1/viewer/cross-signing-reset")
                    .post(crate::handlers::account::users::allow_cross_signing_reset),
            )
            .push(
                Router::with_path("/api/v1/viewer/deactivate")
                    .post(crate::handlers::account::users::deactivate_user),
            )
            .push(
                Router::with_path("/api/v1/viewer/preferences")
                    .get(crate::handlers::account::notification_prefs::get_notification_preferences)
                    .patch(crate::handlers::account::notification_prefs::patch_notification_preferences),
            )
            .push(
                Router::with_path("/api/v1/email-auth/start")
                    .post(crate::handlers::account::emails::start_email_auth),
            )
            .push(
                Router::with_path("/api/v1/email-auth/{id}")
                    .get(crate::handlers::account::emails::get_email_auth),
            )
            .push(
                Router::with_path("/api/v1/email-auth/{id}/complete")
                    .post(crate::handlers::account::emails::complete_email_auth),
            )
            .push(
                Router::with_path("/api/v1/email-auth/{id}/resend")
                    .post(crate::handlers::account::emails::resend_email_auth_code),
            )
            .push(
                Router::with_path("/api/v1/user-emails/{id}")
                    .delete(crate::handlers::account::emails::remove_email),
            )
            // OAuth2 authorization
            .push(
                Router::with_path("/authorize")
                    .get(crate::handlers::oauth2::authorization::get),
            )
            // Upstream OAuth2
            .push(
                Router::with_path("/upstream/authorize/{provider_id}")
                    .get(crate::handlers::upstream_oauth2::authorize::get),
            )
            .push(
                Router::with_path("/upstream/callback/{provider_id}")
                    .get(crate::handlers::upstream_oauth2::callback::handler)
                    .post(crate::handlers::upstream_oauth2::callback::handler),
            )
            .push(
                Router::with_path("/upstream/backchannel-logout/{provider_id}")
                    .post(crate::handlers::upstream_oauth2::backchannel_logout::post),
            )
            // Admin API
            .push(
                Router::with_path("/api/admin/v1")
                    .push(Router::with_path("version").get(version::handler))
                    .push(Router::with_path("site-config").get(site_config::handler))
                    .push(Router::with_path("connector-health").get(connector_health::handler))
                    .push(Router::with_path("notification-channels").get(notification_channels::handler))
                    .push(
                        Router::with_path("notification-templates")
                            .get(notification_templates::list_handler)
                            .push(
                                Router::with_path("publish")
                                    .post(notification_templates::publish_handler),
                            ),
                    )
                    .push(Router::with_path("audit-feed").get(audit_feed::handler))
                    .push(
                        Router::with_path("accounts")
                            .get(accounts::list_accounts)
                            .push(
                                Router::with_path("{id}")
                                    .get(accounts::get_account)
                                    .push(
                                        Router::with_path("lock")
                                            .post(accounts::lock_account),
                                    )
                                    .push(
                                        Router::with_path("disable")
                                            .post(accounts::disable_account),
                                    )
                                    .push(
                                        Router::with_path("erase")
                                            .post(accounts::erase_account),
                                    )
                                    .push(
                                        Router::with_path("reset-recovery")
                                            .post(accounts::reset_recovery),
                                    )
                                    .push(
                                        Router::with_path("dids")
                                            .get(account_dids::list_account_dids)
                                            .post(account_dids::add_account_did)
                                            .push(
                                                Router::with_path("{did_id}")
                                                    .delete(account_dids::remove_account_did),
                                            ),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("users")
                            .get(users::list_users)
                            .post(users::add_user)
                            .push(
                                Router::with_path("by-username/{username}")
                                    .get(users::get_by_username),
                            )
                            .push(
                                Router::with_path("batch-invite")
                                    .post(users::batch_invite),
                            )
                            .push(
                                Router::with_path("{id}")
                                    .get(users::get_user)
                                    .patch(users::update_user)
                                    .push(
                                        Router::with_path("set-password")
                                            .post(users::set_password),
                                    )
                                    .push(Router::with_path("risk-action").post(users::risk_action)),
                            ),
                    )
                    .push(
                        Router::with_path("user-emails")
                            .get(user_emails::list_emails)
                            .post(user_emails::add_email)
                            .push(
                                Router::with_path("{id}")
                                    .get(user_emails::get_email)
                                    .patch(user_emails::update_email)
                                    .delete(user_emails::delete_email),
                            ),
                    )
                    .push(
                        Router::with_path("user-sessions")
                            .get(user_sessions::list_sessions)
                            .push(
                                Router::with_path("{id}")
                                    .get(user_sessions::get_session)
                                    .push(Router::with_path("finish").post(user_sessions::finish_session)),
                            ),
                    )
                    .push(
                        Router::with_path("oauth2-sessions")
                            .get(oauth2_sessions::list_sessions)
                            .push(
                                Router::with_path("{id}")
                                    .get(oauth2_sessions::get_session)
                                    .push(
                                        Router::with_path("finish").post(oauth2_sessions::finish_session),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("personal-sessions")
                            .get(personal_sessions::list_sessions)
                            .post(personal_sessions::add_session)
                            .push(
                                Router::with_path("{id}")
                                    .get(personal_sessions::get_session)
                                    .push(
                                        Router::with_path("regenerate")
                                            .post(personal_sessions::regenerate_session),
                                    )
                                    .push(
                                        Router::with_path("revoke")
                                            .post(personal_sessions::revoke_session),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("devices")
                            .get(devices::list_devices)
                            .push(
                                Router::with_path("{id}/revoke")
                                    .post(devices::revoke_device),
                            ),
                    )
                    .push(
                        Router::with_path("user-registration-tokens")
                            .get(user_registration_tokens::list_tokens)
                            .post(user_registration_tokens::add_token)
                            .push(
                                Router::with_path("{id}")
                                    .get(user_registration_tokens::get_token)
                                    .put(user_registration_tokens::update_token)
                                    .push(
                                        Router::with_path("revoke")
                                            .post(user_registration_tokens::revoke_token),
                                    )
                                    .push(
                                        Router::with_path("unrevoke")
                                            .post(user_registration_tokens::unrevoke_token),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("upstream-oauth-providers")
                            .get(upstream_oauth_providers::list_providers)
                            .push(Router::with_path("{id}").get(upstream_oauth_providers::get_provider)),
                    )
                    .push(
                        Router::with_path("upstream-oauth-links")
                            .get(upstream_oauth_links::list_links)
                            .post(upstream_oauth_links::add_link)
                            .push(
                                Router::with_path("{id}")
                                    .get(upstream_oauth_links::get_link)
                                    .patch(upstream_oauth_links::update_link)
                                    .delete(upstream_oauth_links::delete_link),
                            ),
                    )
                    .push(
                        Router::with_path("policy-data")
                            .push(Router::with_path("latest").get(policy_data::get_latest))
                            .push(Router::with_path("{id}").get(policy_data::get_by_id))
                            .put(policy_data::set_data),
                    )
                    .push(
                        Router::with_path("claims")
                            .post(claims::issue_claim)
                            .push(Router::with_path("status").get(claims::list_claim_status))
                            .push(
                                Router::with_path("{id}/revoke")
                                    .post(claims::revoke_claim),
                            ),
                    )
                    .push(
                        Router::with_path("policy-checks")
                            .push(Router::with_path("dry-run").post(policy_checks::dry_run)),
                    )
                    .push(
                        Router::with_path("policy-decision-audits").push(
                            Router::with_path("{id}")
                                .get(policy_checks::get_signed_decision_audit),
                        ),
                    ),
            )
    }

    pub async fn request(&self, request: Request<String>) -> Response<String> {
        let router = self.build_test_router();
        let service = salvo::Service::new(router);

        let (parts, body) = request.into_parts();
        let uri = parts.uri;
        let url = format!(
            "https://example.com{}",
            uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
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

    /// Create an OAuth 2.0 access token with the given scope for admin API
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

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        self.repository_factory.create().await
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

    /// Do a call to the userinfo endpoint to check if the given token is valid.
    /// Returns true if the token is valid.
    ///
    /// # Panics
    ///
    /// Panics if the response status code is not 200 or 401.
    pub async fn is_access_token_valid(&self, token: &str) -> bool {
        let request = Request::get("/oauth2/userinfo").bearer(token).empty();

        let response = self.request(request).await;

        match response.status() {
            StatusCode::OK => true,
            StatusCode::UNAUTHORIZED => false,
            _ => panic!("Unexpected status code: {}", response.status()),
        }
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

    /// Sets the request Authorization header to the given basic auth
    /// credentials.
    fn basic_auth(self, username: &str, password: &str) -> Self;

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

    fn basic_auth(mut self, username: &str, password: &str) -> Self {
        self.headers_mut()
            .unwrap()
            .typed_insert(Authorization::basic(username, password));
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

    /// Asserts that the response has the given header value.
    ///
    /// # Panics
    ///
    /// Panics if the response does not have the given header or if the header
    /// value does not match.
    fn assert_header_value(&self, header: HeaderName, value: &str);

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
    fn assert_header_value(&self, header: HeaderName, value: &str) {
        let actual_value = self
            .headers()
            .get(&header)
            .unwrap_or_else(|| panic!("Missing header {header}"));

        assert_eq!(
            actual_value,
            value,
            "Header mismatch: got {:?}, expected {:?}",
            self.headers().get(header),
            value
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

    /// Save the cookies from the response into the store.
    pub fn save_cookies<B>(&self, response: &Response<B>) {
        let url = "https://example.com/".parse().unwrap();
        let mut store = self.store.write().unwrap();
        store.store_response_cookies(
            response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .map(|set_cookie| {
                    RawCookie::parse(
                        set_cookie
                            .to_str()
                            .expect("Invalid set-cookie header")
                            .to_owned(),
                    )
                    .expect("Invalid set-cookie header")
                }),
            &url,
        );
    }

    /// Import cookies from a CookieJar into the store.
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
