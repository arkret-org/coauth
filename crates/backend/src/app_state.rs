use std::{net::IpAddr, sync::Arc};

use coauth_config::ContrixConfig;
use coauth_data::{
    AppVersion, BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, PgRepositoryFactory,
    RepositoryFactory, SiteConfig, SystemClock, UrlBuilder,
};
use coauth_i18n::Translator;
use coauth_keystore::{Encrypter, Keystore};
use coauth_policy::{Policy, PolicyFactory};
use coauth_principal::{ConnectorRegistry, PrincipalServerAdmin};
use coauth_templates::Templates;
use diesel_async::{AsyncPgConnection, pooled_connection::deadpool::Pool as DieselPool};
use ipnetwork::IpNetwork;
use opentelemetry::KeyValue;
use rand_core::SeedableRng;
use salvo::prelude::*;
use tracing::Instrument;

use crate::{
    handlers::{
        ActivityTracker, CookieManager, Limiter, MetadataCache, passwords::PasswordManager,
    },
    services::{
        account_claims::account_claims_service,
        did_resolver::default_did_resolver_service,
        email_webhook::EmailWebhookService,
        invite_quarantine::invite_quarantine_service,
        risk_action_proposals::risk_action_proposals_service,
        risk_action_state::default_risk_action_state_service,
        starid_adapter::{StaridRegistryHandle, StaridResolver},
        upstream_oidc::default_upstream_oidc_service,
        upstream_oidc_mapping::TrustedIssuerPolicySet,
        webauthn::webauthn_service,
    },
    telemetry::METER,
};

/// Shared application state that is cloned into the Salvo [`Depot`] for every
/// incoming request. Holds all the service-level dependencies (database pool,
/// templates, keys, policy engine, etc.).
#[derive(Clone)]
pub struct AppState {
    pub repository_factory: PgRepositoryFactory,
    pub templates: Templates,
    pub contrix_config: ContrixConfig,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub principal_server_admin: Arc<dyn PrincipalServerAdmin>,
    pub connector_registry: ConnectorRegistry,
    pub policy_factory: Arc<PolicyFactory>,
    pub http_client: reqwest::Client,
    pub password_manager: PasswordManager,
    pub metadata_cache: MetadataCache,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub trusted_proxies: Vec<IpNetwork>,
    pub limiter: Limiter,
    pub frontend_script_src: String,
    pub email_webhook_service: Option<EmailWebhookService>,
    /// Maximum accepted request-body size, in bytes. Wired into Salvo's
    /// `SecureMaxSize` middleware on the public router.
    pub max_body_bytes: u64,

    /// Per-request handling deadline, in seconds. `0` disables the
    /// timeout middleware. Wired into the `RequestTimeout` hoop in
    /// [`crate::server::build_router`].
    pub request_timeout_seconds: u64,

    /// Grace period (seconds) to drain in-flight requests on
    /// SIGTERM/SIGINT before listeners are forcibly closed.
    pub shutdown_grace_seconds: u64,

    /// Pre-rendered `Strict-Transport-Security` header value.
    /// `None` disables HSTS emission (the default).
    pub hsts_header: Option<String>,

    /// `Content-Security-Policy` value emitted on HTML responses.
    /// `None` (or an empty configured string) suppresses the header.
    pub csp_html_header: Option<String>,
}

impl AppState {
    /// Init the metrics for the app state.
    pub fn init_metrics(&mut self) {
        let pool = self.repository_factory.pool().clone();
        METER
            .i64_observable_up_down_counter("db.connections.usage")
            .with_description("The number of connections that are currently in `state` described by the state attribute.")
            .with_unit("{connection}")
            .with_callback(move |instrument| {
                let status = pool.status();
                let idle = status.available;
                let used = status.size.saturating_sub(idle);
                instrument.observe(idle as i64, &[KeyValue::new("state", "idle")]);
                instrument.observe(used as i64, &[KeyValue::new("state", "used")]);
            })
            .build();

        let pool = self.repository_factory.pool().clone();
        METER
            .i64_observable_up_down_counter("db.connections.max")
            .with_description("The maximum number of open connections allowed.")
            .with_unit("{connection}")
            .with_callback(move |instrument| {
                let status = pool.status();
                instrument.observe(status.max_size as i64, &[]);
            })
            .build();
    }

    /// Init the metadata cache in the background
    pub fn init_metadata_cache(&self) {
        let factory = self.repository_factory.clone();
        let metadata_cache = self.metadata_cache.clone();
        let http_client = self.http_client.clone();

        tokio::spawn(
            async move {
                let mut repo = match factory.create().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            "Failed to acquire a database connection"
                        );
                        return;
                    }
                };

                if let Err(e) = metadata_cache
                    .warm_up_and_run(
                        &http_client,
                        std::time::Duration::from_mins(15),
                        &mut repo,
                    )
                    .await
                {
                    tracing::error!(
                        error = &e as &dyn std::error::Error,
                        "Failed to warm up the metadata cache"
                    );
                }
            }
            .instrument(tracing::info_span!("metadata_cache.background_warmup")),
        );
    }
}

/// Salvo middleware that extracts [`AppState`] from the depot and fans it out
/// into individual typed depot entries (one per component). This allows
/// handler functions to pull only the specific dependency they need.
#[handler]
pub async fn inject_app_state(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // The AppState should already be in depot from the router setup
    let state: AppState = if let Some(state) = depot.get::<AppState>("app_state").ok().cloned() { state } else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Text::Plain("AppState not found in depot"));
        ctrl.skip_rest();
        return;
    };

    // Inject all components into depot with their type names as keys
    depot.insert("pg_pool", state.repository_factory.pool().clone());
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
        "principal_server_admin",
        Arc::clone(&state.principal_server_admin),
    );
    depot.insert("connector_registry", state.connector_registry.clone());
    depot.insert("app_version", AppVersion(crate::version()));
    depot.insert("activity_tracker", state.activity_tracker.clone());
    depot.insert("trusted_proxies", state.trusted_proxies.clone());
    depot.insert("frontend_script_src", state.frontend_script_src.clone());
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
    // Trusted-issuer mapping policy set; default-empty until config wires
    // entries from `contrix_config.trusted_issuers`. Round 25 introduces
    // the registry in-process; production wiring follows later.
    depot.insert(
        "upstream_oidc_trusted_issuers",
        TrustedIssuerPolicySet::default(),
    );
    depot.insert("did_resolver_service", default_did_resolver_service());
    // C35.0: when `[contrix.starid]` is configured, build a single
    // `StaridResolver` per request from the shared http_client. The
    // handle is `Option<StaridRegistryHandle>` in the depot — handlers
    // that need it (today: the onboarding `user_write` flow stage) read
    // via `DepotExt::starid_registry()` and skip the wire-up when it
    // returns `None`. The async did_resolver still works without a
    // handle: it falls back to the local `did:web:coauth.invalid:…`
    // form for accounts whose `starid_backend` flag is `false`.
    if let Some(starid_config) = state.contrix_config.starid.as_ref() {
        match StaridResolver::with_http_client(starid_config, state.http_client.clone()) {
            Ok(resolver) => {
                let handle: StaridRegistryHandle = Arc::new(resolver);
                depot.insert("starid_registry", handle);
            }
            Err(err) => {
                tracing::warn!(
                    %err,
                    "starid registry unavailable (base_url={}); onboarding flows will fall back to the local did:web derivation",
                    starid_config.base_url,
                );
            }
        }
    }
    // Build the WebAuthn service from the current URL builder. We only
    // insert the service if construction succeeds; a misconfigured RP
    // origin should not bring the rest of the request pipeline down.
    {
        let rp_id = state.url_builder.public_hostname().to_owned();
        let rp_origin = state.url_builder.http_base();
        let rp_name = "Contrix";
        match webauthn_service(
            &rp_id,
            &rp_origin,
            rp_name,
            state.repository_factory.pool().clone(),
        ) {
            Ok(svc) => {
                depot.insert("webauthn_service", svc);
            }
            Err(err) => {
                tracing::warn!(
                    %err,
                    "WebAuthn service unavailable (rp_id={rp_id}, rp_origin={rp_origin})",
                );
            }
        }
    }
    if let Some(email_webhook_service) = state.email_webhook_service.clone() {
        depot.insert("email_webhook_service", email_webhook_service);
    }

    ctrl.call_next(req, depot, res).await;
}

/// Convenience accessors for pulling typed components out of a Salvo [`Depot`].
/// Each getter returns `Option<&T>`, returning `None` if the component was not
/// injected (e.g. if [`inject_app_state`] middleware did not run).
pub trait DepotExt {
    fn get_pg_pool(&self) -> Option<&DieselPool<AsyncPgConnection>>;
    fn get_box_repository_factory(&self) -> Option<&BoxRepositoryFactory>;
    fn get_templates(&self) -> Option<&Templates>;
    fn get_translator(&self) -> Option<&Arc<Translator>>;
    fn get_contrix_config(&self) -> Option<&ContrixConfig>;
    fn get_keystore(&self) -> Option<&Keystore>;
    fn get_encrypter(&self) -> Option<&Encrypter>;
    fn get_url_builder(&self) -> Option<&UrlBuilder>;
    fn get_http_client(&self) -> Option<&reqwest::Client>;
    fn get_password_manager(&self) -> Option<&PasswordManager>;
    fn get_cookie_manager(&self) -> Option<&CookieManager>;
    fn get_metadata_cache(&self) -> Option<&MetadataCache>;
    fn get_site_config(&self) -> Option<&SiteConfig>;
    fn get_limiter(&self) -> Option<&Limiter>;
    fn get_policy_factory(&self) -> Option<&Arc<PolicyFactory>>;
    fn get_principal_server_admin(&self) -> Option<&Arc<dyn PrincipalServerAdmin>>;
    fn get_connector_registry(&self) -> Option<&ConnectorRegistry>;
    fn get_app_version(&self) -> Option<&AppVersion>;
    fn get_activity_tracker(&self) -> Option<&ActivityTracker>;
    fn get_trusted_proxies(&self) -> Option<&Vec<IpNetwork>>;
}

impl DepotExt for Depot {
    fn get_pg_pool(&self) -> Option<&DieselPool<AsyncPgConnection>> {
        self.get::<DieselPool<AsyncPgConnection>>("pg_pool").ok()
    }

    fn get_box_repository_factory(&self) -> Option<&BoxRepositoryFactory> {
        self.get::<BoxRepositoryFactory>("box_repository_factory")
            .ok()
    }

    fn get_templates(&self) -> Option<&Templates> {
        self.get::<Templates>("templates").ok()
    }

    fn get_translator(&self) -> Option<&Arc<Translator>> {
        self.get::<Arc<Translator>>("translator").ok()
    }

    fn get_contrix_config(&self) -> Option<&ContrixConfig> {
        self.get::<ContrixConfig>("contrix_config").ok()
    }

    fn get_keystore(&self) -> Option<&Keystore> {
        self.get::<Keystore>("keystore").ok()
    }

    fn get_encrypter(&self) -> Option<&Encrypter> {
        self.get::<Encrypter>("encrypter").ok()
    }

    fn get_url_builder(&self) -> Option<&UrlBuilder> {
        self.get::<UrlBuilder>("url_builder").ok()
    }

    fn get_http_client(&self) -> Option<&reqwest::Client> {
        self.get::<reqwest::Client>("http_client").ok()
    }

    fn get_password_manager(&self) -> Option<&PasswordManager> {
        self.get::<PasswordManager>("password_manager").ok()
    }

    fn get_cookie_manager(&self) -> Option<&CookieManager> {
        self.get::<CookieManager>("cookie_manager").ok()
    }

    fn get_metadata_cache(&self) -> Option<&MetadataCache> {
        self.get::<MetadataCache>("metadata_cache").ok()
    }

    fn get_site_config(&self) -> Option<&SiteConfig> {
        self.get::<SiteConfig>("site_config").ok()
    }

    fn get_limiter(&self) -> Option<&Limiter> {
        self.get::<Limiter>("limiter").ok()
    }

    fn get_policy_factory(&self) -> Option<&Arc<PolicyFactory>> {
        self.get::<Arc<PolicyFactory>>("policy_factory").ok()
    }

    fn get_principal_server_admin(&self) -> Option<&Arc<dyn PrincipalServerAdmin>> {
        self.get::<Arc<dyn PrincipalServerAdmin>>("principal_server_admin")
            .ok()
    }

    fn get_connector_registry(&self) -> Option<&ConnectorRegistry> {
        self.get::<ConnectorRegistry>("connector_registry").ok()
    }

    fn get_app_version(&self) -> Option<&AppVersion> {
        self.get::<AppVersion>("app_version").ok()
    }

    fn get_activity_tracker(&self) -> Option<&ActivityTracker> {
        self.get::<ActivityTracker>("activity_tracker").ok()
    }

    fn get_trusted_proxies(&self) -> Option<&Vec<IpNetwork>> {
        self.get::<Vec<IpNetwork>>("trusted_proxies").ok()
    }
}

/// Extract `BoxClock` from request
#[must_use] 
pub fn extract_clock() -> BoxClock {
    let clock = SystemClock::default();
    Box::new(clock)
}

/// Extract `BoxRng` from request
#[must_use] 
pub fn extract_rng() -> BoxRng {
    let rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed RNG");
    Box::new(rng)
}

/// Extract Policy from depot
pub async fn extract_policy(depot: &Depot) -> Result<Policy, coauth_policy::InstantiateError> {
    let policy_factory = depot.get_policy_factory().ok_or_else(|| {
        coauth_policy::InstantiateError::Runtime(anyhow::anyhow!(
            "PolicyFactory not found in depot"
        ))
    })?;
    policy_factory.instantiate().await
}

/// Extract `BoxRepository` from depot
pub async fn extract_repository(
    depot: &Depot,
) -> Result<BoxRepository, coauth_data::RepositoryError> {
    let app_state = depot.get::<AppState>("app_state").ok().ok_or_else(|| {
        coauth_data::RepositoryError::from_error(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "AppState not found in depot",
        ))
    })?;
    app_state.repository_factory.create().await
}

fn infer_client_ip(req: &Request, trusted_proxies: &[IpNetwork]) -> Option<IpAddr> {
    let connection_info = req.extensions().get::<crate::listener::ConnectionInfo>();

    let peer = if let Some(info) = connection_info {
        // We can always trust the proxy protocol to give us the correct IP address
        if let Some(proxy) = info.proxy()
            && let Some(source) = proxy.source()
        {
            return Some(source.ip());
        }

        info.peer_addr().map(|addr| addr.ip())
    } else {
        None
    };

    // Get the list of IPs from the X-Forwarded-For header
    let peers_from_header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').filter_map(|v| v.trim().parse().ok()))
        .into_iter()
        .flatten();

    // This constructs a list of IP addresses that might be the client's IP address.
    // Each intermediate proxy is supposed to add the client's IP address to front
    // of the list. We are effectively adding the IP we got from the socket to the
    // front of the list.
    // We also call `to_canonical` so that IPv6-mapped IPv4 addresses
    // (::ffff:A.B.C.D) are converted to IPv4.
    let peer_list: Vec<IpAddr> = peer
        .into_iter()
        .chain(peers_from_header)
        .map(|ip| ip.to_canonical())
        .collect();

    // We'll fallback to the first IP in the list if all the IPs we got are trusted
    let fallback = peer_list.first().copied();

    // Now we go through the list, and the IP of the client is the first IP that is
    // not in the list of trusted proxies, starting from the back.
    let client_ip = peer_list
        .iter()
        .rfind(|ip| !trusted_proxies.iter().any(|network| network.contains(**ip)))
        .copied();

    client_ip.or(fallback)
}
