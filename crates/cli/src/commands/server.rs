use std::{process::ExitCode, sync::Arc, time::Duration};

use anyhow::Context;
use clap::Parser;
use coauth_backend::{
    app_state::AppState,
    handlers::{ActivityTracker, CookieManager, Limiter, MetadataCache},
    lifecycle::LifecycleManager,
    listener::server::Server,
    services::email_webhook::EmailWebhookService,
    util::{
        database_url_from_config, diesel_pool_from_config,
        load_policy_factory_dynamic_data_continuously, notification_center_from_config,
        password_manager_from_config, policy_factory_from_config,
        principal_server_connection_from_config, site_config_from_config, templates_from_config,
        test_mailer_in_background,
    },
};
use coauth_config::{
    AppConfig, ClientsConfig, ConfigurationSection, ConfigurationSectionExt, HttpResource,
    UpstreamOAuthConfig,
};
use coauth_data::{PgRepositoryFactory, SystemClock, UrlBuilder};
use figment::Figment;
use itertools::Itertools;
use tracing::{info, info_span, warn};

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Do not apply pending database migrations on start
    #[arg(long)]
    no_migrate: bool,

    /// Do not start the task worker
    #[arg(long)]
    no_worker: bool,

    /// Do not sync the configuration with the database
    #[arg(long)]
    no_sync: bool,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let span = info_span!("cli.run.init").entered();
        let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let mut shutdown = LifecycleManager::new()?
            .with_timeout(Duration::from_secs(config.http.shutdown_grace_seconds));

        info!(version = crate::VERSION, "Starting up");

        // Connect to the database
        info!("Connecting to the database");
        let db_url = database_url_from_config(&config.database)?;
        let pool = diesel_pool_from_config(&config.database).await?;

        if self.no_migrate {
            if coauth_data::has_pending_migrations(&db_url).await? {
                // Refuse to start if there are pending migrations
                return Err(anyhow::anyhow!(
                    "The server is running with `--no-migrate` but there are pending migrations. Please run them first with `coauth database migrate`, or omit the `--no-migrate` flag to apply them automatically on startup."
                ));
            }
        } else {
            info!("Running pending database migrations");
            coauth_data::migrate(&pool, &db_url)
                .await
                .context("could not run migrations")?;
        }

        let encrypter = config.secrets.encrypter().await?;

        if self.no_sync {
            info!("Skipping configuration sync");
        } else {
            // Sync the configuration with the database
            let conn = pool
                .get()
                .await
                .context("could not get connection from pool")?;
            let clients_config =
                ClientsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
            let upstream_oauth_config = UpstreamOAuthConfig::extract_or_default(figment)
                .map_err(anyhow::Error::from_boxed)?;

            coauth_backend::sync::config_sync(
                upstream_oauth_config,
                clients_config,
                conn,
                &encrypter,
                &SystemClock::default(),
                false,
                false,
            )
            .await
            .context("could not sync the configuration with the database")?;
        }

        // Initialize the key store
        let key_store = config
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;

        let cookie_manager = CookieManager::derive_from(
            config.http.public_base.clone(),
            &config.secrets.encryption().await?,
        );

        // Load and compile the WASM policies (and fallback to the default embedded one)
        info!("Loading and compiling the policy module");
        let policy_factory =
            policy_factory_from_config(&config.policy, &config.experimental).await?;
        let policy_factory = Arc::new(policy_factory);

        load_policy_factory_dynamic_data_continuously(
            &policy_factory,
            PgRepositoryFactory::new(pool.clone()).boxed(),
            shutdown.soft_shutdown_token(),
            shutdown.task_tracker(),
        )
        .await?;

        let url_builder = UrlBuilder::new(
            config.http.public_base.clone(),
            config.http.issuer.clone(),
            None,
        );

        // Load the site configuration
        let site_config = site_config_from_config(
            &config.branding,
            &config.http,
            &config.experimental,
            &config.passwords,
            &config.account,
            &config.captcha,
            &config.sms,
        )?;

        // Load and compile the templates
        let templates = templates_from_config(
            &config.templates,
            &site_config,
            &url_builder,
            // Don't use strict mode in production yet
            false,
        )
        .await?;
        shutdown.register_reloadable(&templates);

        let http_client = coauth_backend::reqwest_client();

        let (principal_server_admin, connector_registry) =
            principal_server_connection_from_config(&site_config);

        if !self.no_worker {
            let notifications =
                notification_center_from_config(&config.email, &config.sms, &templates)?;
            if let Some(mailer) = notifications.email() {
                test_mailer_in_background(mailer, Duration::from_secs(30));
            }

            info!("Starting task worker");
            let database_url = database_url_from_config(&config.database)?;
            coauth_tasks::init_and_run(
                PgRepositoryFactory::new(pool.clone()),
                database_url,
                SystemClock::default(),
                &notifications,
                principal_server_admin.clone(),
                url_builder.clone(),
                &site_config,
                shutdown.soft_shutdown_token(),
                shutdown.task_tracker(),
            )
            .await?;
        }

        let listeners_config = config.http.listeners.clone();

        // Discover the hashed frontend script path from the Dioxus build output
        let frontend_script_src = listeners_config
            .iter()
            .flat_map(|l| &l.resources)
            .find_map(|r| {
                if let HttpResource::Assets { path } = r {
                    coauth_backend::server::discover_frontend_script(path)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "/assets/coauth-frontend.js".into());
        info!(frontend_script_src, "Discovered frontend script path");

        let password_manager = password_manager_from_config(&config.passwords).await?;

        // The upstream OIDC metadata cache
        let metadata_cache = MetadataCache::new();

        // Initialize the activity tracker
        // Activity is flushed every minute
        let activity_tracker = ActivityTracker::new(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            Duration::from_mins(1),
            shutdown.task_tracker(),
            shutdown.soft_shutdown_token(),
        );

        shutdown.register_reloadable(&activity_tracker);

        let trusted_proxies = config.http.trusted_proxies.clone();
        let max_body_bytes = config.http.max_body_bytes;
        let request_timeout_seconds = config.http.request_timeout_seconds;
        let shutdown_grace_seconds = config.http.shutdown_grace_seconds;
        let hsts_header = config.http.hsts.as_ref().map(|hsts| {
            let mut value = format!("max-age={}", hsts.max_age_seconds);
            if hsts.include_subdomains {
                value.push_str("; includeSubDomains");
            }
            if hsts.preload {
                value.push_str("; preload");
            }
            value
        });
        let csp_html_header = config
            .http
            .csp_html
            .as_ref()
            .map(|raw| raw.trim().to_owned())
            .filter(|value| !value.is_empty());

        // Build a rate limiter.
        // This should not raise an error here as the config should already have been
        // validated.
        let limiter = Limiter::new(&config.rate_limiting)
            .context("rate-limiting configuration is not valid")?;

        // Initialize the storage backend
        coauth_backend::storage::init(&config.storage)
            .context("failed to initialize storage backend")?;

        let email_webhook_service =
            EmailWebhookService::from_email_config(&config.email, http_client.clone())
                .context("invalid email webhook configuration")?;
        let contrix_config = config.contrix.clone();

        // Explicitly the config to properly zeroize secret keys
        drop(config);

        let state = {
            let mut s = AppState {
                repository_factory: PgRepositoryFactory::new(pool),
                templates,
                contrix_config,
                key_store,
                cookie_manager,
                encrypter,
                url_builder,
                principal_server_admin,
                connector_registry,
                policy_factory,
                http_client,
                password_manager,
                metadata_cache,
                site_config,
                activity_tracker,
                trusted_proxies,
                limiter,
                frontend_script_src,
                email_webhook_service,
                max_body_bytes,
                request_timeout_seconds,
                shutdown_grace_seconds,
                hsts_header,
                csp_html_header,
                // G4.T3 — load verified-profile descriptors at startup from
                // COAUTH_VERIFIED_PROFILES_ARTIFACT (env var IS the feature
                // flag). Empty Arc when unset.
                verified_profiles:
                    coauth_backend::services::verified_profiles::load_from_env(),
            };
            s.init_metrics();
            s.init_metadata_cache();
            s
        };

        let mut fd_manager = listenfd::ListenFd::from_env();

        let mut servers = Vec::new();
        let mut listening_announcements = Vec::with_capacity(listeners_config.len());

        for config in listeners_config {
            let listener_name = config.name.clone();
            let listener_label = listener_name.as_deref().unwrap_or("<unnamed>");

            // Let's first grab all the listeners
            let listeners = coauth_backend::server::build_listeners(&mut fd_manager, &config.binds)
                .with_context(|| format!("could not initialize listener `{listener_label}`"))?;

            // Load the TLS config
            let tls_config = if let Some(tls_config) = config.tls.as_ref() {
                let tls_config = coauth_backend::server::build_tls_server_config(tls_config)?;
                Some(Arc::new(tls_config))
            } else {
                None
            };

            // and build the router
            let router = coauth_backend::server::build_router(
                state.clone(),
                &config.resources,
                config.prefix.as_deref(),
                config.name.as_deref(),
            );

            // Create a Salvo service and hyper handler from the router
            let salvo_service = salvo::Service::new(router);
            let hyper_handler = salvo_service.hyper_handler(
                salvo::conn::SocketAddr::Unknown,
                salvo::conn::SocketAddr::Unknown,
                http::uri::Scheme::HTTP,
                None,
                None,
            );
            let handler = move |req: hyper::Request<hyper::body::Incoming>| {
                use hyper::service::Service;
                hyper_handler.call(req)
            };

            // Only announce listeners after every bind has succeeded.
            let proto = if config.tls.is_some() {
                "https"
            } else {
                "http"
            };
            let prefix = config.prefix.clone().unwrap_or_default();
            let addresses = listeners
                .iter()
                .map(|listener| {
                    if let Ok(addr) = listener.local_addr() {
                        format!("{proto}://{addr:?}{prefix}")
                    } else {
                        warn!(
                            "Could not get local address for listener, something might be wrong!"
                        );
                        format!("{proto}://???{prefix}")
                    }
                })
                .join(", ");
            let resources = format!("{:?}", &config.resources);
            let announcement = if config.proxy_protocol {
                format!("Listening on {addresses} with resources {resources} (with Proxy Protocol)")
            } else {
                format!("Listening on {addresses} with resources {resources}")
            };
            listening_announcements.push((listener_name, announcement));

            servers.extend(listeners.into_iter().map(move |listener| {
                let mut server = Server::new(listener, handler.clone());
                if let Some(tls_config) = &tls_config {
                    server = server.with_tls(tls_config.clone());
                }
                if config.proxy_protocol {
                    server = server.with_proxy();
                }
                server
            }));
        }

        for (listener_name, announcement) in listening_announcements {
            if let Some(listener_name) = listener_name.as_deref() {
                info!(listener = listener_name, "{announcement}");
            } else {
                info!("{announcement}");
            }
        }

        span.exit();

        shutdown
            .task_tracker()
            .spawn(coauth_backend::listener::server::run_servers(
                servers,
                shutdown.soft_shutdown_token(),
                shutdown.hard_shutdown_token(),
            ));

        let exit_code = shutdown.run().await;

        Ok(exit_code)
    }
}
