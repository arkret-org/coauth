use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use coauth_backend::lifecycle::LifecycleManager;
use coauth_backend::util::{
    database_url_from_config, diesel_pool_from_config, notification_center_from_config,
    principal_server_connection_from_config, site_config_from_config, templates_from_config,
    test_mailer_in_background,
};
use coauth_config::{AppConfig, ConfigurationSection};
use coauth_data::{SystemClock, UrlBuilder};
use coauth_storage_postgres::PgRepositoryFactory;
use figment::Figment;
use tracing::{info, info_span};

/// CLI options for the background task worker process.
#[derive(Parser, Debug, Default)]
pub(super) struct Options {}

impl Options {
    /// Boot the task scheduler and block until shutdown is requested.
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let lifecycle = LifecycleManager::new()?;
        let _guard = info_span!("cli.worker.init").entered();

        let app_cfg = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        // ── Database ────────────────────────────────────────────────────
        info!("Connecting to the database");
        let db_pool = diesel_pool_from_config(&app_cfg.database).await?;
        let db_url = database_url_from_config(&app_cfg.database)?;

        let urls = UrlBuilder::new(
            app_cfg.http.public_base.clone(),
            app_cfg.http.issuer.clone(),
            None,
        );

        // ── Site configuration & templates ──────────────────────────────
        let site_cfg = site_config_from_config(
            &app_cfg.branding,
            &app_cfg.http,
            &app_cfg.experimental,
            &app_cfg.passwords,
            &app_cfg.account,
            &app_cfg.captcha,
            &app_cfg.sms,
        )?;

        let tpl = templates_from_config(
            &app_cfg.templates,
            &site_cfg,
            &urls,
            false, // strict mode disabled for task workers
        )
        .await?;

        // ── Notifications ───────────────────────────────────────────────
        let notifs = notification_center_from_config(&app_cfg.email, &app_cfg.sms, &tpl)?;
        if let Some(mailer) = notifs.email() {
            test_mailer_in_background(mailer, Duration::from_secs(30));
        }

        // ── Principal account facade ───────────────────────────────────
        let arkret_http_client = coauth_backend::reqwest_client_for_arkret(&app_cfg.arkret);
        let key_store = app_cfg
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;
        coauth_backend::services::service_identity::initialize_and_spawn(
            PgRepositoryFactory::new(db_pool.clone()),
            &app_cfg.arkret,
            &app_cfg.http.public_base,
            &key_store,
            arkret_http_client.clone(),
        )
        .await
        .context("could not initialize Provider-backed service identity")?;
        coauth_backend::services::principal_server_trust::preflight_and_spawn(
            PgRepositoryFactory::new(db_pool.clone()),
            app_cfg.arkret.clone(),
            arkret_http_client.clone(),
            coauth_backend::error::development_mode_from_env(),
            coauth_config::runtime_var("COAUTH_FIRST_PROVISIONING")
                .is_ok_and(|value| value.trim() == "1"),
            lifecycle.soft_shutdown_token(),
            coauth_backend::services::principal_server_trust::DEFAULT_REFRESH_INTERVAL,
        )
        .await
        .context("principal-server trust preflight failed")?;
        let (principal_conn, _registry) = principal_server_connection_from_config(
            &site_cfg,
            PgRepositoryFactory::new(db_pool.clone()).boxed(),
            app_cfg.arkret.clone(),
            arkret_http_client,
            &key_store,
            &urls,
        )?;

        drop(app_cfg);

        // ── Start the scheduler ─────────────────────────────────────────
        info!("Starting task scheduler");
        coauth_tasks::init_and_run(
            PgRepositoryFactory::new(db_pool.clone()),
            db_url,
            SystemClock::default(),
            &notifs,
            principal_conn,
            urls,
            &site_cfg,
            lifecycle.soft_shutdown_token(),
            lifecycle.task_tracker(),
        )
        .await?;

        Ok(lifecycle.run().await)
    }
}
