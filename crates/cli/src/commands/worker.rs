use std::{process::ExitCode, time::Duration};

use clap::Parser;
use figment::Figment;
use coauth_backend::{
    lifecycle::LifecycleManager,
    util::{
        database_url_from_config, diesel_pool_from_config, homeserver_connection_from_config,
        notification_center_from_config, site_config_from_config, templates_from_config,
        test_mailer_in_background,
    },
};
use coauth_config::{AppConfig, ConfigurationSection};
use coauth_data::{PgRepositoryFactory, SystemClock, UrlBuilder};
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
            &app_cfg.matrix,
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

        // ── Homeserver connection ───────────────────────────────────────
        let http = coauth_backend::reqwest_client();
        let (hs_conn, _registry) = homeserver_connection_from_config(&app_cfg.matrix, http).await?;

        drop(app_cfg);

        // ── Start the scheduler ─────────────────────────────────────────
        info!("Starting task scheduler");
        coauth_tasks::init_and_run(
            PgRepositoryFactory::new(db_pool.clone()),
            db_url,
            SystemClock::default(),
            &notifs,
            hs_conn,
            urls,
            &site_cfg,
            lifecycle.soft_shutdown_token(),
            lifecycle.task_tracker(),
        )
        .await?;

        Ok(lifecycle.run().await)
    }
}
