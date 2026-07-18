use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use coauth_backend::util::{database_url_from_config, diesel_pool_from_config};
use coauth_config::{ConfigurationSectionExt, DatabaseConfig};
use figment::Figment;
use tracing::info_span;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Run database migrations
    Migrate,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.database.migrate").entered();
        let config =
            DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let db_url = database_url_from_config(&config)?;
        let pool = diesel_pool_from_config(&config).await?;

        // Run pending migrations
        coauth_storage_postgres::migrate(&pool, &db_url)
            .await
            .context("could not run migrations")?;

        Ok(ExitCode::SUCCESS)
    }
}
