use std::process::ExitCode;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use coauth_backend::util::{database_url_from_config, diesel_pool_from_config};
use coauth_config::{ConfigurationSection, RootConfig, SyncConfig};
use coauth_data::SystemClock;
use figment::Figment;
use rand_core::SeedableRng;
use tokio::io::AsyncWriteExt;
use tracing::{info, info_span};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Dump the current configuration as YAML
    Dump {
        /// Destination file path; defaults to stdout when omitted
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,
    },

    /// Validate the configuration file
    Check,

    /// Produce a fresh configuration file with generated secrets
    Generate {
        /// Destination file path; defaults to stdout when omitted
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,
    },

    /// Synchronise clients and providers from the config into the database
    Sync {
        /// Remove database entries that are no longer present in the config
        #[clap(long)]
        prune: bool,

        /// Preview changes without writing to the database
        #[clap(long)]
        dry_run: bool,
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        match self.subcommand {
            Subcommand::Dump { output } => Self::handle_dump(figment, output).await,
            Subcommand::Check => Self::handle_check(figment),
            Subcommand::Generate { output } => Self::handle_generate(figment, output).await,
            Subcommand::Sync { prune, dry_run } => Self::handle_sync(figment, prune, dry_run).await,
        }
    }

    async fn handle_dump(figment: &Figment, dest: Option<Utf8PathBuf>) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.dump").entered();

        let root = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let yaml = serde_yaml::to_string(&root)?;

        write_output(&yaml, dest.as_deref()).await?;
        Ok(ExitCode::SUCCESS)
    }

    fn handle_check(figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.check").entered();

        let _validated = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        info!("Configuration file looks good");

        Ok(ExitCode::SUCCESS)
    }

    async fn handle_generate(
        _figment: &Figment,
        dest: Option<Utf8PathBuf>,
    ) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.generate").entered();

        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let generated = RootConfig::generate(&mut rng).await?;
        let yaml = serde_yaml::to_string(&generated)?;

        write_output(&yaml, dest.as_deref()).await?;
        Ok(ExitCode::SUCCESS)
    }

    async fn handle_sync(
        figment: &Figment,
        prune: bool,
        dry_run: bool,
    ) -> anyhow::Result<ExitCode> {
        let cfg = SyncConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let clock = SystemClock::default();
        let encrypter = cfg.secrets.encrypter().await?;

        let db_url = database_url_from_config(&cfg.database)?;
        let pool = diesel_pool_from_config(&cfg.database).await?;

        coauth_data::migrate(&pool, &db_url)
            .await
            .context("could not run migrations")?;

        let conn = pool
            .get()
            .await
            .context("could not get connection from pool")?;

        coauth_backend::sync::config_sync(
            cfg.upstream_oauth2,
            cfg.clients,
            conn,
            &encrypter,
            &clock,
            prune,
            dry_run,
        )
        .await
        .context("could not sync the configuration with the database")?;

        Ok(ExitCode::SUCCESS)
    }
}

/// Write `content` to the given file path, or to stdout when no path is given.
async fn write_output(content: &str, dest: Option<&camino::Utf8Path>) -> anyhow::Result<()> {
    if let Some(path) = dest {
        info!("Writing configuration to {path:?}");
        let mut file = tokio::fs::File::create(path.as_std_path()).await?;
        file.write_all(content.as_bytes()).await?;
    } else {
        info!("Writing configuration to standard output");
        tokio::io::stdout().write_all(content.as_bytes()).await?;
    }
    Ok(())
}
