use std::process::ExitCode;

use anyhow::Context;
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand};
use coauth_backend::util::{database_url_from_config, diesel_pool_from_config};
use coauth_config::{
    ConfigurationSection, IdentityRegistryConfig, PrincipalServerConfig, RootConfig, SyncConfig,
};
use coauth_data::SystemClock;
use figment::Figment;
use rand_core::SeedableRng;
use tokio::io::AsyncWriteExt;
use tracing::{info, info_span};
use url::Url;

const DEV_DATABASE_URI: &str = "postgresql://coauth:coauth@localhost/coauth";
const DEV_PUBLIC_BASE: &str = "https://auth.local.host/";
const DEV_SOLAND_URL: &str = "https://local.host/";
const DEV_SOLAND_IDENTITY_RESOLVER_URL: &str = "https://local.host/_arkret/root/identity/resolve";
const DEV_SOLAND_SESSION_GRANT_BEARER: &str = "local-coauth-session-grant-introspection";
const DEV_SOLAND_WEBVH_REGISTRATION_BEARER: &str = "local-soland-webvh-registration";

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Dump the current configuration as YAML
    Dump {
        /// Destination file path; defaults to stdout when omitted
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,
    },

    /// Validate the configuration file
    Check,

    /// Produce a fresh configuration file with generated secrets
    Generate(GenerateOptions),

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

#[derive(Args, Debug)]
struct GenerateOptions {
    /// Destination file path; defaults to stdout when omitted
    #[clap(short, long)]
    output: Option<Utf8PathBuf>,

    /// Generate a local development config that can pass fail-closed validation
    #[clap(long)]
    dev: bool,

    /// Override http.public_base_url and http.issuer in the generated config
    #[clap(long)]
    public_base_url: Option<Url>,

    /// Override database.uri in the generated config
    #[clap(long)]
    database_url: Option<String>,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Dump { output } => Self::handle_dump(figment, output).await,
            Command::Check => Self::handle_check(figment),
            Command::Generate(options) => Self::handle_generate(options).await,
            Command::Sync { prune, dry_run } => Self::handle_sync(figment, prune, dry_run).await,
        }
    }

    async fn handle_dump(figment: &Figment, dest: Option<Utf8PathBuf>) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.dump").entered();

        let root = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let yaml = serde_yaml_ng::to_string(&root)?;

        write_output(&yaml, dest.as_deref()).await?;
        Ok(ExitCode::SUCCESS)
    }

    fn handle_check(figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.check").entered();

        let _validated = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        info!("Configuration file looks good");

        Ok(ExitCode::SUCCESS)
    }

    async fn handle_generate(options: GenerateOptions) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.config.generate").entered();

        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let mut generated = RootConfig::generate(&mut rng).await?;
        apply_generated_config_options(&mut generated, &options)?;
        let yaml = serde_yaml_ng::to_string(&generated)?;

        write_output(&yaml, options.output.as_deref()).await?;
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

        coauth_storage_postgres::migrate(&pool, &db_url)
            .await
            .context("could not run migrations")?;

        let conn = pool
            .get()
            .await
            .context("could not get connection from pool")?;

        coauth_backend::sync::config_sync(
            cfg.upstream_oauth,
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

fn apply_generated_config_options(
    config: &mut RootConfig,
    options: &GenerateOptions,
) -> anyhow::Result<()> {
    if options.dev {
        config.database.uri = Some(
            options
                .database_url
                .clone()
                .unwrap_or_else(|| DEV_DATABASE_URI.to_owned()),
        );
        let public_base_url = options
            .public_base_url
            .clone()
            .unwrap_or_else(|| DEV_PUBLIC_BASE.parse().expect("valid dev public base"));
        config.http.public_base_url = public_base_url.clone();
        config.http.issuer = Some(public_base_url);
        config.arkret.principal_servers = vec![PrincipalServerConfig {
            name: "soland-dev".to_owned(),
            endpoint: DEV_SOLAND_URL.parse().expect("valid dev soland URL"),
            service_id: None,
            session_grant_introspection_bearer: Some(DEV_SOLAND_SESSION_GRANT_BEARER.to_owned()),
            embedded_webvh_registration_bearer: Some(
                DEV_SOLAND_WEBVH_REGISTRATION_BEARER.to_owned(),
            ),
        }];
        config.arkret.identity_registry = Some(IdentityRegistryConfig {
            resolver: DEV_SOLAND_IDENTITY_RESOLVER_URL
                .parse()
                .expect("valid dev identity resolver URL"),
            proof_required_for_pairwise: false,
        });
    } else {
        if let Some(public_base_url) = options.public_base_url.clone() {
            config.http.public_base_url = public_base_url.clone();
            config.http.issuer = Some(public_base_url);
        }
        if let Some(database_url) = options.database_url.clone() {
            config.database.uri = Some(database_url);
        }
    }

    Ok(())
}

async fn write_output(content: &str, dest: Option<&Utf8Path>) -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_dev_config_delegates_did_resolution_to_soland() {
        let mut config = RootConfig::test();
        let options = GenerateOptions {
            output: None,
            dev: true,
            public_base_url: None,
            database_url: None,
        };

        apply_generated_config_options(&mut config, &options)
            .expect("dev config options should apply");

        let principal_server = config
            .arkret
            .principal_servers
            .first()
            .expect("dev config should include Soland");
        assert_eq!(principal_server.endpoint.as_str(), DEV_SOLAND_URL);
        let serialized = serde_json::to_value(&config).expect("dev config should serialize");
        let serialized_server = &serialized["arkret"]["principal_servers"][0];
        assert!(serialized_server.get("audience").is_none());
        assert!(serialized_server.get("did").is_none());

        let registry = config
            .arkret
            .identity_registry
            .expect("dev config should include an identity resolver");
        assert_eq!(registry.resolver.as_str(), DEV_SOLAND_IDENTITY_RESOLVER_URL);
    }
}
