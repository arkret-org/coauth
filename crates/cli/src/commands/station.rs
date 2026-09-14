//! Station trust enrollment commands
//!
//! Explicit high-risk replacement and revocation of persisted Station
//! authorization pins. The endpoint, egress, TLS
//! and Provider settings all come from the same configuration the server
//! uses, so operators never re-enter a second, drift-prone URL set.

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use coauth_backend::util::diesel_pool_from_config;
use coauth_config::{AppConfig, ConfigurationSection, StationConfig};
use coauth_storage_postgres::PgRepositoryFactory;
use figment::Figment;
use tracing::{info, info_span};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Manage Station trust enrollment
    Trust(TrustOptions),
}

#[derive(Parser, Debug)]
struct TrustOptions {
    #[command(subcommand)]
    subcommand: TrustSubcommand,
}

#[derive(Parser, Debug)]
enum TrustSubcommand {
    /// Explicitly replace an enrolled pin after a legitimate identity genesis
    Replace(ReplaceOptions),
    /// Revoke an enrolled pin
    Revoke(RevokeOptions),
}

#[derive(Parser, Debug)]
struct ReplaceOptions {
    /// Name of the enrolled `arkret.stations[]` entry
    #[arg(long)]
    name: String,

    /// The currently enrolled `service_id`. The replacement only applies when
    /// the stored pin still equals this value (compare-and-swap).
    #[arg(long)]
    expect_old: String,

    /// Assert the expected new identity: after online verification the
    /// verified `service_id` must equal this value exactly.
    #[arg(long)]
    accept_new: Option<String>,
}

#[derive(Parser, Debug)]
struct RevokeOptions {
    /// Name of the enrolled `arkret.stations[]` entry
    #[arg(long)]
    name: String,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.station").entered();
        match self.subcommand {
            Subcommand::Trust(options) => options.run(figment).await,
        }
    }
}

struct CommandContext {
    server: StationConfig,
    repository_factory: PgRepositoryFactory,
    http_client: reqwest::Client,
}

impl TrustOptions {
    async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        match &self.subcommand {
            TrustSubcommand::Replace(options) => {
                let context = load_context(figment, &options.name).await?;
                let expect_old = arkret_identifiers::DidCoreId::new(options.expect_old.clone())
                    .context("--expect-old must be a valid did_core id")?;
                let accept_new = options
                    .accept_new
                    .as_ref()
                    .map(|value| {
                        arkret_identifiers::DidCoreId::new(value.clone())
                            .context("--accept-new must be a valid did_core id")
                    })
                    .transpose()?;
                let outcome = coauth_backend::services::station_trust::replace(
                    &context.repository_factory,
                    &context.http_client,
                    &context.server,
                    &expect_old,
                    accept_new.as_ref(),
                )
                .await
                .context("station trust replace failed")?;
                print_summary(serde_json::json!({
                    "action": "replaced",
                    "name": outcome.enrollment.name,
                    "canonical_endpoint": outcome.enrollment.canonical_endpoint,
                    "service_id": outcome.enrollment.service_id.as_str(),
                    "previous_service_id": expect_old.as_str(),
                    "revoked_session_grants": outcome.revoked_session_grants,
                }));
            }
            TrustSubcommand::Revoke(options) => {
                let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
                let pool = diesel_pool_from_config(&config.database).await?;
                let repository_factory = PgRepositoryFactory::new(pool);
                let revoked = coauth_backend::services::station_trust::revoke(
                    &repository_factory,
                    &options.name,
                )
                .await
                .context("station trust revoke failed")?;
                print_summary(serde_json::json!({
                    "action": if revoked { "revoked" } else { "unchanged" },
                    "name": options.name,
                }));
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}

/// Load the configuration, find the named Station entry, and build
/// the same database pool and egress-controlled HTTP client the server uses.
async fn load_context(figment: &Figment, name: &str) -> anyhow::Result<CommandContext> {
    let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
    let server = config
        .arkret
        .stations
        .iter()
        .find(|server| server.name == name)
        .cloned()
        .with_context(|| {
            format!("no `arkret.stations[]` entry named {name:?} in the configuration")
        })?;
    let pool = diesel_pool_from_config(&config.database).await?;
    let http_client = coauth_backend::reqwest_client_for_server(
        &config.arkret,
        &config.http.public_base_url,
        config.http.issuer.as_ref(),
    );
    Ok(CommandContext {
        server,
        repository_factory: PgRepositoryFactory::new(pool),
        http_client,
    })
}

/// Print the stable, machine-parseable summary. It only carries public
/// identity material — never bearer tokens, private keys or raw evidence.
fn print_summary(summary: serde_json::Value) {
    let rendered = serde_json::to_string(&summary).expect("summary serialization cannot fail");
    info!(%rendered, "station trust operation completed");
    println!("{rendered}");
}
