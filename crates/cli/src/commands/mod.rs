use std::process::ExitCode;

use camino::Utf8PathBuf;
use clap::Parser;
use figment::Figment;
use figment::providers::{Env, Format, Yaml};

mod config;
mod database;
mod debug;
mod doctor;
mod healthcheck;
mod manage;
mod server;
mod station;
mod templates;
mod worker;

pub(super) const METRICS_BIND_ENV: &str = "COAUTH_METRICS_BIND";

#[derive(Parser, Debug)]
enum Subcommand {
    /// Configuration-related commands
    Config(self::config::Options),

    /// Manage the database
    Database(self::database::Options),

    /// Runs the web server
    Server(self::server::Options),

    /// Run the worker
    Worker(self::worker::Options),

    /// Manage the instance
    Manage(self::manage::Options),

    /// Manage Station trust enrollment
    Station(self::station::Options),

    /// Templates-related commands
    Templates(self::templates::Options),

    /// Debug utilities
    #[clap(hide = true)]
    Debug(self::debug::Options),

    /// Run diagnostics on the deployment
    Doctor(self::doctor::Options),

    /// Probe the configured `/health` endpoint and exit. Designed for
    /// Dockerfile `HEALTHCHECK` and orchestrator probes.
    Healthcheck(self::healthcheck::Options),
}

#[derive(Parser, Debug)]
#[command(version = crate::VERSION)]
pub struct Options {
    /// Path to the configuration file
    #[arg(short, long, global = true, action = clap::ArgAction::Append)]
    config: Vec<Utf8PathBuf>,

    /// Ignore ambient COAUTH_* variables when explicit config files are used
    #[arg(long, global = true)]
    no_env_overrides: bool,

    /// Enable debug-only cotest endpoints
    #[arg(long, global = true)]
    enable_test_endpoints: bool,

    /// Enable the global development posture and detailed diagnostics
    #[arg(long, global = true)]
    development_mode: bool,

    /// Confirm that the configured in-band email verification bypass is intentional
    #[arg(long, global = true)]
    allow_insecure_dev_email_bypass: bool,

    /// Confirm that the configured password bootstrap flow is intentional
    #[arg(long, global = true)]
    allow_insecure_password_bootstrap: bool,

    /// Debug/test only: allow outbound plain HTTP to loopback services
    #[arg(long, global = true)]
    allow_insecure_loopback_http: bool,

    #[command(subcommand)]
    subcommand: Option<Subcommand>,
}

impl Options {
    pub(super) fn has_explicit_config(&self) -> bool {
        !self.config.is_empty()
    }

    pub(super) fn runtime_environment_policy(&self) -> coauth_config::RuntimeEnvironmentPolicy {
        let mut policy = coauth_config::RuntimeEnvironmentPolicy::new(
            self.has_explicit_config() && self.no_env_overrides,
        );
        for (key, enabled) in [
            ("COAUTH_DEVELOPMENT_MODE", self.development_mode),
            ("COAUTH_ENABLE_TEST_ENDPOINTS", self.enable_test_endpoints),
            (
                "COAUTH_ALLOW_INSECURE_DEV_EMAIL_BYPASS",
                self.allow_insecure_dev_email_bypass,
            ),
            (
                "COAUTH_ALLOW_INSECURE_PASSWORD_BOOTSTRAP",
                self.allow_insecure_password_bootstrap,
            ),
            (
                "COAUTH_ALLOW_INSECURE_LOOPBACK_HTTP",
                self.allow_insecure_loopback_http,
            ),
        ] {
            if enabled {
                policy = policy.with_override(key, "1");
            }
        }
        policy
    }

    pub(super) fn runs_server(&self) -> bool {
        matches!(&self.subcommand, Some(Subcommand::Server(_)) | None)
    }

    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as S;
        // We Box the futures for each subcommand so that we avoid this function being
        // big on the stack all the time
        match self.subcommand {
            Some(S::Config(c)) => Box::pin(c.run(figment)).await,
            Some(S::Database(c)) => Box::pin(c.run(figment)).await,
            Some(S::Server(c)) => Box::pin(c.run(figment)).await,
            Some(S::Worker(c)) => Box::pin(c.run(figment)).await,
            Some(S::Manage(c)) => Box::pin(c.run(figment)).await,
            Some(S::Station(c)) => Box::pin(c.run(figment)).await,
            Some(S::Templates(c)) => Box::pin(c.run(figment)).await,
            Some(S::Debug(c)) => Box::pin(c.run(figment)).await,
            Some(S::Doctor(c)) => Box::pin(c.run(figment)).await,
            Some(S::Healthcheck(c)) => Box::pin(c.run(figment)).await,
            None => Box::pin(self::server::Options::default().run(figment)).await,
        }
    }

    /// Get a [`Figment`] instance with the configuration loaded
    pub fn figment(&self) -> Figment {
        let configs = if self.config.is_empty() {
            coauth_config::runtime_var("COAUTH_CONFIG")
                .unwrap_or_else(|_| "config.yaml".to_owned())
                .split(':')
                .map(Utf8PathBuf::from)
                .collect()
        } else {
            self.config.clone()
        };

        let explicit_config = self.has_explicit_config();
        let base = if explicit_config {
            Figment::new()
        } else {
            Figment::new().merge(Env::prefixed("COAUTH_").split("__"))
        };
        let figment = configs
            .into_iter()
            .fold(base, |f, path| f.admerge(Yaml::file(path)));

        if explicit_config && !self.no_env_overrides {
            figment.merge(Env::prefixed("COAUTH_").split("__"))
        } else {
            figment
        }
    }
}
