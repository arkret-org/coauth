use std::process::ExitCode;

use clap::Parser;
use coauth_backend::util::{
    diesel_pool_from_config, load_policy_factory_dynamic_data, policy_factory_from_config,
};
use coauth_config::{
    ConfigurationSection, ConfigurationSectionExt, DatabaseConfig, ExperimentalConfig,
    MatrixConfig, PolicyConfig,
};
use coauth_data::PgRepositoryFactory;
use figment::Figment;
use tracing::{info, info_span};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Verify that policy files compile correctly
    Policy {
        /// Also load dynamic data from the database before compiling
        #[arg(long)]
        with_dynamic_data: bool,
    },
}

impl Options {
    #[tracing::instrument(skip_all)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let Subcommand::Policy {
            with_dynamic_data: load_dynamic,
        } = self.subcommand;

        let _span = info_span!("cli.debug.policy").entered();

        let pol_cfg =
            PolicyConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let mtx_cfg = MatrixConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let exp_cfg = ExperimentalConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        info!("Loading and compiling the policy module");
        let factory = policy_factory_from_config(&pol_cfg, &mtx_cfg, &exp_cfg).await?;

        if load_dynamic {
            let db_cfg = DatabaseConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
            let pool = diesel_pool_from_config(&db_cfg).await?;
            let repo_factory = PgRepositoryFactory::new(pool);
            load_policy_factory_dynamic_data(&factory, &repo_factory).await?;
        }

        let _compiled = factory.instantiate().await?;

        Ok(ExitCode::SUCCESS)
    }
}
