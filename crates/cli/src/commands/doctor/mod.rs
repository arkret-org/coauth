//! Deployment health-check diagnostics
//!
//! Validates connectivity to the homeserver, well-known document discovery,
//! and Pasion API integration.  Run with `coauth doctor` while both Pasion
//! and Palpo are active and using the same configuration.

mod homeserver;
mod well_known;

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use coauth_config::{ConfigurationSection, RootConfig};
use figment::Figment;
use tracing::{info, info_span, warn};
use url::Host;

/// Documentation base URL for links in diagnostic messages
const DOCS_BASE: &str = "https://palpo-im.github.io/coauth";

#[derive(Parser, Debug)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.doctor").entered();
        info!(
            "Running diagnostics -- ensure both Pasion and Palpo are running \
             and that Pasion is using the same configuration files as this tool."
        );

        let config = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        let http = coauth_backend::reqwest_client();
        let public_base = config.http.public_base.as_str();
        let resolved_issuer = config
            .http
            .issuer
            .as_ref()
            .map(url::Url::as_str)
            .unwrap_or(public_base);

        let domain: Host = Host::parse(&config.matrix.homeserver).context(
            "The homeserver host in the config (`matrix.homeserver`) is not a valid domain.\n\
             See {DOCS_BASE}/setup/homeserver.html",
        )?;
        let shared_secret = config.matrix.secret().await?;
        let hs_endpoint = config.matrix.endpoint;

        if !resolved_issuer.starts_with("https://") {
            warn!(
                "The issuer (`http.issuer`/`http.public_base`) is not an HTTPS URL. \
                 Some clients will refuse to use it."
            );
        }

        // 1. Well-known discovery
        let _discovered_cs_api =
            well_known::check_well_known(&http, &domain, resolved_issuer, public_base).await;

        // 2. Homeserver reachability
        let reachable = homeserver::verify_reachability(&http, &hs_endpoint, &domain).await;

        if reachable {
            // 3. Token validation round-trip
            homeserver::check_whoami(&http, &hs_endpoint, resolved_issuer).await;

            // 4. Authenticated Pasion API probe
            homeserver::check_coauth_api(
                &http,
                &hs_endpoint,
                &shared_secret,
                resolved_issuer,
                &domain,
            )
            .await;
        }

        Ok(ExitCode::SUCCESS)
    }
}
