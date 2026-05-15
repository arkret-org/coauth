//! `coauth healthcheck` — operator-grade liveness probe.
//!
//! Issues a single HTTP GET against the configured `/health` endpoint
//! and exits 0 on `200 OK`. Designed for the Dockerfile `HEALTHCHECK`
//! and orchestrator probes that cannot reach the network themselves
//! (the distroless image ships no `curl`).
//
// Healthcheck binary doesn't pull in the outbound-http tracing layer.
#![allow(clippy::disallowed_methods)]

use std::{net::ToSocketAddrs, process::ExitCode, time::Duration};

use clap::Parser;
use coauth_config::{
    AppConfig, ConfigurationSection, HttpBindConfig, HttpListenerConfig, HttpResource,
};
use figment::Figment;
use tracing::{info, warn};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Override the URL to probe. Defaults to the first listener that
    /// exposes the `health` resource.
    #[arg(long)]
    url: Option<String>,

    /// Per-attempt timeout, in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u64,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let url = if let Some(url) = self.url { url } else {
            let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
            derive_health_url(&config.http.listeners).ok_or_else(|| {
                anyhow::anyhow!(
                    "no listener exposes the `health` resource; pass --url explicitly"
                )
            })?
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                info!(url = %url, status = %response.status(), "health probe ok");
                Ok(ExitCode::SUCCESS)
            }
            Ok(response) => {
                warn!(url = %url, status = %response.status(), "health probe failed");
                Ok(ExitCode::FAILURE)
            }
            Err(error) => {
                warn!(url = %url, error = %error, "health probe transport error");
                Ok(ExitCode::FAILURE)
            }
        }
    }
}

/// Pick the first listener that exposes the `health` resource and
/// derive a probe URL pointing at `127.0.0.1:<port>/health`. Returns
/// `None` if no such listener exists.
fn derive_health_url(listeners: &[HttpListenerConfig]) -> Option<String> {
    listeners
        .iter()
        .find(|listener| {
            listener
                .resources
                .iter()
                .any(|resource| matches!(resource, HttpResource::Health))
        })
        .and_then(|listener| listener.binds.iter().find_map(bind_to_local_url))
}

/// Convert a [`HttpBindConfig`] to a loopback probe URL.
///
/// We always probe loopback because the healthcheck runs co-located
/// with the server. Extracting the configured port avoids assumptions
/// about the default and survives operator port overrides.
fn bind_to_local_url(bind: &HttpBindConfig) -> Option<String> {
    match bind {
        HttpBindConfig::Listen { port, .. } => Some(format!("http://127.0.0.1:{port}/health")),
        HttpBindConfig::Address { address } => {
            // Resolve the configured socket address to extract the port,
            // then probe loopback on that port. Wildcard binds
            // (e.g. `[::]:8091`) become `127.0.0.1:8091`.
            let port = address.to_socket_addrs().ok()?.next()?.port();
            Some(format!("http://127.0.0.1:{port}/health"))
        }
        // Unix and file-descriptor binds aren't probeable from outside
        // the process; require an explicit `--url`.
        _ => None,
    }
}
