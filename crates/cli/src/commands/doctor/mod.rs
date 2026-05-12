//! Deployment health-check diagnostics
//!
//! Validates Contrix/OIDC discovery surfaces exposed by the coauth server.

use std::process::ExitCode;

use clap::Parser;
use coauth_config::{ConfigurationSection, RootConfig};
use figment::Figment;
use tracing::{error, info, info_span, warn};
use url::Url;

#[derive(Parser, Debug)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.doctor").entered();
        info!("Running Contrix auth server diagnostics.");

        let config = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        let http = coauth_backend::reqwest_client();
        let public_base = &config.http.public_base;
        let resolved_issuer = config
            .http
            .issuer
            .as_ref()
            .map(url::Url::as_str)
            .unwrap_or_else(|| public_base.as_str());

        if !resolved_issuer.starts_with("https://") {
            warn!(
                "The issuer (`http.issuer`/`http.public_base`) is not an HTTPS URL. \
                 Some clients will refuse to use it."
            );
        }

        if config.contrix.principal_servers.is_empty() {
            warn!(
                "No Contrix principal servers are configured (`contrix.principal_servers` is empty)."
            );
        } else {
            for server in &config.contrix.principal_servers {
                info!(
                    name = %server.name,
                    audience = %server.audience,
                    endpoint = %server.endpoint,
                    "Configured Contrix principal server"
                );
            }
        }

        check_openid_discovery(&http, public_base, resolved_issuer).await;
        check_contrix_server_describe(&http, public_base).await;

        Ok(ExitCode::SUCCESS)
    }
}

async fn check_openid_discovery(http: &reqwest::Client, public_base: &Url, issuer: &str) {
    let url = match public_base.join("/.well-known/openid-configuration") {
        Ok(url) => url,
        Err(error) => {
            error!(%error, "Unable to construct OpenID discovery URL");
            return;
        }
    };

    let response = match http.get(url.as_str()).send().await {
        Ok(response) => response,
        Err(error) => {
            warn!(%url, %error, "Could not fetch OpenID discovery document");
            return;
        }
    };

    if !response.status().is_success() {
        warn!(
            %url,
            status = %response.status(),
            "OpenID discovery endpoint did not return success"
        );
        return;
    }

    let body: serde_json::Value = match response.json().await {
        Ok(body) => body,
        Err(error) => {
            warn!(%url, %error, "OpenID discovery document is not valid JSON");
            return;
        }
    };

    match body.get("issuer").and_then(|value| value.as_str()) {
        Some(found) if found == issuer => {
            info!(%url, "OpenID discovery issuer matches configuration");
        }
        Some(found) => {
            warn!(
                %url,
                expected = %issuer,
                actual = %found,
                "OpenID discovery issuer does not match configuration"
            );
        }
        None => {
            warn!(%url, "OpenID discovery document does not contain an issuer");
        }
    }
}

async fn check_contrix_server_describe(http: &reqwest::Client, public_base: &Url) {
    let url = match public_base.join("/api/v1/server/describe") {
        Ok(url) => url,
        Err(error) => {
            error!(%error, "Unable to construct Contrix server description URL");
            return;
        }
    };

    match http.get(url.as_str()).send().await {
        Ok(response) if response.status().is_success() => {
            info!(%url, "Contrix server description endpoint is reachable");
        }
        Ok(response) => {
            warn!(
                %url,
                status = %response.status(),
                "Contrix server description endpoint did not return success"
            );
        }
        Err(error) => {
            warn!(%url, %error, "Could not fetch Contrix server description");
        }
    }
}
