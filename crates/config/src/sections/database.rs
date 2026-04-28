use std::{num::NonZeroU32, time::Duration};

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;
use crate::schema;

// ---------------------------------------------------------------------------
// Pool-tuning defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_CONNS: u32 = 10;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 10 * 60;
const DEFAULT_MAX_LIFETIME_SECS: u64 = 30 * 60;

#[allow(clippy::unnecessary_wraps)]
fn fallback_uri() -> Option<String> {
    Some("postgresql://".to_owned())
}

fn pool_max_connections() -> NonZeroU32 {
    NonZeroU32::new(DEFAULT_MAX_CONNS).unwrap()
}

fn pool_connect_timeout() -> Duration {
    Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)
}

#[allow(clippy::unnecessary_wraps)]
fn pool_idle_timeout() -> Option<Duration> {
    Some(Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS))
}

#[allow(clippy::unnecessary_wraps)]
fn pool_max_lifetime() -> Option<Duration> {
    Some(Duration::from_secs(DEFAULT_MAX_LIFETIME_SECS))
}

// ---------------------------------------------------------------------------
// SSL mode
// ---------------------------------------------------------------------------

/// PostgreSQL wire-encryption behaviour
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PgSslMode {
    /// Never attempt SSL
    Disable,
    /// Try plaintext first, fall back to SSL
    Allow,
    /// Try SSL first, fall back to plaintext
    Prefer,
    /// Require SSL; optionally verify the CA when a root cert is present
    Require,
    /// Require SSL and verify the server certificate against the CA
    VerifyCa,
    /// Require SSL, verify CA, and confirm the hostname matches the cert
    VerifyFull,
}

// ---------------------------------------------------------------------------
// Main config struct
// ---------------------------------------------------------------------------

/// PostgreSQL connection and pool settings
#[serde_as]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    // -- Connection target (URI *or* split fields) --
    /// Full connection URI. Mutually exclusive with `host`/`port`/`socket`/
    /// `username`/`password`/`database`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "fallback_uri")]
    pub uri: Option<String>,

    /// Server hostname (not allowed when `uri` is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option::<schema::Hostname>")]
    pub host: Option<String>,

    /// Server port (not allowed when `uri` is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: Option<u16>,

    /// UNIX socket directory (not allowed when `uri` is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub socket: Option<Utf8PathBuf>,

    /// PostgreSQL role (not allowed when `uri` is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Role password (not allowed when `uri` is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Target database name (not allowed when `uri` is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,

    // -- SSL --
    /// Wire-encryption policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_mode: Option<PgSslMode>,

    /// PEM root CA certificate (inline). Mutually exclusive with `ssl_ca_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_ca: Option<String>,

    /// Path to root CA certificate. Mutually exclusive with `ssl_ca`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub ssl_ca_file: Option<Utf8PathBuf>,

    /// PEM client certificate (inline). Mutually exclusive with
    /// `ssl_certificate_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_certificate: Option<String>,

    /// Path to client certificate. Mutually exclusive with `ssl_certificate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub ssl_certificate_file: Option<Utf8PathBuf>,

    /// PEM client key (inline). Mutually exclusive with `ssl_key_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_key: Option<String>,

    /// Path to client key. Mutually exclusive with `ssl_key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub ssl_key_file: Option<Utf8PathBuf>,

    // -- Pool parameters --
    /// Upper bound on pool connections
    #[serde(default = "pool_max_connections")]
    pub max_connections: NonZeroU32,

    /// Lower bound on pool connections (kept warm)
    #[serde(default)]
    pub min_connections: u32,

    /// Per-connection establishment timeout (seconds)
    #[schemars(with = "u64")]
    #[serde(default = "pool_connect_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    pub connect_timeout: Duration,

    /// Recycle idle connections after this many seconds
    #[schemars(with = "Option<u64>")]
    #[serde(default = "pool_idle_timeout", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub idle_timeout: Option<Duration>,

    /// Hard upper bound on connection age (seconds)
    #[schemars(with = "u64")]
    #[serde(default = "pool_max_lifetime", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub max_lifetime: Option<Duration>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            uri: fallback_uri(),
            host: None,
            port: None,
            socket: None,
            username: None,
            password: None,
            database: None,
            ssl_mode: None,
            ssl_ca: None,
            ssl_ca_file: None,
            ssl_certificate: None,
            ssl_certificate_file: None,
            ssl_key: None,
            ssl_key_file: None,
            max_connections: pool_max_connections(),
            min_connections: 0,
            connect_timeout: pool_connect_timeout(),
            idle_timeout: pool_idle_timeout(),
            max_lifetime: pool_max_lifetime(),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Produce a fully-annotated `figment::Error` scoped to the database section
fn scoped_error(figment: &figment::Figment, message: &str) -> figment::Error {
    let mut err = figment::Error::from(message.to_owned());
    err.metadata = figment.find_metadata(DatabaseConfig::PATH).cloned();
    err.profile = Some(figment::Profile::Default);
    err.path = vec![DatabaseConfig::PATH.to_owned()];
    err
}

/// Assert that at most one of two optional fields is set
fn assert_exclusive(
    a: bool,
    b: bool,
    label_a: &str,
    label_b: &str,
    figment: &figment::Figment,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    if a && b {
        Err(scoped_error(
            figment,
            &format!("{label_a} must not be specified if {label_b} is specified"),
        )
        .into())
    } else {
        Ok(())
    }
}

impl ConfigurationSection for DatabaseConfig {
    const PATH: &'static str = "database";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // URI vs. split-field exclusivity
        let uses_split = self.host.is_some()
            || self.port.is_some()
            || self.socket.is_some()
            || self.username.is_some()
            || self.password.is_some()
            || self.database.is_some();

        if self.uri.is_some() && uses_split {
            return Err(scoped_error(
                figment,
                "uri must not be specified if host, port, socket, username, password, or database are specified",
            ).into());
        }

        // SSL mutual exclusions
        assert_exclusive(
            self.ssl_ca.is_some(),
            self.ssl_ca_file.is_some(),
            "ssl_ca",
            "ssl_ca_file",
            figment,
        )?;
        assert_exclusive(
            self.ssl_certificate.is_some(),
            self.ssl_certificate_file.is_some(),
            "ssl_certificate",
            "ssl_certificate_file",
            figment,
        )?;
        assert_exclusive(
            self.ssl_key.is_some(),
            self.ssl_key_file.is_some(),
            "ssl_key",
            "ssl_key_file",
            figment,
        )?;

        // Key and certificate must both be present or both absent
        let has_key = self.ssl_key.is_some() || self.ssl_key_file.is_some();
        let has_cert = self.ssl_certificate.is_some() || self.ssl_certificate_file.is_some();
        if has_key ^ has_cert {
            return Err(scoped_error(
                figment,
                "both a ssl_certificate and a ssl_key must be set at the same time or none of them",
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    database:
                      uri: postgresql://user:password@host/database
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<DatabaseConfig>("database")?;

            assert_eq!(
                config.uri.as_deref(),
                Some("postgresql://user:password@host/database")
            );

            Ok(())
        });
    }
}
