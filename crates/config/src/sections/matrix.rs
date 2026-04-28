use anyhow::bail;
use camino::Utf8PathBuf;
use rand_core::RngCore as Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_HOMESERVER: &str = "localhost:8008";
const DEFAULT_ENDPOINT: &str = "http://localhost:8008/";

fn homeserver_fallback() -> String {
    DEFAULT_HOMESERVER.to_owned()
}

fn endpoint_fallback() -> Url {
    Url::parse(DEFAULT_ENDPOINT).unwrap()
}

// ---------------------------------------------------------------------------
// Homeserver variant
// ---------------------------------------------------------------------------

/// Variant of the Matrix homeserver backing this deployment
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum HomeserverKind {
    /// Full read-write integration with Palpo
    #[default]
    Palpo,
    /// Read-only mode against Palpo (safe for rolling-out evaluations)
    PalpoReadOnly,
    /// Palpo using the newer (modern) admin API surface
    PalpoModern,
}

// ---------------------------------------------------------------------------
// Shared secret helper
// ---------------------------------------------------------------------------

/// A shared secret that can be stored inline or referenced via an external file
#[derive(Clone, Debug)]
pub enum Secret {
    File(Utf8PathBuf),
    Value(String),
}

/// Wire representation for [`Secret`] (two mutually-exclusive fields)
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
struct SecretRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
}

impl TryFrom<SecretRaw> for Secret {
    type Error = anyhow::Error;

    fn try_from(raw: SecretRaw) -> Result<Self, Self::Error> {
        match (raw.secret, raw.secret_file) {
            (Some(v), None) => Ok(Self::Value(v)),
            (None, Some(p)) => Ok(Self::File(p)),
            (None, None) => bail!("Missing `secret` or `secret_file`"),
            (Some(_), Some(_)) => bail!("Cannot specify both `secret` and `secret_file`"),
        }
    }
}

impl From<Secret> for SecretRaw {
    fn from(s: Secret) -> Self {
        match s {
            Secret::Value(v) => Self {
                secret: Some(v),
                secret_file: None,
            },
            Secret::File(p) => Self {
                secret: None,
                secret_file: Some(p),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// MatrixConfig
// ---------------------------------------------------------------------------

/// Connection details for the Matrix homeserver
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatrixConfig {
    /// Which homeserver variant is running
    #[serde(default)]
    pub kind: HomeserverKind,

    /// The Matrix server name (e.g. `matrix.example.com:8448`)
    #[serde(default = "homeserver_fallback")]
    pub homeserver: String,

    /// Shared admin-API secret (inline value or path to a file)
    #[schemars(with = "SecretRaw")]
    #[serde_as(as = "serde_with::TryFromInto<SecretRaw>")]
    #[serde(flatten)]
    pub secret: Secret,

    /// Base URL of the homeserver's client-server API
    #[serde(default = "endpoint_fallback")]
    pub endpoint: Url,
}

impl ConfigurationSection for MatrixConfig {
    const PATH: &'static str = "matrix";
}

impl MatrixConfig {
    /// Resolve the shared secret, reading from disk when a file path was
    /// configured.
    ///
    /// File contents are trimmed to stay compatible with Palpo's behaviour.
    ///
    /// # Errors
    ///
    /// Returns an error if the referenced file cannot be read.
    pub async fn secret(&self) -> anyhow::Result<String> {
        match &self.secret {
            Secret::Value(v) => Ok(v.clone()),
            Secret::File(path) => {
                let raw = tokio::fs::read_to_string(path).await?;
                Ok(raw.trim().to_string())
            }
        }
    }

    pub(crate) fn generate<R>(mut rng: R) -> Self
    where
        R: Rng + Send,
    {
        Self {
            kind: HomeserverKind::default(),
            homeserver: homeserver_fallback(),
            secret: Secret::Value({
                const CHARSET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                bytes
                    .iter()
                    .map(|b| CHARSET[*b as usize % CHARSET.len()] as char)
                    .collect()
            }),
            endpoint: endpoint_fallback(),
        }
    }

    pub(crate) fn test() -> Self {
        Self {
            kind: HomeserverKind::default(),
            homeserver: homeserver_fallback(),
            secret: Secret::Value("test".to_owned()),
            endpoint: endpoint_fallback(),
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use tokio::{runtime::Handle, task};

    use super::*;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r"
                        matrix:
                          homeserver: matrix.org
                          secret_file: secret
                    ",
                )?;
                jail.create_file("secret", r"m472!x53c237")?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<MatrixConfig>("matrix")?;

                Handle::current().block_on(async move {
                    assert_eq!(&config.homeserver, "matrix.org");
                    assert!(matches!(config.secret, Secret::File(ref p) if p == "secret"));
                    assert_eq!(config.secret().await.unwrap(), "m472!x53c237");
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_config_inline_secrets() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r"
                        matrix:
                          homeserver: matrix.org
                          secret: m472!x53c237
                    ",
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<MatrixConfig>("matrix")?;

                Handle::current().block_on(async move {
                    assert_eq!(&config.homeserver, "matrix.org");
                    assert!(matches!(config.secret, Secret::Value(ref v) if v == "m472!x53c237"));
                    assert_eq!(config.secret().await.unwrap(), "m472!x53c237");
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }
}
