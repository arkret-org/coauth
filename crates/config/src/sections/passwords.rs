use anyhow::bail;
use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Minimum password strength score (zxcvbn)
const DEFAULT_MIN_COMPLEXITY: u8 = 3;

/// bcrypt cost factor used when none is specified
#[allow(clippy::unnecessary_wraps)]
fn bcrypt_cost_default() -> Option<u32> {
    Some(12)
}

// ---------------------------------------------------------------------------
// Algorithm enum
// ---------------------------------------------------------------------------

/// Supported password hashing algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// bcrypt adaptive hashing
    Bcrypt,
    /// argon2id (memory-hard)
    #[default]
    Argon2id,
    /// PBKDF2 key derivation
    Pbkdf2,
}

// ---------------------------------------------------------------------------
// HashingScheme
// ---------------------------------------------------------------------------

/// Parameters for the active password hashing algorithm
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HashingScheme {
    /// Which hashing algorithm to apply
    pub algorithm: Algorithm,

    /// bcrypt work-factor (only relevant for bcrypt)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(default = "bcrypt_cost_default")]
    pub cost: Option<u32>,

    /// Pepper secret mixed into the hash -- makes brute-force harder after a
    /// database leak
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Like `secret` but read from an external file
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub secret_file: Option<Utf8PathBuf>,
}

impl Default for HashingScheme {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::default(),
            cost: None,
            secret: None,
            secret_file: None,
        }
    }
}

// ---------------------------------------------------------------------------
// PasswordsConfig
// ---------------------------------------------------------------------------

/// Password authentication and hashing behaviour
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordsConfig {
    /// Master switch for password-based login
    #[serde(default = "default_pw_enabled")]
    pub enabled: bool,

    /// Parameters for the active password hashing algorithm
    #[serde(default)]
    pub scheme: HashingScheme,

    /// Minimum zxcvbn complexity score (0-4):
    ///   0 = <100 guesses, 1 = <10k, 2 = <1M, 3 = <100M, 4 = beyond
    #[serde(default = "default_min_complexity")]
    #[schemars(range(min = 0, max = 4))]
    minimum_complexity: u8,
}

fn default_pw_enabled() -> bool {
    true
}

fn default_min_complexity() -> u8 {
    DEFAULT_MIN_COMPLEXITY
}

impl Default for PasswordsConfig {
    fn default() -> Self {
        Self {
            enabled: default_pw_enabled(),
            scheme: HashingScheme::default(),
            minimum_complexity: DEFAULT_MIN_COMPLEXITY,
        }
    }
}

impl PasswordsConfig {
    /// Whether password login is turned on
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Required minimum password complexity score (0--4)
    #[must_use]
    pub fn minimum_complexity(&self) -> u8 {
        self.minimum_complexity
    }

    /// Resolve the active hashing parameters and optional pepper secret.
    ///
    /// # Errors
    ///
    /// Fails if an external secret file cannot be read or both secret sources
    /// are configured.
    pub async fn load(&self) -> Result<(Algorithm, Option<u32>, Option<Vec<u8>>), anyhow::Error> {
        let scheme = &self.scheme;
        let pepper = match (&scheme.secret, &scheme.secret_file) {
            (Some(secret), None) => Some(secret.clone().into_bytes()),
            (None, Some(path)) => Some(tokio::fs::read(path).await?),
            (Some(_), Some(_)) => bail!("Cannot specify both `secret` and `secret_file`"),
            (None, None) => None,
        };
        Ok((scheme.algorithm, scheme.cost, pepper))
    }
}

impl ConfigurationSection for PasswordsConfig {
    const PATH: &'static str = "passwords";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let make_err = |msg: String| {
            let mut err = figment::Error::from(msg);
            err.metadata = figment.find_metadata(Self::PATH).cloned();
            err.profile = Some(figment::Profile::Default);
            err.path = vec![Self::PATH.to_owned()];
            err
        };

        if self.minimum_complexity > 4 {
            return Err(
                make_err("Minimum password complexity must be between 0 and 4".into()).into(),
            );
        }

        // Nothing to validate when password auth is off
        if !self.enabled {
            return Ok(());
        }

        if self.scheme.secret.is_some() && self.scheme.secret_file.is_some() {
            return Err(make_err("Cannot specify both `secret` and `secret_file`".into()).into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use figment::Figment;

    use super::PasswordsConfig;
    use crate::ConfigurationSection;

    #[test]
    fn rejects_password_complexity_above_zxcvbn_range() {
        let config = PasswordsConfig {
            minimum_complexity: 5,
            ..PasswordsConfig::default()
        };

        let error = config
            .validate(&Figment::new())
            .expect_err("out-of-range complexity must be rejected");

        assert!(error.to_string().contains("between 0 and 4"));
    }
    #[test]
    fn rejects_unknown_password_configuration_members() {
        for value in [
            serde_json::json!({"unexpected": true}),
            serde_json::json!({"scheme": {"algorithm": "argon2id", "unexpected": true}}),
        ] {
            let error = serde_json::from_value::<PasswordsConfig>(value).unwrap_err();
            assert!(error.to_string().contains("unknown field"));
        }
    }
}
