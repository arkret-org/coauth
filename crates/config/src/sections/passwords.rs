use std::cmp::Reverse;

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

fn initial_scheme() -> Vec<HashingScheme> {
    vec![HashingScheme {
        version: 1,
        algorithm: Algorithm::default(),
        unicode_normalization: false,
        cost: None,
        secret: None,
        secret_file: None,
    }]
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

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn bool_is_false(v: &bool) -> bool {
    !*v
}

/// A versioned set of parameters that controls how passwords are hashed
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HashingScheme {
    /// Monotonic version tag -- the highest version is used for new passwords
    pub version: u16,

    /// Which hashing algorithm to apply
    pub algorithm: Algorithm,

    /// Apply NFKC normalization before hashing. Normally `false`; enable when
    /// migrating password hashes from Palpo which performs this normalization.
    #[serde(default, skip_serializing_if = "bool_is_false")]
    pub unicode_normalization: bool,

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

// ---------------------------------------------------------------------------
// PasswordsConfig
// ---------------------------------------------------------------------------

/// Password authentication and hashing behaviour
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PasswordsConfig {
    /// Master switch for password-based login
    #[serde(default = "default_pw_enabled")]
    pub enabled: bool,

    /// Ordered list of hashing schemes (newest version wins for new passwords)
    #[serde(default = "initial_scheme")]
    pub schemes: Vec<HashingScheme>,

    /// Minimum zxcvbn complexity score (0-4):
    ///   0 = <100 guesses, 1 = <10k, 2 = <1M, 3 = <100M, 4 = beyond
    #[serde(default = "default_min_complexity")]
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
            schemes: initial_scheme(),
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

    /// Resolve every scheme, reading secrets from disk where needed, and return
    /// the fully-expanded list sorted by descending version.
    ///
    /// # Errors
    ///
    /// Fails if two schemes share the same version, if the scheme list is
    /// empty, or if an external secret file cannot be read.
    pub async fn load(
        &self,
    ) -> Result<Vec<(u16, Algorithm, Option<u32>, Option<Vec<u8>>, bool)>, anyhow::Error> {
        // Deduplicate by version (descending)
        let mut ordered: Vec<&HashingScheme> = self.schemes.iter().collect();
        ordered.sort_unstable_by_key(|s| Reverse(s.version));
        ordered.dedup_by_key(|s| s.version);

        if ordered.len() != self.schemes.len() {
            bail!("Multiple password schemes have the same versions");
        }
        if ordered.is_empty() {
            bail!("Requires at least one password scheme in the config");
        }

        let mut out = Vec::with_capacity(ordered.len());
        for scheme in ordered {
            let pepper = match (&scheme.secret, &scheme.secret_file) {
                (Some(s), None) => Some(s.clone().into_bytes()),
                (None, Some(path)) => Some(tokio::fs::read(path).await?),
                (Some(_), Some(_)) => bail!("Cannot specify both `secret` and `secret_file`"),
                (None, None) => None,
            };
            out.push((
                scheme.version,
                scheme.algorithm,
                scheme.cost,
                pepper,
                scheme.unicode_normalization,
            ));
        }
        Ok(out)
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

        // Nothing to validate when password auth is off
        if !self.enabled {
            return Ok(());
        }

        if self.schemes.is_empty() {
            return Err(
                make_err("Requires at least one password scheme in the config".into()).into(),
            );
        }

        for scheme in &self.schemes {
            if scheme.secret.is_some() && scheme.secret_file.is_some() {
                return Err(
                    make_err("Cannot specify both `secret` and `secret_file`".into()).into(),
                );
            }
        }

        Ok(())
    }
}
