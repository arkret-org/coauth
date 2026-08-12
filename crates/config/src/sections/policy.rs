use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

/// The policy engine backend to use for policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEngine {
    /// Amazon Cedar policy backend.
    ///
    /// Uses Cedar policies evaluated natively in Rust.
    /// Requires the `cedar` feature to be enabled.
    #[default]
    Cedar,
}

fn is_default_engine(value: &PolicyEngine) -> bool {
    *value == PolicyEngine::default()
}

/// Policy engine configuration.
///
/// Currently the only supported backend is Cedar.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct PolicyConfig {
    /// The policy engine to use.
    ///
    /// Defaults to `cedar`.
    #[serde(default, skip_serializing_if = "is_default_engine")]
    pub engine: PolicyEngine,

    // -- Cedar-specific configuration --
    /// Path to the Cedar policy file (used when engine is `cedar`).
    ///
    /// The file should contain Cedar policy statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub cedar_policy_file: Option<Utf8PathBuf>,

    /// Whether to enable audit logging for policy evaluations.
    ///
    /// When enabled, every policy evaluation will be logged with the action
    /// type, result (violation count or error), and evaluation duration.
    #[serde(default)]
    pub audit_logging: bool,
}

impl PolicyConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        is_default_engine(&self.engine) && self.cedar_policy_file.is_none() && !self.audit_logging
    }
}

impl ConfigurationSection for PolicyConfig {
    const PATH: &'static str = "policy";
}
