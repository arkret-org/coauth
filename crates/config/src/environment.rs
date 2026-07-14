//! Process-environment policy for runtime configuration reads.

use std::collections::BTreeMap;
use std::env::VarError;
use std::ffi::OsString;
use std::sync::OnceLock;

static POLICY: OnceLock<RuntimeEnvironmentPolicy> = OnceLock::new();

/// Controls whether runtime configuration may read ambient process variables.
#[derive(Debug, Default)]
pub struct RuntimeEnvironmentPolicy {
    ignore_ambient: bool,
    overrides: BTreeMap<String, String>,
}

impl RuntimeEnvironmentPolicy {
    /// Create a policy. When `ignore_ambient` is true, `COAUTH_*` and
    /// `DATABASE_URL` are treated as unset.
    #[must_use]
    pub fn new(ignore_ambient: bool) -> Self {
        Self {
            ignore_ambient,
            overrides: BTreeMap::new(),
        }
    }

    /// Add an explicit CLI-sourced value that remains visible in hermetic mode.
    #[must_use]
    pub fn with_override(mut self, key: &str, value: &str) -> Self {
        self.overrides.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Install the process-wide policy before worker threads are created.
    pub fn install(self) -> Result<(), Self> {
        POLICY.set(self)
    }
}

/// Read a runtime configuration variable through the installed source policy.
pub fn runtime_var(key: &str) -> Result<String, VarError> {
    if let Some(policy) = POLICY.get() {
        if let Some(value) = policy.overrides.get(key) {
            return Ok(value.clone());
        }
        if policy.ignore_ambient && is_managed_key(key) {
            return Err(VarError::NotPresent);
        }
    }
    std::env::var(key)
}

/// Read an OS-string runtime variable through the installed source policy.
#[must_use]
pub fn runtime_var_os(key: &str) -> Option<OsString> {
    if let Some(policy) = POLICY.get() {
        if let Some(value) = policy.overrides.get(key) {
            return Some(OsString::from(value));
        }
        if policy.ignore_ambient && is_managed_key(key) {
            return None;
        }
    }
    std::env::var_os(key)
}

fn is_managed_key(key: &str) -> bool {
    key.starts_with("COAUTH_") || key == "DATABASE_URL"
}
