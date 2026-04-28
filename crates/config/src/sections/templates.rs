use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ConfigurationSection;

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_path() -> Utf8PathBuf {
    "./templates/".into()
}

#[cfg(feature = "docker")]
fn default_path() -> Utf8PathBuf {
    "/usr/local/share/coauth/templates/".into()
}

#[cfg(feature = "dist")]
fn default_path() -> Utf8PathBuf {
    "./share/templates/".into()
}

fn is_default_path(value: &Utf8PathBuf) -> bool {
    *value == default_path()
}

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_translations_path() -> Utf8PathBuf {
    "./translations/".into()
}

#[cfg(feature = "docker")]
fn default_translations_path() -> Utf8PathBuf {
    "/usr/local/share/coauth/translations/".into()
}

#[cfg(feature = "dist")]
fn default_translations_path() -> Utf8PathBuf {
    "./share/translations/".into()
}

fn is_default_translations_path(value: &Utf8PathBuf) -> bool {
    *value == default_translations_path()
}

fn is_default_default_locale(value: &Option<String>) -> bool {
    value.is_none()
}

/// Configuration related to templates
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TemplatesConfig {
    /// Path to the folder which holds the templates
    #[serde(default = "default_path", skip_serializing_if = "is_default_path")]
    #[schemars(with = "Option<String>")]
    pub path: Utf8PathBuf,

    /// Path to the translations
    #[serde(
        default = "default_translations_path",
        skip_serializing_if = "is_default_translations_path"
    )]
    #[schemars(with = "Option<String>")]
    pub translations_path: Utf8PathBuf,

    /// Default locale used as the last-resort fallback when the requested
    /// locale's ICU fallback chain is exhausted.
    ///
    /// Defaults to `"en"` when unset.
    #[serde(default, skip_serializing_if = "is_default_default_locale")]
    pub default_locale: Option<String>,
}

impl Default for TemplatesConfig {
    fn default() -> Self {
        Self {
            path: default_path(),
            translations_path: default_translations_path(),
            default_locale: None,
        }
    }
}

impl TemplatesConfig {
    /// Returns true if all fields are at their default values
    pub(crate) fn is_default(&self) -> bool {
        is_default_path(&self.path)
            && is_default_translations_path(&self.translations_path)
            && is_default_default_locale(&self.default_locale)
    }
}

impl ConfigurationSection for TemplatesConfig {
    const PATH: &'static str = "templates";
}
