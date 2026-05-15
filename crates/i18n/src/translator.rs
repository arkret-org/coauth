use std::{collections::HashMap, fs};

use camino::{Utf8Path, Utf8PathBuf};
use fluent_bundle::{FluentArgs, FluentResource};
use icu_experimental::relativetime::{
    RelativeTimeFormatter, RelativeTimeFormatterOptions, options::Numeric,
};
use icu_locid::Locale;
use icu_locid_transform::fallback::{
    LocaleFallbackConfig, LocaleFallbacker, LocaleFallbackerWithConfig,
};
use thiserror::Error;
use unic_langid::LanguageIdentifier;
use writeable::Writeable;

const FALLBACKER: LocaleFallbackerWithConfig<'static> =
    LocaleFallbacker::new().for_config(LocaleFallbackConfig::default());

/// Error type for loading translations.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to load translation directory {path:?}")]
    ReadDir {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read translation file {path:?}")]
    ReadFile {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse FTL file {path:?}: {errors:?}")]
    ParseFtl {
        path: Utf8PathBuf,
        errors: Vec<String>,
    },

    #[error("Invalid locale for file {path:?}: {detail}")]
    InvalidLocale { path: Utf8PathBuf, detail: String },

    #[error("Invalid file name {path:?}")]
    InvalidFileName { path: Utf8PathBuf },
}

/// A concurrent Fluent bundle type alias, safe for use in async / web servers.
type ConcurrentBundle = fluent_bundle::concurrent::FluentBundle<FluentResource>;

/// A translator backed by Fluent `.ftl` files.
///
/// Holds one [`FluentBundle`](fluent_bundle::concurrent::FluentBundle) per
/// locale and performs key lookup with automatic locale fallback (using the ICU
/// fallback chain) and transparent dot-to-hyphen key conversion so that
/// template code can use `"common.loading"` while the FTL file defines
/// `common-loading`.
pub struct Translator {
    bundles: HashMap<Locale, ConcurrentBundle>,
    default_locale: Locale,
}

// Manual Debug impl because FluentBundle doesn't implement Debug.
impl std::fmt::Debug for Translator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Translator")
            .field("locales", &self.bundles.keys().collect::<Vec<_>>())
            .field("default_locale", &self.default_locale)
            .finish()
    }
}

impl Default for Translator {
    fn default() -> Self {
        Self {
            bundles: HashMap::new(),
            default_locale: icu_locid::locale!("en"),
        }
    }
}

impl Translator {
    /// Load `.ftl` translation files from a directory.
    ///
    /// The directory should contain one `.ftl` file per locale, where the file
    /// name (without extension) is the BCP-47 locale tag, e.g. `en.ftl`,
    /// `zh-Hans.ftl`.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read, if any file cannot be
    /// parsed as valid FTL, or if a filename is not a valid locale.
    pub fn load_from_path(path: &Utf8Path) -> Result<Self, LoadError> {
        Self::load_from_path_with_default(path, icu_locid::locale!("en"))
    }

    /// Load `.ftl` translation files from a directory, using `default_locale`
    /// as the last-resort fallback when the requested locale's fallback
    /// chain is exhausted without a match.
    ///
    /// This is the configurable variant of [`Translator::load_from_path`].
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read, if any file cannot be
    /// parsed as valid FTL, or if a filename is not a valid locale.
    pub fn load_from_path_with_default(
        path: &Utf8Path,
        default_locale: Locale,
    ) -> Result<Self, LoadError> {
        let entries = path.read_dir_utf8().map_err(|source| LoadError::ReadDir {
            path: path.to_owned(),
            source,
        })?;

        let mut bundles: HashMap<Locale, ConcurrentBundle> = HashMap::new();

        for dir_result in entries {
            let dir_entry = dir_result.map_err(|source| LoadError::ReadDir {
                path: path.to_owned(),
                source,
            })?;

            let file_path = dir_entry.into_path();

            // Only process .ftl files
            if file_path.extension() != Some("ftl") {
                continue;
            }

            let stem = file_path
                .file_stem()
                .ok_or_else(|| LoadError::InvalidFileName {
                    path: file_path.clone(),
                })?;

            // Parse stem as an ICU locale
            let icu_locale: Locale = stem.parse().map_err(|e| LoadError::InvalidLocale {
                path: file_path.clone(),
                detail: format!("{e}"),
            })?;

            // Parse stem as a unic LanguageIdentifier (for FluentBundle)
            let langid: LanguageIdentifier =
                stem.parse().map_err(|e| LoadError::InvalidLocale {
                    path: file_path.clone(),
                    detail: format!("{e}"),
                })?;

            let source = fs::read_to_string(&file_path).map_err(|source| LoadError::ReadFile {
                path: file_path.clone(),
                source,
            })?;

            let resource =
                FluentResource::try_new(source).map_err(|(_, errors)| LoadError::ParseFtl {
                    path: file_path.clone(),
                    errors: errors.iter().map(|e| format!("{e}")).collect(),
                })?;

            let mut bundle = fluent_bundle::concurrent::FluentBundle::new_concurrent(vec![langid]);
            bundle.set_use_isolating(false);
            bundle
                .add_resource(resource)
                .map_err(|errors| LoadError::ParseFtl {
                    path: file_path.clone(),
                    errors: errors.iter().map(|e| format!("{e}")).collect(),
                })?;

            bundles.insert(icu_locale, bundle);
        }

        Ok(Self {
            bundles,
            default_locale,
        })
    }

    // ------------------------------------------------------------------
    // Message lookup
    // ------------------------------------------------------------------

    /// Convert a dot/underscore-separated template key to the hyphen-separated
    /// FTL message identifier.
    ///
    /// Example: `"coauth.emails.verify.body_text"` becomes
    /// `"coauth-emails-verify-body-text"`.
    fn key_to_ftl_id(key: &str) -> String {
        key.replace(['.', '_'], "-")
    }

    /// Format a message for the given locale, walking the ICU fallback chain.
    ///
    /// The `key` may use dot separators (e.g. `"common.loading"`); dots are
    /// transparently converted to hyphens for the FTL lookup.
    ///
    /// Returns `None` if no translation is found in any locale along the
    /// fallback chain.
    #[must_use]
    pub fn format(
        &self,
        locale: &Locale,
        key: &str,
        args: Option<&FluentArgs<'_>>,
    ) -> Option<String> {
        let ftl_id = Self::key_to_ftl_id(key);

        // Try the exact locale first.
        if let Some(result) = self.format_in_bundle(locale, &ftl_id, args) {
            return Some(result);
        }

        // Walk the ICU fallback chain.
        let mut chain = FALLBACKER.fallback_for(locale.into());
        loop {
            let candidate = chain.get();

            let candidate_locale = (*candidate).into_locale();
            if let Some(result) = self.format_in_bundle(&candidate_locale, &ftl_id, args) {
                return Some(result);
            }

            if candidate.is_unknown() {
                // Last resort: default locale.
                return self.format_in_bundle(&self.default_locale, &ftl_id, args);
            }

            chain.step();
        }
    }

    /// Try to format a single message in the bundle for `locale`.
    fn format_in_bundle(
        &self,
        locale: &Locale,
        ftl_id: &str,
        args: Option<&FluentArgs<'_>>,
    ) -> Option<String> {
        let bundle = self.bundles.get(locale)?;
        let message = bundle.get_message(ftl_id)?;
        let pattern = message.value()?;
        let mut errors = vec![];
        let result = bundle.format_pattern(pattern, args, &mut errors);
        Some(result.into_owned())
    }

    // ------------------------------------------------------------------
    // ICU date/time helpers (unchanged from original)
    // ------------------------------------------------------------------

    /// Format a relative date.
    ///
    /// # Parameters
    ///
    /// * `locale` -- The locale to use.
    /// * `days` -- The number of days to format, where 0 = today, 1 = tomorrow,
    ///   -1 = yesterday, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the ICU formatter cannot be created for the locale.
    pub fn relative_date(&self, locale: &Locale, days: i64) -> Result<String, crate::FormatError> {
        let mut opts = RelativeTimeFormatterOptions::default();
        opts.numeric = Numeric::Auto;
        let formatter = RelativeTimeFormatter::try_new_long_day(locale.into(), opts)
            .map_err(|_| crate::FormatError::new("failed to load relative time formatter"))?;
        let writeable = formatter.format(days.into());
        Ok(writeable.write_to_string().into_owned())
    }

    /// Format a short time.
    ///
    /// # Parameters
    ///
    /// * `locale` -- The locale to use.
    /// * `time` -- The time to format.
    ///
    /// # Errors
    ///
    /// Returns an error if the ICU formatter cannot be created for the locale.
    pub fn short_time(
        &self,
        locale: &Locale,
        time: &icu_datetime::input::Time,
    ) -> Result<String, crate::FormatError> {
        let fmt = icu_datetime::NoCalendarFormatter::try_new(
            locale.into(),
            icu_datetime::fieldsets::T::short(),
        )
        .map_err(|_| crate::FormatError::new("failed to load time formatter"))?;
        Ok(fmt.format(time).to_string())
    }

    // ------------------------------------------------------------------
    // Locale helpers
    // ------------------------------------------------------------------

    /// Get a list of available locales.
    #[must_use]
    pub fn available_locales(&self) -> Vec<Locale> {
        self.bundles.keys().cloned().collect()
    }

    /// Check if a locale is available.
    #[must_use]
    pub fn has_locale(&self, locale: &Locale) -> bool {
        self.bundles.contains_key(locale)
    }

    /// Choose the best available locale from a list of candidates.
    #[must_use]
    pub fn choose_locale(&self, iter: impl Iterator<Item = Locale>) -> Locale {
        for candidate in iter {
            // Exact match?
            if self.has_locale(&candidate) {
                return candidate;
            }

            // Walk the fallback chain for this candidate.
            let mut chain = FALLBACKER.fallback_for(candidate.into());
            loop {
                let current = chain.get();
                if current.is_unknown() {
                    break;
                }

                let current_locale = (*current).into_locale();
                if self.has_locale(&current_locale) {
                    return current_locale;
                }

                chain.step();
            }
        }

        // Nothing matched; return the default.
        self.default_locale.clone()
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use fluent_bundle::FluentValue;
    use icu_locid::locale;

    use super::Translator;

    fn translator() -> Translator {
        let root: Utf8PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
        let test_data = root.join("test_data");
        Translator::load_from_path(&test_data).unwrap()
    }

    #[test]
    fn test_message() {
        let translator = translator();

        let result = translator.format(&locale!("en"), "hello", None);
        assert_eq!(result.as_deref(), Some("Hello!"));

        let result = translator.format(&locale!("fr"), "hello", None);
        assert_eq!(result.as_deref(), Some("Bonjour !"));

        // en-US has its own hello
        let result = translator.format(&locale!("en-US"), "hello", None);
        assert_eq!(result.as_deref(), Some("Hey!"));

        // en-US does not have "goodbye", should fall back to en
        let result = translator.format(&locale!("en-US"), "goodbye", None);
        assert_eq!(result.as_deref(), Some("Goodbye!"));
    }

    #[test]
    fn test_format_with_args() {
        let translator = translator();

        let mut args = fluent_bundle::FluentArgs::new();
        args.set("count", FluentValue::from(1));
        let result = translator.format(&locale!("en"), "active-sessions-one", Some(&args));
        assert_eq!(result.as_deref(), Some("1 active session."));

        let mut args = fluent_bundle::FluentArgs::new();
        args.set("count", FluentValue::from(2));
        let result = translator.format(&locale!("en"), "active-sessions-other", Some(&args));
        assert_eq!(result.as_deref(), Some("2 active sessions."));
    }

    #[test]
    fn test_dot_to_hyphen_conversion() {
        let translator = translator();

        let mut args = fluent_bundle::FluentArgs::new();
        args.set("count", FluentValue::from(1));
        let result = translator.format(&locale!("en"), "active-sessions.one", Some(&args));
        assert_eq!(result.as_deref(), Some("1 active session."));
    }
}
