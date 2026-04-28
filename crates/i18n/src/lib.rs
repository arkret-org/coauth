//! Internationalization (i18n) support for the Pasion authentication service.
//!
//! This crate provides:
//!
//! - [`Translator`] -- loads `.ftl` (Fluent) translation files and resolves
//!   messages for a given locale, with automatic fallback.
//! - Re-exports of ICU crates (`icu_calendar`, `icu_datetime`, `icu_locid`) for
//!   date/time formatting in the user's locale.

mod translator;

pub use icu_calendar;
pub use icu_datetime;
pub use icu_locid::{self, Locale, locale};

/// Type alias for backward compatibility -- previously
/// `icu_provider::DataLocale`, now backed by `icu_locid::Locale` to avoid
/// conflicts between ICU provider 1.x and 2.x in the dependency tree.
pub type DataLocale = icu_locid::Locale;

/// Error type for backward compatibility -- previously re-exported from
/// `icu_provider`.
///
/// Wraps an inner error with a static description. This is a thin replacement
/// for the ICU provider `DataError` to decouple this crate from `icu_provider`
/// version specifics.
#[derive(Debug)]
pub struct DataError {
    msg: &'static str,
    #[allow(dead_code)]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Display for DataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for DataError {}

impl DataError {
    /// Create a new `DataError` with a static message.
    pub fn new(msg: &'static str) -> Self {
        Self { msg, source: None }
    }
}

pub use self::translator::{LoadError, Translator};
