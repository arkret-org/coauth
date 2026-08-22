//! Internationalization (i18n) support for the coauth authentication service.
//!
//! This crate provides:
//!
//! - [`Translator`] -- loads `.ftl` (Fluent) translation files and resolves messages for a given
//!   locale, with automatic fallback.
//! - Re-exports of ICU crates (`icu_calendar`, `icu_datetime`, `icu_locid`) for date/time
//!   formatting in the user's locale.

mod translator;
mod ui_locale;

pub use arkret_locale::{LocaleSources, TextDirection, UiLocale, resolve};
pub use icu_calendar;
pub use icu_datetime;
pub use icu_locid::{self, Locale, locale};
pub use ui_locale::icu_locale_for;

/// Error type for ICU-backed formatting helpers.
#[derive(Debug)]
pub struct FormatError {
    msg: &'static str,
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for FormatError {}

impl FormatError {
    /// Create a new `FormatError` with a static message.
    #[must_use]
    pub fn new(msg: &'static str) -> Self {
        Self { msg }
    }
}

pub use self::translator::{LoadError, Translator};
