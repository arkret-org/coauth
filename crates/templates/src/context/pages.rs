//! Context types for the app shell and error pages.

use std::collections::BTreeMap;
use std::fmt::Formatter;

use coauth_data::UrlBuilder;
use rand_core::RngCore as Rng;
use serde::Serialize;

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};

// -- Frontend application shell ---------------------------------------------

/// An error state injected by the backend so the frontend displays an
/// error page instead of the normal SPA routes.
#[derive(Serialize, Clone, Default)]
pub struct AppErrorState {
    /// One of: `account_deactivated`, `account_locked`, `session_ended`,
    /// `generic`.
    pub kind: String,
    /// The local handle (without `@` / `:server`), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Human-readable description, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Frontend application configuration serialized as `snake_case` JSON.
#[derive(Serialize)]
pub struct AppConfig {
    root: String,
    api_endpoint: String,
    script_src: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<AppErrorState>,
}

/// Data passed to the `app.html` template.
#[derive(Serialize)]
pub struct AppContext {
    app_config: AppConfig,
}

impl AppContext {
    /// Build the context from a [`UrlBuilder`] and frontend script path
    /// (resolved from the Dioxus build output at startup).
    #[must_use]
    pub fn new(url_builder: &UrlBuilder, script_src: &str) -> Self {
        let root = url_builder.relative_url("/account/");
        let prefix = url_builder.prefix().unwrap_or_default();
        Self {
            app_config: AppConfig {
                root,
                api_endpoint: format!("{prefix}/_coauth"),
                script_src: script_src.to_owned(),
                error: None,
            },
        }
    }

    /// Attach an error state that the frontend will display instead of
    /// its normal routes.
    #[must_use]
    pub fn with_error(mut self, error: AppErrorState) -> Self {
        self.app_config.error = Some(error);
        self
    }
}

impl TemplateContext for AppContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        let builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        sample_list(vec![Self::new(&builder, "/assets/coauth-frontend.js")])
    }
}

// -- Error pages ------------------------------------------------------------

/// Data for the `error.html` template.
#[derive(Default, Serialize, Debug, Clone)]
pub struct ErrorContext {
    code: Option<&'static str>,
    description: Option<String>,
    details: Option<String>,
    lang: Option<String>,
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = &self.code {
            writeln!(f, "code: {code}")?;
        }
        if let Some(desc) = &self.description {
            writeln!(f, "{desc}")?;
        }
        if let Some(detail) = &self.details {
            writeln!(f, "details: {detail}")?;
        }
        Ok(())
    }
}

impl ErrorContext {
    /// Create a blank error context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the error code.
    #[must_use]
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    /// Set the human-readable description.
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Set additional detail text.
    #[must_use]
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Set the language tag for the error page.
    #[must_use]
    pub fn with_language(mut self, lang: &coauth_i18n::Locale) -> Self {
        self.lang = Some(lang.to_string());
        self
    }

    /// Return the error code, if set.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    /// Return the description, if set.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Return the detail text, if set.
    #[must_use]
    pub fn details(&self) -> Option<&str> {
        self.details.as_deref()
    }
}

impl TemplateContext for ErrorContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![
            Self::new()
                .with_code("sample_error")
                .with_description("A fancy description".into())
                .with_details("Something happened".into()),
            Self::new().with_code("another_error"),
            Self::new(),
        ])
    }
}
