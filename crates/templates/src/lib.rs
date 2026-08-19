#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

//! Template rendering engine for coauth.
//!
//! This crate wraps [`minijinja`] to provide strongly-typed template
//! rendering.  Each page or email is backed by a dedicated context type
//! (see the [`context`] module) and a corresponding template file on disk.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use anyhow::Context as _;
use arc_swap::ArcSwap;
use camino::{Utf8Path, Utf8PathBuf};
use coauth_data::UrlBuilder;
use coauth_i18n::Translator;
use minijinja::{UndefinedBehavior, Value};
use rand_core::RngCore as Rng;
use serde::Serialize;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{debug, info};
use walkdir::DirEntry;

mod context;
mod functions;

#[macro_use]
mod macros;

pub use self::context::{
    AppContext, AppErrorState, DeviceNameContext, EmailRecoveryContext, EmailVerificationContext,
    EmptyContext, ErrorContext, FormPostContext, SiteBranding, SiteConfigExt, SiteFeatures,
    TemplateContext, WithLanguage,
};
use crate::context::SampleIdentifier;

// ── Error types ─────────────────────────────────────────────────────────────

/// There was an issue while loading the templates
#[derive(Error, Debug)]
pub enum TemplateLoadingError {
    /// I/O error
    #[error(transparent)]
    IO(#[from] std::io::Error),

    /// Failed to load the translations
    #[error("failed to load the translations")]
    Translations(#[from] coauth_i18n::LoadError),

    /// Failed to traverse the filesystem
    #[error("failed to traverse the filesystem")]
    WalkDir(#[from] walkdir::Error),

    /// Encountered non-UTF-8 path
    #[error("encountered non-UTF-8 path")]
    NonUtf8Path(#[from] camino::FromPathError),

    /// Encountered non-UTF-8 path
    #[error("encountered non-UTF-8 path")]
    NonUtf8PathBuf(#[from] camino::FromPathBufError),

    /// Encountered invalid path
    #[error("encountered invalid path")]
    InvalidPath(#[from] std::path::StripPrefixError),

    /// Some templates failed to compile
    #[error("could not load and compile some templates")]
    Compile(#[from] minijinja::Error),

    /// Could not join blocking task
    #[error("error from async runtime")]
    Runtime(#[from] JoinError),

    /// There are essential templates missing
    #[error("missing templates {missing:?}")]
    MissingTemplates {
        /// List of missing templates
        missing: HashSet<String>,
        /// List of templates that were loaded
        loaded: HashSet<String>,
    },
}

/// Failed to render a template
#[derive(Error, Debug)]
pub enum TemplateError {
    /// Missing template
    #[error("missing template {template:?}")]
    Missing {
        /// The name of the template being rendered
        template: &'static str,
        /// The underlying error
        #[source]
        source: minijinja::Error,
    },

    /// Failed to render the template
    #[error("could not render template {template:?}")]
    Render {
        /// The name of the template being rendered
        template: &'static str,
        /// The underlying error
        #[source]
        source: minijinja::Error,
    },
}

// ── Templates engine ────────────────────────────────────────────────────────

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|s| s.starts_with('.'))
}

/// Wrapper around [`minijinja::Environment`] helping rendering the various
/// templates
#[derive(Debug, Clone)]
pub struct Templates {
    environment: Arc<ArcSwap<minijinja::Environment<'static>>>,
    translator: Arc<ArcSwap<Translator>>,
    url_builder: UrlBuilder,
    branding: SiteBranding,
    features: SiteFeatures,
    translations_path: Utf8PathBuf,
    /// Default locale used as the last-resort fallback for the embedded
    /// [`Translator`]. Kept alongside [`Self::translations_path`] so reloads
    /// preserve the caller's choice.
    default_locale: coauth_i18n::icu_locid::Locale,
    path: Utf8PathBuf,
    /// Whether template rendering is in strict mode (for testing,
    /// until this can be rolled out in production.)
    strict: bool,
}

impl Templates {
    // -- Core rendering helpers ---------------------------------------------

    fn render_registered<C: Serialize>(
        &self,
        template: &'static str,
        context: &C,
    ) -> Result<String, TemplateError> {
        let context = Value::from_serialize(context);
        self.render_value(template, context)
    }

    fn render_value(
        &self,
        template: &'static str,
        context: Value,
    ) -> Result<String, TemplateError> {
        let environment = self.environment.load();
        let tpl = environment
            .get_template(template)
            .map_err(|source| TemplateError::Missing { template, source })?;

        tpl.render(context)
            .map_err(|source| TemplateError::Render { template, source })
    }

    fn render_sample_set<C, R>(
        &self,
        template: &'static str,
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
    ) -> anyhow::Result<BTreeMap<SampleIdentifier, String>>
    where
        C: TemplateContext + Serialize,
        R: Rng + Clone,
    {
        let locales = self.translator().available_locales();
        let samples: BTreeMap<SampleIdentifier, C> = TemplateContext::sample(now, rng, &locales);
        let mut output = BTreeMap::new();

        for (sample_id, sample_context) in samples {
            let serialized_context = serde_json::to_value(&sample_context)?;
            tracing::info!(name = template, %serialized_context, "Rendering template");
            let html = self
                .render_registered(template, &sample_context)
                .with_context(|| {
                    format!(
                        "Failed to render sample template {template:?}-{sample_id:?} with context {serialized_context}"
                    )
                })?;
            output.insert(sample_id, html);
        }

        Ok(output)
    }

    // -- Loading & reloading ------------------------------------------------

    /// Load the templates from the given config
    ///
    /// # Errors
    ///
    /// Returns an error if the templates could not be loaded from disk.
    #[tracing::instrument(
        name = "templates.load",
        skip_all,
        fields(%path),
    )]
    pub async fn load(
        path: Utf8PathBuf,
        url_builder: UrlBuilder,
        translations_path: Utf8PathBuf,
        branding: SiteBranding,
        features: SiteFeatures,
        strict: bool,
    ) -> Result<Self, TemplateLoadingError> {
        Self::load_with_default_locale(
            path,
            url_builder,
            translations_path,
            coauth_i18n::icu_locid::locale!("en"),
            branding,
            features,
            strict,
        )
        .await
    }

    /// Load the templates from the given config, using `default_locale` as
    /// the last-resort translation fallback.
    ///
    /// # Errors
    ///
    /// Returns an error if the templates could not be loaded from disk.
    #[tracing::instrument(
        name = "templates.load_with_default_locale",
        skip_all,
        fields(%path, %default_locale),
    )]
    pub async fn load_with_default_locale(
        path: Utf8PathBuf,
        url_builder: UrlBuilder,
        translations_path: Utf8PathBuf,
        default_locale: coauth_i18n::icu_locid::Locale,
        branding: SiteBranding,
        features: SiteFeatures,
        strict: bool,
    ) -> Result<Self, TemplateLoadingError> {
        let (translator, environment) = Self::load_(
            &path,
            url_builder.clone(),
            &translations_path,
            default_locale.clone(),
            branding.clone(),
            features,
            strict,
        )
        .await?;

        Ok(Self {
            environment: Arc::new(ArcSwap::new(environment)),
            translator: Arc::new(ArcSwap::new(translator)),
            path,
            url_builder,
            translations_path,
            default_locale,
            branding,
            features,
            strict,
        })
    }

    async fn load_(
        path: &Utf8Path,
        url_builder: UrlBuilder,
        translations_path: &Utf8Path,
        default_locale: coauth_i18n::icu_locid::Locale,
        branding: SiteBranding,
        features: SiteFeatures,
        strict: bool,
    ) -> Result<(Arc<Translator>, Arc<minijinja::Environment<'static>>), TemplateLoadingError> {
        let path = path.to_owned();
        let span = tracing::Span::current();

        // Load translations on a blocking thread
        let translations_path = translations_path.to_owned();
        let translator_default_locale = default_locale.clone();
        let translator = tokio::task::spawn_blocking(move || {
            Translator::load_from_path_with_default(&translations_path, translator_default_locale)
        })
        .await??;
        let translator = Arc::new(translator);
        debug!(locales = ?translator.available_locales(), "Loaded translations");

        // Load and compile templates on a blocking thread
        let (loaded, mut env) = tokio::task::spawn_blocking(move || {
            span.in_scope(move || {
                let mut loaded: HashSet<_> = HashSet::new();
                let mut env = minijinja::Environment::new();
                env.set_undefined_behavior(if strict {
                    UndefinedBehavior::Strict
                } else {
                    UndefinedBehavior::SemiStrict
                });

                let root = path.canonicalize_utf8()?;
                info!(%root, "Loading templates from filesystem");

                for entry in walkdir::WalkDir::new(&root)
                    .min_depth(1)
                    .into_iter()
                    .filter_entry(|e| !is_hidden(e))
                {
                    let entry = entry?;
                    if !entry.file_type().is_file() {
                        continue;
                    }

                    let path = Utf8PathBuf::try_from(entry.into_path())?;
                    let Some(ext) = path.extension() else {
                        continue;
                    };

                    if matches!(ext, "html" | "txt" | "subject") {
                        let relative = path.strip_prefix(&root)?;
                        // Normalize path separators to forward slashes for
                        // cross-platform compatibility (Windows uses backslashes)
                        let key = relative.as_str().replace('\\', "/");
                        debug!(%key, "Registering template");
                        let template = std::fs::read_to_string(&path)?;
                        env.add_template_owned(key.clone(), template)?;
                        loaded.insert(key);
                    }
                }

                Ok::<_, TemplateLoadingError>((loaded, env))
            })
        })
        .await??;

        env.add_global("branding", Value::from_object(branding));
        env.add_global("features", Value::from_object(features));

        self::functions::register(&mut env, url_builder, Arc::clone(&translator));

        let env = Arc::new(env);

        // Verify all required templates are present
        let needed: HashSet<_> = TEMPLATES.iter().copied().map(ToOwned::to_owned).collect();
        debug!(?loaded, ?needed, "Templates loaded");
        let missing: HashSet<_> = needed.difference(&loaded).cloned().collect();

        if missing.is_empty() {
            Ok((translator, env))
        } else {
            Err(TemplateLoadingError::MissingTemplates { missing, loaded })
        }
    }

    /// Reload the templates on disk
    ///
    /// # Errors
    ///
    /// Returns an error if the templates could not be reloaded from disk.
    #[tracing::instrument(
        name = "templates.reload",
        skip_all,
        fields(path = %self.path),
    )]
    pub async fn reload(&self) -> Result<(), TemplateLoadingError> {
        let (translator, environment) = Self::load_(
            &self.path,
            self.url_builder.clone(),
            &self.translations_path,
            self.default_locale.clone(),
            self.branding.clone(),
            self.features,
            self.strict,
        )
        .await?;

        self.environment.store(environment);
        self.translator.store(translator);

        Ok(())
    }

    /// Get the translator
    #[must_use]
    pub fn translator(&self) -> Arc<Translator> {
        self.translator.load_full()
    }
}

// ── Template registration ───────────────────────────────────────────────────

register_templates! {
    /// Render the frontend app (Dioxus SPA shell)
    pub fn render_app(WithLanguage<AppContext>) { "app.html" }

    /// Render the form used by the `form_post` response mode (OAuth protocol)
    pub fn render_form_post<#[sample(EmptyContext)] T: Serialize>(WithLanguage<FormPostContext<T>>) { "form_post.html" }

    /// Render the email recovery email (plain text variant)
    pub fn render_email_recovery_txt(WithLanguage<EmailRecoveryContext>) { "emails/recovery.txt" }

    /// Render the email recovery email (HTML text variant)
    pub fn render_email_recovery_html(WithLanguage<EmailRecoveryContext>) { "emails/recovery.html" }

    /// Render the email recovery subject
    pub fn render_email_recovery_subject(WithLanguage<EmailRecoveryContext>) { "emails/recovery.subject" }

    /// Render the email verification email (plain text variant)
    pub fn render_email_verification_txt(WithLanguage<EmailVerificationContext>) { "emails/verification.txt" }

    /// Render the email verification email (HTML text variant)
    pub fn render_email_verification_html(WithLanguage<EmailVerificationContext>) { "emails/verification.html" }

    /// Render the email verification subject
    pub fn render_email_verification_subject(WithLanguage<EmailVerificationContext>) { "emails/verification.subject" }

    /// Render the automatic device name for OAuth client
    pub fn render_device_name(WithLanguage<DeviceNameContext>) { "device_name.txt" }
}

impl Templates {
    /// Render all templates with the generated samples to check if they render
    /// properly.
    ///
    /// Returns the renders in a map whose keys are template names
    /// and the values are lists of renders (according to the list
    /// of samples).
    /// Samples are stable across re-runs and can be used for
    /// acceptance testing.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the templates fails to render
    pub fn check_render<R: Rng + Clone>(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        rng: &R,
    ) -> anyhow::Result<BTreeMap<(&'static str, SampleIdentifier), String>> {
        check::all(self, now, rng)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::UserEmailAuthenticationCode;
    use rand_core::SeedableRng;

    use super::*;

    #[tokio::test]
    async fn check_builtin_templates() {
        #[allow(clippy::disallowed_methods)]
        let now = chrono::Utc::now();
        let rng = rand_chacha::ChaCha8Rng::from_seed([42; 32]);

        let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/");
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let branding = SiteBranding::new("example.com");
        let features = SiteFeatures {
            password_login: true,
            password_registration: true,
            password_registration_contact_required: true,
            account_recovery: true,
            login_with_email_allowed: true,
        };
        let translations_path =
            Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../translations");

        let templates = Templates::load(
            path.clone(),
            url_builder.clone(),
            translations_path.clone(),
            branding.clone(),
            features,
            true,
        )
        .await
        .unwrap();

        // Check the renders are deterministic, when given the same rng
        let render1 = templates.check_render(now, &rng).unwrap();
        let render2 = templates.check_render(now, &rng).unwrap();

        assert_eq!(render1, render2);
    }

    #[tokio::test]
    async fn verification_email_renders_instance_identifiers_in_english() {
        #[allow(clippy::disallowed_methods)]
        let now = chrono::Utc::now();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([7; 32]);

        let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/");
        let url_builder =
            UrlBuilder::new("https://tenant.example.com/".parse().unwrap(), None, None);
        let branding = SiteBranding::new("auth.example.com");
        let features = SiteFeatures {
            password_login: true,
            password_registration: true,
            password_registration_contact_required: true,
            account_recovery: true,
            login_with_email_allowed: true,
        };
        let translations_path =
            Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../translations");

        let templates = Templates::load(
            path,
            url_builder,
            translations_path,
            branding,
            features,
            true,
        )
        .await
        .unwrap();

        let context = EmailVerificationContext::new(
            UserEmailAuthenticationCode {
                id: coauth_data::new_id(now, &mut rng),
                user_email_authentication_id: coauth_data::new_id(now, &mut rng),
                code: "654321".to_owned(),
                created_at: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(4),
            },
            None,
            None,
        )
        .with_language("en".parse().unwrap());

        let subject = templates
            .render_email_verification_subject(&context)
            .unwrap();
        let text = templates.render_email_verification_txt(&context).unwrap();

        assert!(subject.contains("[auth.example.com]"));
        assert!(subject.contains("Your email verification code"));
        assert!(text.contains("Your email verification code for auth.example.com is: 654321"));
        assert!(text.contains("coauth service: auth.example.com"));
        assert!(!text.contains("Instance domain:"));
    }
}
