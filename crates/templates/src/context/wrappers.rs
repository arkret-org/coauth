use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use coauth_data::BrowserSession;
use coauth_i18n::DataLocale;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as Rng, SeedableRng};
use serde::{Serialize, ser::SerializeStruct};

use super::captcha::WithCaptcha;

/// Trait implemented by every template context to provide wrapper constructors
/// and deterministic sample data for template validation.
pub trait TemplateContext: Serialize {
    /// Wrap this context with a browser session.
    fn with_session(self, current_session: BrowserSession) -> WithSession<Self>
    where
        Self: Sized,
    {
        WithSession {
            current_session,
            inner: self,
        }
    }

    /// Wrap this context with an optional browser session.
    fn maybe_with_session(
        self,
        current_session: Option<BrowserSession>,
    ) -> WithOptionalSession<Self>
    where
        Self: Sized,
    {
        WithOptionalSession {
            current_session,
            inner: self,
        }
    }

    /// Wrap this context with a CSRF token.
    fn with_csrf<C>(self, csrf_token: C) -> WithCsrf<Self>
    where
        Self: Sized,
        C: ToString,
    {
        WithCsrf {
            csrf_token: csrf_token.to_string(),
            inner: self,
        }
    }

    /// Wrap this context with a locale tag.
    fn with_language(self, lang: DataLocale) -> WithLanguage<Self>
    where
        Self: Sized,
    {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }

    /// Wrap this context with optional CAPTCHA configuration.
    fn with_captcha(self, captcha: Option<coauth_data::CaptchaConfig>) -> WithCaptcha<Self>
    where
        Self: Sized,
    {
        WithCaptcha::new(captcha, self)
    }

    /// Produce sample values for template validation.
    fn sample<R: Rng>(
        now: DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized;
}

/// Key that identifies one particular sample rendering variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SampleIdentifier {
    pub components: Vec<(&'static str, String)>,
}

impl SampleIdentifier {
    pub fn from_index(index: usize) -> Self {
        Self {
            components: Vec::new(),
        }
        .with_appended("index", index.to_string())
    }

    pub fn with_appended(&self, kind: &'static str, value: String) -> Self {
        let mut identifier = self.clone();
        identifier.components.push((kind, value));
        identifier
    }
}

/// Turn a plain list of contexts into an indexed sample map.
pub(crate) fn sample_list<T: TemplateContext>(items: Vec<T>) -> BTreeMap<SampleIdentifier, T> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, context)| (SampleIdentifier::from_index(index), context))
        .collect()
}

impl TemplateContext for () {
    fn sample<R: Rng>(
        _now: DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BTreeMap::new()
    }
}

/// Wraps a context with a locale string.
#[derive(Serialize, Debug)]
pub struct WithLanguage<T> {
    pub(crate) lang: String,

    #[serde(flatten)]
    pub(crate) inner: T,
}

impl<T> WithLanguage<T> {
    /// Return the language tag carried by this wrapper.
    pub fn language(&self) -> &str {
        &self.lang
    }
}

impl<T> std::ops::Deref for WithLanguage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: TemplateContext> TemplateContext for WithLanguage<T> {
    fn sample<R: Rng>(
        now: DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let locale_rng = ChaCha8Rng::from_rng(rng).unwrap();

        locales
            .iter()
            .flat_map(|locale| {
                T::sample(now, &mut locale_rng.clone(), locales)
                    .into_iter()
                    .map(|(identifier, context)| {
                        (
                            identifier.with_appended("locale", locale.to_string()),
                            Self {
                                lang: locale.to_string(),
                                inner: context,
                            },
                        )
                    })
            })
            .collect()
    }
}

/// Wraps a context with a CSRF token.
#[derive(Serialize, Debug)]
pub struct WithCsrf<T> {
    csrf_token: String,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithCsrf<T> {
    fn sample<R: Rng>(
        now: DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(identifier, context)| {
                (
                    identifier,
                    Self {
                        csrf_token: "fake_csrf_token".into(),
                        inner: context,
                    },
                )
            })
            .collect()
    }
}

/// Wraps a context with an authenticated browser session.
#[derive(Serialize)]
pub struct WithSession<T> {
    current_session: BrowserSession,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithSession<T> {
    fn sample<R: Rng>(
        now: DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now, rng)
            .into_iter()
            .enumerate()
            .flat_map(|(session_index, session)| {
                T::sample(now, rng, locales)
                    .into_iter()
                    .map(move |(identifier, context)| {
                        (
                            identifier.with_appended("browser-session", session_index.to_string()),
                            Self {
                                current_session: session.clone(),
                                inner: context,
                            },
                        )
                    })
            })
            .collect()
    }
}

/// Wraps a context with an optional browser session.
#[derive(Serialize)]
pub struct WithOptionalSession<T> {
    current_session: Option<BrowserSession>,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithOptionalSession<T> {
    fn sample<R: Rng>(
        now: DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let sessions: Vec<Option<BrowserSession>> = BrowserSession::samples(now, rng)
            .into_iter()
            .map(Some)
            .chain(std::iter::once(None))
            .collect();

        sessions
            .into_iter()
            .enumerate()
            .flat_map(|(session_index, current_session)| {
                T::sample(now, rng, locales)
                    .into_iter()
                    .map(move |(identifier, context)| {
                        let identifier = if current_session.is_some() {
                            identifier.with_appended("browser-session", session_index.to_string())
                        } else {
                            identifier
                        };

                        (
                            identifier,
                            Self {
                                current_session: current_session.clone(),
                                inner: context,
                            },
                        )
                    })
            })
            .collect()
    }
}

/// Placeholder context that serializes to an empty struct.
pub struct EmptyContext;

impl Serialize for EmptyContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("EmptyContext", 0)?;
        state.serialize_field("__UNUSED", &())?;
        state.end()
    }
}

impl TemplateContext for EmptyContext {
    fn sample<R: Rng>(
        _now: DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![EmptyContext])
    }
}
