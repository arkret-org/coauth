use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use coauth_i18n::Locale;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as Rng, SeedableRng};
use serde::Serialize;
use serde::ser::SerializeStruct;

/// Trait implemented by every template context to provide wrapper constructors
/// and deterministic sample data for template validation.
pub trait TemplateContext: Serialize {
    /// Wrap this context with a locale tag.
    fn with_language(self, lang: Locale) -> WithLanguage<Self>
    where
        Self: Sized,
    {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }

    /// Produce sample values for template validation.
    fn sample<R: Rng>(
        now: DateTime<Utc>,
        rng: &mut R,
        locales: &[Locale],
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
        locales: &[Locale],
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
        _locales: &[Locale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![EmptyContext])
    }
}
