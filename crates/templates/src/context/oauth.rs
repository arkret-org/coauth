//! OAuth 2.0 form_post response mode context.

use std::collections::BTreeMap;

use coauth_i18n::DataLocale;
use rand_core::RngCore as Rng;
use serde::Serialize;
use url::Url;

use super::wrappers::{SampleIdentifier, TemplateContext, WithLanguage};

/// Data for the `form_post.html` template.
#[derive(Serialize)]
pub struct FormPostContext<T> {
    redirect_uri: Option<Url>,
    params: T,
}

impl<T: TemplateContext> TemplateContext for FormPostContext<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(id, inner_params)| {
                let ctx = Self {
                    redirect_uri: "https://example.com/callback".parse().ok(),
                    params: inner_params,
                };
                (id, ctx)
            })
            .collect()
    }
}

impl<T> FormPostContext<T> {
    /// Build a form-post context that redirects to the given URL.
    pub fn new_for_url(redirect_uri: Url, params: T) -> Self {
        Self {
            redirect_uri: Some(redirect_uri),
            params,
        }
    }

    /// Build a form-post context that posts to the current URL.
    pub fn new_for_current_url(params: T) -> Self {
        Self {
            redirect_uri: None,
            params,
        }
    }

    /// Attach a language tag.
    ///
    /// Provided separately from the [`TemplateContext`] trait because the
    /// generic parameter makes blanket implementation awkward.
    pub fn with_language(self, lang: &DataLocale) -> WithLanguage<Self> {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }
}
