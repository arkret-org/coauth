use std::{collections::BTreeMap, sync::Arc};

use minijinja::{
    Value,
    value::{Enumerator, Object},
};
use coauth_i18n::DataLocale;
use rand_core::RngCore as Rng;
use serde::Serialize;

use crate::{TemplateContext, context::SampleIdentifier};

const CAPTCHA_FIELD_NAMES: [&str; 2] = ["service", "site_key"];

#[derive(Debug, Clone, Copy)]
enum CaptchaField {
    Service,
    SiteKey,
}

impl CaptchaField {
    fn from_key(key: &str) -> Option<Self> {
        match key {
            "service" => Some(Self::Service),
            "site_key" => Some(Self::SiteKey),
            _ => None,
        }
    }

    fn value(self, captcha: &CaptchaDescriptor) -> Value {
        match self {
            Self::Service => Value::from(captcha.service.as_template_key()),
            Self::SiteKey => Value::from(captcha.site_key.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CaptchaServiceKey {
    RecaptchaV2,
    CloudflareTurnstile,
    HCaptcha,
}

impl CaptchaServiceKey {
    const fn as_template_key(self) -> &'static str {
        match self {
            Self::RecaptchaV2 => "recaptcha_v2",
            Self::CloudflareTurnstile => "cloudflare_turnstile",
            Self::HCaptcha => "hcaptcha",
        }
    }
}

impl From<coauth_data::CaptchaService> for CaptchaServiceKey {
    fn from(service: coauth_data::CaptchaService) -> Self {
        match service {
            coauth_data::CaptchaService::RecaptchaV2 => Self::RecaptchaV2,
            coauth_data::CaptchaService::CloudflareTurnstile => Self::CloudflareTurnstile,
            coauth_data::CaptchaService::HCaptcha => Self::HCaptcha,
        }
    }
}

/// Wraps a [`coauth_data::CaptchaConfig`] so it can be exposed as a minijinja
/// object with named fields.
#[derive(Debug)]
struct CaptchaDescriptor {
    service: CaptchaServiceKey,
    site_key: Arc<str>,
}

impl From<coauth_data::CaptchaConfig> for CaptchaDescriptor {
    fn from(config: coauth_data::CaptchaConfig) -> Self {
        Self {
            service: config.service.into(),
            site_key: Arc::<str>::from(config.site_key),
        }
    }
}

impl Object for CaptchaDescriptor {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        CaptchaField::from_key(key.as_str()?).map(|field| field.value(self))
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&CAPTCHA_FIELD_NAMES)
    }
}

/// Context with an optional CAPTCHA configuration in it
#[derive(Serialize)]
pub struct WithCaptcha<T> {
    captcha: Option<Value>,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithCaptcha<T> {
    #[must_use]
    pub(crate) fn new(captcha: Option<coauth_data::CaptchaConfig>, inner: T) -> Self {
        let captcha_value =
            captcha.map(|config| Value::from_object(CaptchaDescriptor::from(config)));
        Self {
            captcha: captcha_value,
            inner,
        }
    }
}

impl<T: TemplateContext> TemplateContext for WithCaptcha<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::prelude::Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(identifier, inner_ctx)| (identifier, Self::new(None, inner_ctx)))
            .collect()
    }
}
