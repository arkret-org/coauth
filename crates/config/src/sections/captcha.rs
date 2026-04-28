use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};

use crate::ConfigurationSection;

/// Supported CAPTCHA provider services
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
pub enum CaptchaServiceKind {
    /// Google reCAPTCHA v2
    #[serde(rename = "recaptcha_v2")]
    RecaptchaV2,

    /// Cloudflare Turnstile verification
    #[serde(rename = "cloudflare_turnstile")]
    CloudflareTurnstile,

    /// ``HCaptcha`` verification service
    #[serde(rename = "hcaptcha")]
    HCaptcha,
}

/// Controls CAPTCHA-based bot protection for sensitive operations
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize, Default)]
pub struct CaptchaConfig {
    /// The CAPTCHA provider to use, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<CaptchaServiceKind>,

    /// Public-facing site key provided by the CAPTCHA service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_key: Option<String>,

    /// Server-side secret key for verifying CAPTCHA responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

impl CaptchaConfig {
    /// Checks whether every field holds its zero/default state
    pub(crate) fn is_default(&self) -> bool {
        self.service.is_none() && self.site_key.is_none() && self.secret_key.is_none()
    }

    /// Ensures that required keys are present when a service is selected
    fn check_required_keys(
        &self,
        figment_meta: Option<&figment::Metadata>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let make_error = |field: &'static str| {
            let mut err = figment::error::Error::missing_field(field);
            err.metadata = figment_meta.cloned();
            err.profile = Some(figment::Profile::Default);
            err.path = vec![Self::PATH.to_owned(), field.to_owned()];
            err
        };

        if self.site_key.is_none() {
            return Err(make_error("site_key").into());
        }
        if self.secret_key.is_none() {
            return Err(make_error("secret_key").into());
        }
        Ok(())
    }
}

impl ConfigurationSection for CaptchaConfig {
    const PATH: &'static str = "captcha";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let figment_meta = figment.find_metadata(Self::PATH);

        // Only reCAPTCHA v2 currently mandates both keys during validation
        if matches!(self.service, Some(CaptchaServiceKind::RecaptchaV2)) {
            self.check_required_keys(figment_meta)?;
        }

        Ok(())
    }
}
