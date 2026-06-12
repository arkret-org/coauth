//! Configuration related to sending SMS messages

use schemars::JsonSchema;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

/// Twilio SMS delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TwilioSmsProviderConfig {
    /// Twilio account SID
    pub account_sid: String,

    /// Twilio auth token
    pub auth_token: String,

    /// Phone number to send SMS from
    pub from_number: String,
}

/// Generic HTTP SMS API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpWebhookSmsProviderConfig {
    /// API endpoint accepting outbound SMS requests
    pub url: String,

    /// Optional bearer token sent as `Authorization: Bearer ...`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Phone number to send SMS from
    pub from_number: String,
}

/// Aliyun SMS delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AliyunSmsProviderConfig {
    /// Aliyun access key ID
    pub access_key_id: String,

    /// Aliyun access key secret
    pub access_key_secret: String,

    /// Aliyun sign name (签名)
    pub sign_name: String,

    /// Aliyun template code (模板编号)
    pub template_code: String,
}

/// Tencent Cloud SMS delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TencentCloudSmsProviderConfig {
    /// Tencent Cloud secret ID
    pub secret_id: String,

    /// Tencent Cloud secret key
    pub secret_key: String,

    /// Tencent Cloud SDK app ID
    pub sdk_app_id: String,

    /// Tencent Cloud sign name (签名)
    pub sign_name: String,

    /// Tencent Cloud template ID (模板 ID)
    pub template_id: String,
}

/// Paloud internal notification SMS delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PaloudInternalSmsProviderConfig {
    /// Fully qualified Paloud internal SMS dispatch endpoint
    pub url: String,

    /// Shared key identifier sent in `X-Paloud-Key-Id`
    pub key_id: String,

    /// Shared secret used to sign the request with `HMAC-SHA256`
    pub secret: String,

    /// Optional workspace UUID or subdomain used for provider routing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

/// Which provider delivers outbound SMS messages
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SmsProviderConfig {
    /// Silently discard all SMS messages (useful for development)
    #[default]
    Blackhole,

    /// Deliver through Twilio
    Twilio(TwilioSmsProviderConfig),

    /// Submit SMS payloads to a generic HTTP endpoint
    HttpWebhook(HttpWebhookSmsProviderConfig),

    /// Deliver through Aliyun SMS
    AliyunSms(AliyunSmsProviderConfig),

    /// Deliver through Tencent Cloud SMS
    TencentCloudSms(TencentCloudSmsProviderConfig),

    /// Submit SMS payloads to Paloud's internal notification API
    PaloudInternal(PaloudInternalSmsProviderConfig),
}

/// Configuration related to sending SMS messages
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SmsConfig {
    /// Active SMS delivery provider
    #[serde(default)]
    pub provider: SmsProviderConfig,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            provider: SmsProviderConfig::Blackhole,
        }
    }
}

impl SmsConfig {
    pub(crate) fn is_default(&self) -> bool {
        matches!(&self.provider, SmsProviderConfig::Blackhole)
    }
}

impl ConfigurationSection for SmsConfig {
    const PATH: &'static str = "sms";

    #[allow(clippy::result_large_err)]
    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH);

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.to_owned(), field.to_owned()];
            error
        };

        let ensure_non_empty =
            |value: &str, field: &'static str| -> Result<(), figment::error::Error> {
                if value.trim().is_empty() {
                    return Err(error_on_field(
                        figment::error::Error::custom("value must not be empty"),
                        field,
                    ));
                }

                Ok(())
            };

        let ensure_valid_url =
            |value: &str, field: &'static str| -> Result<(), figment::error::Error> {
                Url::parse(value)
                    .map_err(|error| error_on_field(figment::error::Error::custom(error), field))?;
                Ok(())
            };

        match &self.provider {
            SmsProviderConfig::Blackhole => {}

            SmsProviderConfig::Twilio(provider) => {
                ensure_non_empty(&provider.account_sid, "provider.account_sid")?;
                ensure_non_empty(&provider.auth_token, "provider.auth_token")?;
                ensure_non_empty(&provider.from_number, "provider.from_number")?;
            }

            SmsProviderConfig::HttpWebhook(provider) => {
                ensure_valid_url(&provider.url, "provider.url")?;
                ensure_non_empty(&provider.from_number, "provider.from_number")?;
            }

            SmsProviderConfig::AliyunSms(provider) => {
                ensure_non_empty(&provider.access_key_id, "provider.access_key_id")?;
                ensure_non_empty(&provider.access_key_secret, "provider.access_key_secret")?;
                ensure_non_empty(&provider.sign_name, "provider.sign_name")?;
                ensure_non_empty(&provider.template_code, "provider.template_code")?;
            }

            SmsProviderConfig::TencentCloudSms(provider) => {
                ensure_non_empty(&provider.secret_id, "provider.secret_id")?;
                ensure_non_empty(&provider.secret_key, "provider.secret_key")?;
                ensure_non_empty(&provider.sdk_app_id, "provider.sdk_app_id")?;
                ensure_non_empty(&provider.sign_name, "provider.sign_name")?;
                ensure_non_empty(&provider.template_id, "provider.template_id")?;
            }

            SmsProviderConfig::PaloudInternal(provider) => {
                ensure_valid_url(&provider.url, "provider.url")?;
                ensure_non_empty(&provider.key_id, "provider.key_id")?;
                ensure_non_empty(&provider.secret, "provider.secret")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::result_large_err)]
    use figment::providers::{Format, Yaml};
    use figment::{Figment, Jail};

    use super::*;

    #[test]
    fn load_twilio_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    sms:
                      provider:
                        type: twilio
                        account_sid: AC123
                        auth_token: secret
                        from_number: "+12065550123"
                "#,
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<SmsConfig>("sms")?;

            match config.provider {
                SmsProviderConfig::Twilio(provider) => {
                    assert_eq!(provider.account_sid, "AC123");
                    assert_eq!(provider.auth_token, "secret");
                    assert_eq!(provider.from_number, "+12065550123");
                }
                other => panic!("expected twilio provider, got {other:?}"),
            }

            Ok(())
        });
    }

    #[test]
    fn load_paloud_internal_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    sms:
                      provider:
                        type: paloud_internal
                        url: https://tenant.meldry.com/api/v1/internal/notifications/sms/send
                        key_id: coauth-control-dev
                        secret: super-secret
                        workspace: demo
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<SmsConfig>("sms")?;

            match config.provider {
                SmsProviderConfig::PaloudInternal(provider) => {
                    assert_eq!(
                        provider.url,
                        "https://tenant.meldry.com/api/v1/internal/notifications/sms/send"
                    );
                    assert_eq!(provider.key_id, "coauth-control-dev");
                    assert_eq!(provider.secret, "super-secret");
                    assert_eq!(provider.workspace.as_deref(), Some("demo"));
                }
                other => panic!("unexpected provider: {other:?}"),
            }

            Ok(())
        });
    }

    #[test]
    fn reject_invalid_paloud_internal_url() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    sms:
                      provider:
                        type: paloud_internal
                        url: '::not-a-url::'
                        key_id: coauth-control-dev
                        secret: super-secret
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<SmsConfig>("sms")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.url"));

            Ok(())
        });
    }
}
