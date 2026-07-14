use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::str::FromStr;

use coauth_email_types::Mailbox;
use schemars::JsonSchema;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

/// Wire encryption mode for the SMTP relay
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EmailSmtpMode {
    /// Unencrypted connection
    Plain,
    /// Opportunistic upgrade (`STARTTLS`)
    StartTls,
    /// Implicit TLS from the start
    Tls,
}

/// SMTP relay delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SmtpEmailProviderConfig {
    /// SMTP connection encryption mode
    pub mode: EmailSmtpMode,

    /// SMTP relay hostname
    #[schemars(with = "crate::schema::Hostname")]
    pub hostname: String,

    /// SMTP relay port (defaults: 25 plain, 465 TLS, 587 STARTTLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: Option<NonZeroU16>,

    /// SMTP authentication username (must accompany `password`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// SMTP authentication password (must accompany `username`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

fn sendmail_command_default() -> String {
    "sendmail".to_owned()
}

fn resend_base_url_default() -> String {
    "https://api.resend.com".to_owned()
}

fn sendgrid_base_url_default() -> String {
    "https://api.sendgrid.com".to_owned()
}

fn brevo_base_url_default() -> String {
    "https://api.brevo.com".to_owned()
}

fn email_webhook_max_age_seconds_default() -> u64 {
    300
}

fn aws_sns_allowed_signing_cert_url_prefixes_default() -> Vec<String> {
    vec!["https://sns.".to_owned(), "https://sns-".to_owned()]
}

/// Resend webhook verification settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResendWebhookConfig {
    /// Svix/Resend webhook signing secret
    pub signing_secret: String,

    /// Maximum accepted age for signed webhook timestamps
    #[serde(default = "email_webhook_max_age_seconds_default")]
    pub max_age_seconds: u64,
}

/// `SendGrid` event webhook verification settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SendgridWebhookConfig {
    /// PEM-encoded public key used to verify signed event webhooks
    pub public_key_pem: String,
}

/// Brevo webhook request validation settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct BrevoWebhookConfig {
    /// Expected static headers attached by Brevo when invoking the webhook URL
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// AWS SES feedback ingestion settings delivered through SNS
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AwsSesWebhookConfig {
    /// SNS topic ARN allowed to post SES delivery feedback to this endpoint
    pub topic_arn: String,

    /// Automatically confirm `SubscriptionConfirmation` callbacks
    #[serde(default)]
    pub auto_confirm_subscription: bool,

    /// Allowed HTTPS prefixes for `SigningCertURL`
    #[serde(
        default = "aws_sns_allowed_signing_cert_url_prefixes_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_signing_cert_url_prefixes: Vec<String>,
}

/// Sendmail delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SendmailEmailProviderConfig {
    /// Path to the sendmail-compatible binary
    #[serde(default = "sendmail_command_default")]
    pub command: String,
}

/// Generic HTTP email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct HttpWebhookEmailProviderConfig {
    /// API endpoint accepting outbound email requests
    pub url: String,

    /// Optional bearer token sent as `Authorization: Bearer ...`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Static headers to attach to every outbound request
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// Paloud internal notification email delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct PaloudInternalEmailProviderConfig {
    /// Fully qualified Paloud internal email dispatch endpoint
    pub url: String,

    /// Shared key identifier sent in `X-Paloud-Key-Id`
    pub key_id: String,

    /// Shared secret used to sign the request with `HMAC-SHA256`
    pub secret: String,

    /// Optional workspace UUID or subdomain used for provider routing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

/// Resend email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResendEmailProviderConfig {
    /// Resend API key
    pub api_key: String,

    /// Base URL for the Resend API
    #[serde(default = "resend_base_url_default")]
    pub base_url: String,

    /// Optional webhook verification settings for asynchronous delivery events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<ResendWebhookConfig>,
}

/// `SendGrid` email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SendgridEmailProviderConfig {
    /// `SendGrid` API key
    pub api_key: String,

    /// Base URL for the `SendGrid` API
    #[serde(default = "sendgrid_base_url_default")]
    pub base_url: String,

    /// Optional webhook verification settings for asynchronous delivery events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<SendgridWebhookConfig>,
}

/// Twilio email API delivery settings.
///
/// Twilio email delivery is implemented via Twilio `SendGrid`'s mail send API.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TwilioEmailProviderConfig {
    /// Twilio `SendGrid` API key
    pub api_key: String,

    /// Base URL for the Twilio `SendGrid` API
    #[serde(default = "sendgrid_base_url_default")]
    pub base_url: String,

    /// Optional webhook verification settings for asynchronous delivery events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<SendgridWebhookConfig>,
}

/// Brevo transactional email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BrevoEmailProviderConfig {
    /// Brevo API key
    pub api_key: String,

    /// Base URL for the Brevo API
    #[serde(default = "brevo_base_url_default")]
    pub base_url: String,

    /// Optional webhook validation settings for asynchronous delivery events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<BrevoWebhookConfig>,
}

/// AWS SES API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AwsSesEmailProviderConfig {
    /// AWS region that hosts the SES API endpoint
    pub region: String,

    /// AWS access key ID
    pub access_key_id: String,

    /// AWS secret access key
    pub secret_access_key: String,

    /// Optional AWS session token for temporary credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,

    /// Optional SES endpoint override, useful for proxies or AWS partitions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Optional SES configuration set name applied to every message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_set_name: Option<String>,

    /// Optional webhook settings for SNS-delivered delivery feedback
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<AwsSesWebhookConfig>,
}

/// Which provider delivers outbound emails
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailProviderConfig {
    /// Silently discard all emails (useful for development)
    #[default]
    Blackhole,

    /// Relay through an SMTP server
    Smtp(SmtpEmailProviderConfig),

    /// Pipe through the local `sendmail` binary
    Sendmail(SendmailEmailProviderConfig),

    /// Submit email payloads to a generic HTTP endpoint
    HttpWebhook(HttpWebhookEmailProviderConfig),

    /// Submit email payloads to Paloud's internal notification API
    PaloudInternal(PaloudInternalEmailProviderConfig),

    /// Deliver through the Resend email API
    Resend(ResendEmailProviderConfig),

    /// Deliver through the `SendGrid` email API
    Sendgrid(SendgridEmailProviderConfig),

    /// Deliver through Twilio `SendGrid`
    Twilio(TwilioEmailProviderConfig),

    /// Deliver through the Brevo transactional email API
    Brevo(BrevoEmailProviderConfig),

    /// Deliver through the AWS SES v2 email API
    AwsSes(AwsSesEmailProviderConfig),
}

const DEFAULT_FROM_ADDRESS: &str = r#""Authentication Service" <root@localhost>"#;

fn from_address_default() -> String {
    DEFAULT_FROM_ADDRESS.to_owned()
}

/// Outbound email delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    /// Envelope From / sender address
    #[serde(default = "from_address_default")]
    pub from: String,

    /// Reply-To header value
    #[serde(default = "from_address_default")]
    pub reply_to: String,

    /// Active email delivery provider
    #[serde(default)]
    pub provider: EmailProviderConfig,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            from: from_address_default(),
            reply_to: from_address_default(),
            provider: EmailProviderConfig::Blackhole,
        }
    }
}

impl ConfigurationSection for EmailConfig {
    const PATH: &'static str = "email";

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

        if let Err(error) = Mailbox::from_str(&self.from) {
            return Err(error_on_field(figment::error::Error::custom(error), "from").into());
        }

        if let Err(error) = Mailbox::from_str(&self.reply_to) {
            return Err(error_on_field(figment::error::Error::custom(error), "reply_to").into());
        }

        match &self.provider {
            EmailProviderConfig::Blackhole => {}

            EmailProviderConfig::Smtp(provider) => {
                match (provider.username.is_some(), provider.password.is_some()) {
                    (true, false) => {
                        return Err(error_on_field(
                            figment::error::Error::missing_field("password"),
                            "provider.password",
                        )
                        .into());
                    }
                    (false, true) => {
                        return Err(error_on_field(
                            figment::error::Error::missing_field("username"),
                            "provider.username",
                        )
                        .into());
                    }
                    _ => {}
                }
            }

            EmailProviderConfig::Sendmail(provider) => {
                ensure_non_empty(&provider.command, "provider.command")?;
            }

            EmailProviderConfig::HttpWebhook(provider) => {
                ensure_valid_url(&provider.url, "provider.url")?;
            }

            EmailProviderConfig::PaloudInternal(provider) => {
                ensure_valid_url(&provider.url, "provider.url")?;
                ensure_non_empty(&provider.key_id, "provider.key_id")?;
                ensure_non_empty(&provider.secret, "provider.secret")?;
            }

            EmailProviderConfig::Resend(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
                if let Some(webhook) = &provider.webhook {
                    ensure_non_empty(&webhook.signing_secret, "provider.webhook.signing_secret")?;
                    if webhook.max_age_seconds == 0 {
                        return Err(error_on_field(
                            figment::error::Error::custom(
                                "provider.webhook.max_age_seconds must be greater than zero",
                            ),
                            "provider.webhook.max_age_seconds",
                        )
                        .into());
                    }
                }
            }

            EmailProviderConfig::Sendgrid(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
                if let Some(webhook) = &provider.webhook {
                    ensure_non_empty(&webhook.public_key_pem, "provider.webhook.public_key_pem")?;
                }
            }

            EmailProviderConfig::Twilio(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
                if let Some(webhook) = &provider.webhook {
                    ensure_non_empty(&webhook.public_key_pem, "provider.webhook.public_key_pem")?;
                }
            }

            EmailProviderConfig::Brevo(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
                if let Some(webhook) = &provider.webhook
                    && webhook.headers.is_empty()
                {
                    return Err(error_on_field(
                        figment::error::Error::custom("provider.webhook.headers must not be empty"),
                        "provider.webhook.headers",
                    )
                    .into());
                }
            }

            EmailProviderConfig::AwsSes(provider) => {
                ensure_non_empty(&provider.region, "provider.region")?;
                ensure_non_empty(&provider.access_key_id, "provider.access_key_id")?;
                ensure_non_empty(&provider.secret_access_key, "provider.secret_access_key")?;

                if let Some(endpoint) = &provider.endpoint {
                    ensure_valid_url(endpoint, "provider.endpoint")?;
                }

                if let Some(webhook) = &provider.webhook {
                    ensure_non_empty(&webhook.topic_arn, "provider.webhook.topic_arn")?;
                    if webhook.allowed_signing_cert_url_prefixes.is_empty() {
                        return Err(error_on_field(
                            figment::error::Error::custom(
                                "provider.webhook.allowed_signing_cert_url_prefixes must not be empty",
                            ),
                            "provider.webhook.allowed_signing_cert_url_prefixes",
                        )
                        .into());
                    }
                }
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
    fn load_smtp_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: smtp
                        mode: tls
                        hostname: smtp.example.com
                        port: 465
                        username: smtp-user
                        password: smtp-password
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<EmailConfig>("email")?;

            assert_eq!(config.from, "coauth <noreply@example.com>");
            match config.provider {
                EmailProviderConfig::Smtp(provider) => {
                    assert_eq!(provider.hostname, "smtp.example.com");
                    assert_eq!(provider.port.map(NonZeroU16::get), Some(465));
                }
                other => panic!("expected smtp provider, got {other:?}"),
            }

            Ok(())
        });
    }

    #[test]
    fn load_resend_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: resend
                        api_key: re_test_123
                        base_url: https://api.resend.com
                        webhook:
                          signing_secret: whsec_test_123
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<EmailConfig>("email")?;

            match config.provider {
                EmailProviderConfig::Resend(provider) => {
                    assert_eq!(provider.api_key, "re_test_123");
                    assert_eq!(provider.base_url, "https://api.resend.com");
                    assert_eq!(
                        provider
                            .webhook
                            .as_ref()
                            .map(|webhook| webhook.signing_secret.as_str()),
                        Some("whsec_test_123")
                    );
                }
                other => panic!("expected resend provider, got {other:?}"),
            }

            Ok(())
        });
    }

    #[test]
    fn reject_unpaired_smtp_credentials() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: smtp
                        mode: starttls
                        hostname: smtp.example.com
                        username: smtp-user
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("password"));

            Ok(())
        });
    }

    #[test]
    fn reject_invalid_http_webhook_url() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: http_webhook
                        url: '::not-a-url::'
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.url"));

            Ok(())
        });
    }

    #[test]
    fn reject_invalid_sendgrid_base_url() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: sendgrid
                        api_key: SG.test
                        base_url: '::not-a-url::'
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.base_url"));

            Ok(())
        });
    }

    #[test]
    fn reject_empty_aws_ses_region() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: aws_ses
                        region: ''
                        access_key_id: AKIATEST
                        secret_access_key: secret
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.region"));

            Ok(())
        });
    }

    #[test]
    fn reject_empty_brevo_webhook_headers() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    email:
                      from: 'coauth <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: brevo
                        api_key: brevo_test
                        webhook:
                          headers: {}
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.webhook.headers"));

            Ok(())
        });
    }

    #[test]
    fn load_paloud_internal_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: '"Auth" <auth@example.com>'
                      reply_to: '"Auth" <auth@example.com>'
                      provider:
                        type: paloud_internal
                        url: https://tenant.meldry.com/api/v1/internal/notifications/email/send
                        key_id: coauth-control-dev
                        secret: super-secret
                        workspace: demo
                "#,
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;

            match config.provider {
                EmailProviderConfig::PaloudInternal(provider) => {
                    assert_eq!(
                        provider.url,
                        "https://tenant.meldry.com/api/v1/internal/notifications/email/send"
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
}
