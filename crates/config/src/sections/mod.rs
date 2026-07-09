// ── Root Configuration Module ──
//
// Aggregates all configuration sections and provides the top-level
// config structs used throughout the application.

use anyhow::bail;
use camino::Utf8PathBuf;
use rand_core::RngCore as Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Sub-module declarations ──

mod account;
mod branding;
mod captcha;
mod clients;
mod arkret;
mod database;
mod email;
mod experimental;
mod http;
mod passwords;
mod policy;
mod rate_limiting;
mod secrets;
pub mod sms;
mod storage;
mod telemetry;
mod templates;
mod upstream_oauth;

// ── Re-exports ──

pub use self::account::AccountConfig;
pub use self::branding::BrandingConfig;
pub use self::captcha::{CaptchaConfig, CaptchaServiceKind};
pub use self::clients::{ClientAuthMethodConfig, ClientConfig, ClientsConfig};
pub use self::arkret::{
    CokretConfig, DeploymentProfileConfig, IdentityRegistryConfig, IdentityRegistryKind,
    PrincipalMethodConfig, PrincipalServerConfig, StaridConfig,
};
pub use self::database::{DatabaseConfig, PgSslMode};
pub use self::email::{
    AwsSesEmailProviderConfig, AwsSesWebhookConfig, BrevoEmailProviderConfig, BrevoWebhookConfig,
    EmailConfig, EmailProviderConfig, EmailSmtpMode, HttpWebhookEmailProviderConfig,
    PaloudInternalEmailProviderConfig, ResendEmailProviderConfig, ResendWebhookConfig,
    SendgridEmailProviderConfig, SendgridWebhookConfig, SendmailEmailProviderConfig,
    SmtpEmailProviderConfig, TwilioEmailProviderConfig,
};
pub use self::experimental::{ExperimentalConfig, MAX_ACCESS_TOKEN_TTL_SECS};
pub use self::http::{
    BindConfig as HttpBindConfig, HstsConfig as HttpHstsConfig, HttpConfig,
    ListenerConfig as HttpListenerConfig, Resource as HttpResource, TlsConfig as HttpTlsConfig,
    UnixOrTcp,
};
pub use self::passwords::{
    Algorithm as PasswordAlgorithm, HashingScheme as PasswordHashingScheme, PasswordsConfig,
};
pub use self::policy::{PolicyConfig, PolicyEngine};
pub use self::rate_limiting::{RateLimiterConfiguration, RateLimitingConfig};
pub use self::secrets::SecretsConfig;
pub use self::sms::{
    AliyunSmsProviderConfig, HttpWebhookSmsProviderConfig, PaloudInternalSmsProviderConfig,
    SmsConfig, SmsProviderConfig, TencentCloudSmsProviderConfig, TwilioSmsProviderConfig,
};
pub use self::storage::StorageConfig;
pub use self::telemetry::{
    MetricsConfig, MetricsExporterKind, Propagator, TelemetryConfig, TracingConfig,
    TracingExporterKind,
};
pub use self::templates::TemplatesConfig;
pub use self::upstream_oauth::{
    ClaimsImports as UpstreamOAuthClaimsImports, DiscoveryMode as UpstreamOAuthDiscoveryMode,
    EmailImportPreference as UpstreamOAuthEmailImportPreference,
    ImportAction as UpstreamOAuthImportAction,
    OnBackchannelLogout as UpstreamOAuthOnBackchannelLogout, OnConflict as UpstreamOAuthOnConflict,
    PkceMethod as UpstreamOAuthPkceMethod, Provider as UpstreamOAuthProvider,
    ResponseMode as UpstreamOAuthResponseMode, TokenAuthMethod as UpstreamOAuthTokenAuthMethod,
    UpstreamOAuthConfig,
};
use crate::util::ConfigurationSection;

// ── Client Secret ──

/// Represents a client secret that can be provided inline or loaded from a
/// file.
#[derive(Clone, Debug)]
pub enum ClientSecret {
    /// Path to the file containing the client secret.
    File(Utf8PathBuf),

    /// Client secret value.
    Value(String),
}

impl ClientSecret {
    /// Resolves and returns the secret string.
    ///
    /// When the secret references a file, the contents are read asynchronously.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub async fn value(&self) -> anyhow::Result<String> {
        match self {
            Self::File(path) => Ok(tokio::fs::read_to_string(path).await?),
            Self::Value(val) => Ok(val.clone()),
        }
    }
}

/// Serialization helper for client secret fields (inline value or file path)
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct ClientSecretRaw {
    /// Path to the file containing the client secret. The client secret is used
    /// by the `client_secret_basic`, `client_secret_post` and
    /// `client_secret_jwt` authentication methods.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret_file: Option<Utf8PathBuf>,

    /// Alternative to `client_secret_file`: Reads the client secret directly
    /// from the config.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

impl TryFrom<ClientSecretRaw> for Option<ClientSecret> {
    type Error = anyhow::Error;

    fn try_from(raw: ClientSecretRaw) -> Result<Self, Self::Error> {
        match (raw.client_secret, raw.client_secret_file) {
            (None, None) => Ok(None),
            (Some(val), None) => Ok(Some(ClientSecret::Value(val))),
            (None, Some(path)) => Ok(Some(ClientSecret::File(path))),
            (Some(_), Some(_)) => {
                bail!("Cannot specify both `client_secret` and `client_secret_file`")
            }
        }
    }
}

impl From<Option<ClientSecret>> for ClientSecretRaw {
    fn from(secret: Option<ClientSecret>) -> Self {
        match secret {
            None => ClientSecretRaw {
                client_secret: None,
                client_secret_file: None,
            },
            Some(ClientSecret::Value(val)) => ClientSecretRaw {
                client_secret: Some(val),
                client_secret_file: None,
            },
            Some(ClientSecret::File(path)) => ClientSecretRaw {
                client_secret: None,
                client_secret_file: Some(path),
            },
        }
    }
}

// ── Root Configuration ──

/// Top-level application configuration encompassing all sections
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RootConfig {
    /// List of OAuth/OIDC clients config
    #[serde(default, skip_serializing_if = "ClientsConfig::is_default")]
    pub clients: ClientsConfig,

    /// Configuration of the HTTP server
    #[serde(default)]
    pub http: HttpConfig,

    /// Database connection configuration
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Arkret-specific audiences, DIDs, and downstream integration metadata
    #[serde(default, skip_serializing_if = "CokretConfig::is_default")]
    pub arkret: CokretConfig,

    /// Configuration related to sending monitoring data
    #[serde(default, skip_serializing_if = "TelemetryConfig::is_default")]
    pub telemetry: TelemetryConfig,

    /// Configuration related to templates
    #[serde(default, skip_serializing_if = "TemplatesConfig::is_default")]
    pub templates: TemplatesConfig,

    /// Configuration related to sending emails
    #[serde(default)]
    pub email: EmailConfig,

    /// Configuration related to sending SMS messages
    #[serde(default, skip_serializing_if = "SmsConfig::is_default")]
    pub sms: SmsConfig,

    /// Application secrets
    pub secrets: SecretsConfig,

    /// Configuration related to user passwords
    #[serde(default)]
    pub passwords: PasswordsConfig,

    /// Configuration related to the policy engine
    #[serde(default, skip_serializing_if = "PolicyConfig::is_default")]
    pub policy: PolicyConfig,

    /// Configuration related to limiting the rate of user actions to prevent
    /// abuse
    #[serde(default, skip_serializing_if = "RateLimitingConfig::is_default")]
    pub rate_limiting: RateLimitingConfig,

    /// Configuration related to upstream OAuth providers
    #[serde(default, skip_serializing_if = "UpstreamOAuthConfig::is_default")]
    pub upstream_oauth: UpstreamOAuthConfig,

    /// Configuration section for tweaking the branding of the service
    #[serde(default, skip_serializing_if = "BrandingConfig::is_default")]
    pub branding: BrandingConfig,

    /// Configuration section to setup CAPTCHA protection on a few operations
    #[serde(default, skip_serializing_if = "CaptchaConfig::is_default")]
    pub captcha: CaptchaConfig,

    /// Configuration section to configure features related to account
    /// management
    #[serde(default, skip_serializing_if = "AccountConfig::is_default")]
    pub account: AccountConfig,

    /// Experimental configuration options
    #[serde(default, skip_serializing_if = "ExperimentalConfig::is_default")]
    pub experimental: ExperimentalConfig,

    /// Configuration for file/media storage backend
    #[serde(default, skip_serializing_if = "StorageConfig::is_default")]
    pub storage: StorageConfig,
}

impl ConfigurationSection for RootConfig {
    const PATH: &'static str = "";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Validate each sub-section in a deterministic order
        type SectionValidator<'a> =
            &'a dyn Fn(
                &figment::Figment,
            )
                -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
        let sections: &[SectionValidator<'_>] = &[
            &|f| self.clients.validate(f),
            &|f| self.http.validate(f),
            &|f| self.database.validate(f),
            &|f| self.arkret.validate(f),
            &|f| self.telemetry.validate(f),
            &|f| self.templates.validate(f),
            &|f| self.email.validate(f),
            &|f| self.sms.validate(f),
            &|f| self.passwords.validate(f),
            &|f| self.secrets.validate(f),
            &|f| self.policy.validate(f),
            &|f| self.rate_limiting.validate(f),
            &|f| self.upstream_oauth.validate(f),
            &|f| self.branding.validate(f),
            &|f| self.captcha.validate(f),
            &|f| self.account.validate(f),
            &|f| self.experimental.validate(f),
            &|f| self.storage.validate(f),
        ];

        for validate_fn in sections {
            validate_fn(figment)?;
        }

        Ok(())
    }
}

impl RootConfig {
    /// Generate a new configuration with random secrets
    ///
    /// # Errors
    ///
    /// Returns an error if the secrets could not be generated
    pub async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        let secrets = SecretsConfig::generate(&mut rng).await?;
        Ok(Self {
            secrets,
            clients: ClientsConfig::default(),
            http: HttpConfig::default(),
            database: DatabaseConfig::default(),
            arkret: CokretConfig::default(),
            telemetry: TelemetryConfig::default(),
            templates: TemplatesConfig::default(),
            email: EmailConfig::default(),
            sms: SmsConfig::default(),
            passwords: PasswordsConfig::default(),
            policy: PolicyConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            upstream_oauth: UpstreamOAuthConfig::default(),
            branding: BrandingConfig::default(),
            captcha: CaptchaConfig::default(),
            account: AccountConfig::default(),
            experimental: ExperimentalConfig::default(),
            storage: StorageConfig::default(),
        })
    }

    /// Configuration used in tests
    #[must_use]
    pub fn test() -> Self {
        Self {
            secrets: SecretsConfig::test(),
            clients: ClientsConfig::default(),
            http: HttpConfig::default(),
            database: DatabaseConfig::default(),
            arkret: CokretConfig::default(),
            telemetry: TelemetryConfig::default(),
            templates: TemplatesConfig::default(),
            passwords: PasswordsConfig::default(),
            email: EmailConfig::default(),
            sms: SmsConfig::default(),
            policy: PolicyConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            upstream_oauth: UpstreamOAuthConfig::default(),
            branding: BrandingConfig::default(),
            captcha: CaptchaConfig::default(),
            account: AccountConfig::default(),
            experimental: ExperimentalConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

// ── App Configuration (server subset) ──

/// Partial configuration actually used by the server
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub arkret: CokretConfig,

    #[serde(default)]
    pub templates: TemplatesConfig,

    #[serde(default)]
    pub email: EmailConfig,

    #[serde(default)]
    pub sms: SmsConfig,

    pub secrets: SecretsConfig,

    #[serde(default)]
    pub passwords: PasswordsConfig,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,

    #[serde(default)]
    pub branding: BrandingConfig,

    #[serde(default)]
    pub captcha: CaptchaConfig,

    #[serde(default)]
    pub account: AccountConfig,

    #[serde(default)]
    pub experimental: ExperimentalConfig,

    #[serde(default)]
    pub storage: StorageConfig,
}

impl ConfigurationSection for AppConfig {
    const PATH: &'static str = "";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.http.validate(figment)?;
        self.database.validate(figment)?;
        self.arkret.validate(figment)?;
        self.templates.validate(figment)?;
        self.email.validate(figment)?;
        self.sms.validate(figment)?;
        self.passwords.validate(figment)?;
        self.secrets.validate(figment)?;
        self.policy.validate(figment)?;
        self.rate_limiting.validate(figment)?;
        self.branding.validate(figment)?;
        self.captcha.validate(figment)?;
        self.account.validate(figment)?;
        self.experimental.validate(figment)?;
        self.storage.validate(figment)?;

        Ok(())
    }
}

// ── Sync Configuration (config sync subset) ──

/// Partial config used by the `coauth config sync` command
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub database: DatabaseConfig,

    pub secrets: SecretsConfig,

    #[serde(default)]
    pub clients: ClientsConfig,

    #[serde(default)]
    pub upstream_oauth: UpstreamOAuthConfig,
}

impl ConfigurationSection for SyncConfig {
    const PATH: &'static str = "";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.database.validate(figment)?;
        self.secrets.validate(figment)?;
        self.clients.validate(figment)?;
        self.upstream_oauth.validate(figment)?;

        Ok(())
    }
}
