//! Email transport backends.
//!
//! Server callers inject the backend guarded `reqwest::Client`; this crate
//! stays backend-agnostic and therefore does not depend on `outbound_http`.
#![allow(clippy::disallowed_methods)]

mod aws_ses;
mod common;
mod http_providers;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::sendmail::AsyncSendmailTransport;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncTransport, Tokio1Executor};
use reqwest::Client;
use thiserror::Error;
use url::Url;

use self::aws_ses::AwsSesProvider;
use self::common::build_lettre_message;
#[cfg(test)]
use self::common::{extract_provider_error_code, extract_provider_message_id, provider_error};
use self::http_providers::{
    BrevoProvider, HttpWebhookProvider, PaloudInternalProvider, ResendProvider,
    SendgridLikeProvider,
};

/// Encryption mode to use for SMTP transports.
#[derive(Debug, Clone, Copy)]
pub enum SmtpMode {
    /// Plain text
    Plain,
    /// `StartTLS` (starts as plain text then upgrades to TLS)
    StartTls,
    /// TLS
    Tls,
}

/// Provider-agnostic outbound email payload.
#[derive(Debug, Clone)]
pub struct OutboundEmail {
    /// Envelope sender displayed to recipients.
    pub from: Mailbox,
    /// Optional reply-to address.
    pub reply_to: Option<Mailbox>,
    /// Recipients of the message.
    pub to: Vec<Mailbox>,
    /// Localized subject line.
    pub subject: String,
    /// Plain-text body.
    pub text_body: String,
    /// Optional HTML body.
    pub html_body: Option<String>,
    /// Provider-specific extra headers.
    pub headers: BTreeMap<String, String>,
    /// Provider-specific tags or metadata.
    pub tags: BTreeMap<String, String>,
}

/// Result returned by an email provider after accepting a message.
#[derive(Debug, Clone, Default)]
pub struct SendResult {
    /// Optional provider-side message identifier.
    pub provider_message_id: Option<String>,
}

#[async_trait]
/// A delivery backend capable of accepting rendered email payloads.
pub trait EmailProvider: Send + Sync {
    /// Returns the stable provider binding key recorded on notification
    /// deliveries for this backend.
    fn binding_key(&self) -> &'static str;

    /// Sends a rendered outbound email through the provider.
    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error>;

    /// Performs a lightweight connectivity check when the provider supports
    /// it.
    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error>;
}

/// A cloneable wrapper around an email provider implementation.
#[derive(Clone)]
pub struct Transport {
    inner: Arc<dyn EmailProvider>,
}

impl Default for Transport {
    fn default() -> Self {
        Self::blackhole()
    }
}

impl Transport {
    fn new(provider: impl EmailProvider + 'static) -> Self {
        Self {
            inner: Arc::new(provider),
        }
    }

    /// Construct a blackhole transport.
    #[must_use]
    pub fn blackhole() -> Self {
        Self::new(BlackholeProvider)
    }

    /// Construct a SMTP transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying SMTP transport could not be built.
    pub fn smtp(
        mode: SmtpMode,
        hostname: &str,
        port: Option<NonZeroU16>,
        credentials: Option<Credentials>,
    ) -> Result<Self, lettre::transport::smtp::Error> {
        let mut builder = match mode {
            SmtpMode::Plain => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(hostname),
            SmtpMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(hostname)?,
            SmtpMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(hostname)?,
        };

        if let Some(credentials) = credentials {
            builder = builder.credentials(credentials);
        }

        if let Some(port) = port {
            builder = builder.port(port.into());
        }

        Ok(Self::new(SmtpProvider {
            transport: builder.build(),
        }))
    }

    /// Construct a Sendmail transport.
    #[must_use]
    pub fn sendmail(command: Option<impl Into<OsString>>) -> Self {
        let transport = if let Some(command) = command {
            AsyncSendmailTransport::new_with_command(command)
        } else {
            AsyncSendmailTransport::new()
        };

        Self::new(SendmailProvider { transport })
    }

    /// Construct a generic HTTP webhook email transport.
    #[must_use]
    pub fn http_webhook(
        client: Client,
        url: Url,
        api_key: Option<String>,
        headers: BTreeMap<String, String>,
    ) -> Self {
        Self::new(HttpWebhookProvider {
            client,
            url,
            api_key,
            headers,
        })
    }

    /// Construct a Paloud internal notification API transport.
    #[must_use]
    pub fn paloud_internal(
        client: Client,
        url: Url,
        key_id: String,
        secret: String,
        workspace: Option<String>,
    ) -> Self {
        Self::new(PaloudInternalProvider {
            client,
            url,
            key_id,
            secret,
            workspace,
        })
    }

    /// Construct a Resend email API transport.
    #[must_use]
    pub fn resend(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(ResendProvider {
            client,
            base_url,
            api_key,
        })
    }

    /// Construct a `SendGrid` email API transport.
    #[must_use]
    pub fn sendgrid(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(SendgridLikeProvider {
            client,
            base_url,
            api_key,
            binding_key: "email.sendgrid",
        })
    }

    /// Construct a Twilio `SendGrid` email API transport.
    #[must_use]
    pub fn twilio(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(SendgridLikeProvider {
            client,
            base_url,
            api_key,
            binding_key: "email.twilio",
        })
    }

    /// Construct a Brevo transactional email API transport.
    #[must_use]
    pub fn brevo(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(BrevoProvider {
            client,
            base_url,
            api_key,
        })
    }

    /// Construct an AWS SES v2 email API transport.
    #[must_use]
    pub fn aws_ses(
        client: Client,
        region: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        endpoint: Option<Url>,
        configuration_set_name: Option<String>,
    ) -> Self {
        let endpoint = endpoint.unwrap_or_else(|| {
            Url::parse(&format!("https://email.{region}.amazonaws.com"))
                .expect("default AWS SES endpoint must be valid")
        });

        Self::new(AwsSesProvider {
            client,
            endpoint,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            configuration_set_name,
        })
    }

    /// Send an outbound email through the configured provider.
    pub async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        self.inner.send(email).await
    }

    /// Test the connection to the underlying transport when supported.
    pub async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        self.inner.test_connection(from).await
    }

    /// Return the stable provider binding key for this transport.
    #[must_use]
    pub fn binding_key(&self) -> &'static str {
        self.inner.binding_key()
    }
}

#[derive(Debug, Error)]
/// Errors that can occur while handing an email to a delivery provider.
pub enum Error {
    /// The payload could not be converted into a provider-specific message.
    #[error(transparent)]
    Message(#[from] lettre::error::Error),

    /// The SMTP transport failed.
    #[error(transparent)]
    Smtp(#[from] lettre::transport::smtp::Error),

    /// The sendmail transport failed.
    #[error(transparent)]
    Sendmail(#[from] lettre::transport::sendmail::Error),

    /// The email payload could not be serialized for the provider.
    #[error("failed to serialize email payload: {0}")]
    Json(#[from] serde_json::Error),

    /// The HTTP client failed before a provider response was received.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The provider returned a non-success response payload.
    #[error("email provider returned non-success status {status}")]
    ProviderError {
        /// HTTP status code returned by the provider.
        status: u16,
        /// Optional provider error code.
        code: Option<String>,
        /// Raw response body captured for diagnostics.
        body: String,
        /// Whether the provider failure is safe to retry.
        retryable: bool,
    },
}

struct BlackholeProvider;

#[async_trait]
impl EmailProvider for BlackholeProvider {
    fn binding_key(&self) -> &'static str {
        "email.blackhole"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let to: Vec<String> = email.to.iter().map(ToString::to_string).collect();
        tracing::warn!(
            email.to = ?to,
            "An email was supposed to be sent but no email backend is configured"
        );
        Ok(SendResult::default())
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        Ok(())
    }
}

struct SmtpProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

#[async_trait]
impl EmailProvider for SmtpProvider {
    fn binding_key(&self) -> &'static str {
        "email.smtp"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let message = build_lettre_message(email)?;
        self.transport.send(message).await?;
        Ok(SendResult::default())
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        self.transport.test_connection().await?;
        Ok(())
    }
}

struct SendmailProvider {
    transport: AsyncSendmailTransport<Tokio1Executor>,
}

#[async_trait]
impl EmailProvider for SendmailProvider {
    fn binding_key(&self) -> &'static str {
        "email.sendmail"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let message = build_lettre_message(email)?;
        self.transport.send(message).await?;
        Ok(SendResult::default())
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
