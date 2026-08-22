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
use std::fmt;
use std::num::NonZeroU16;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use async_trait::async_trait;
use coauth_email_types::Mailbox;
use mail_send::SmtpClientBuilder;
use reqwest::Client;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use url::Url;

use self::aws_ses::AwsSesProvider;
use self::common::{build_message, build_raw_message};
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

/// Username and password used to authenticate to an SMTP server.
#[derive(Clone)]
pub struct SmtpCredentials {
    username: String,
    password: String,
}

impl SmtpCredentials {
    /// Construct SMTP credentials.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for SmtpCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
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
    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError>;

    /// Performs a lightweight connectivity check when the provider supports
    /// it.
    async fn test_connection(&self, from: &Mailbox) -> Result<(), EmailTransportError>;
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
        credentials: Option<SmtpCredentials>,
    ) -> Result<Self, SmtpError> {
        let provider = SmtpProvider {
            mode,
            hostname: hostname.to_owned(),
            port: port.map_or_else(|| default_smtp_port(mode), NonZeroU16::get),
            credentials,
        };
        provider.builder()?;
        Ok(Self::new(provider))
    }

    /// Construct a Sendmail transport.
    #[must_use]
    pub fn sendmail(command: Option<impl Into<OsString>>) -> Self {
        Self::new(SendmailProvider {
            command: command.map_or_else(|| OsString::from("sendmail"), Into::into),
        })
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
    pub async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
        self.inner.send(email).await
    }

    /// Test the connection to the underlying transport when supported.
    pub async fn test_connection(&self, from: &Mailbox) -> Result<(), EmailTransportError> {
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
pub enum EmailTransportError {
    /// The payload could not be converted into a provider-specific message.
    #[error("failed to build email message: {0}")]
    Message(#[source] std::io::Error),

    /// The SMTP transport failed.
    #[error(transparent)]
    Smtp(#[from] SmtpError),

    /// The sendmail transport failed.
    #[error(transparent)]
    Sendmail(#[from] SendmailError),

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

/// Errors produced while configuring or communicating with an SMTP server.
#[derive(Debug, Error)]
pub enum SmtpError {
    /// The SMTP client configuration is invalid.
    #[error("invalid SMTP configuration: {0}")]
    Configuration(String),
    /// The SMTP connection or delivery failed.
    #[error(transparent)]
    Delivery(#[from] mail_send::Error),
}

/// Errors produced while invoking a local sendmail-compatible command.
#[derive(Debug, Error)]
pub enum SendmailError {
    /// The sendmail process could not be spawned or communicated with.
    #[error("sendmail I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The spawned process did not expose its standard input pipe.
    #[error("sendmail process did not expose stdin")]
    MissingStdin,
    /// The sendmail process rejected the message.
    #[error("sendmail exited unsuccessfully: {0}")]
    Exit(ExitStatus),
}

struct BlackholeProvider;

#[async_trait]
impl EmailProvider for BlackholeProvider {
    fn binding_key(&self) -> &'static str {
        "email.blackhole"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
        let to: Vec<String> = email.to.iter().map(ToString::to_string).collect();
        tracing::warn!(
            email.to = ?to,
            "An email was supposed to be sent but no email backend is configured"
        );
        Ok(SendResult::default())
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), EmailTransportError> {
        Ok(())
    }
}

struct SmtpProvider {
    mode: SmtpMode,
    hostname: String,
    port: u16,
    credentials: Option<SmtpCredentials>,
}

impl SmtpProvider {
    fn builder(&self) -> Result<SmtpClientBuilder<String>, SmtpError> {
        let mut builder = SmtpClientBuilder::new(self.hostname.clone(), self.port)
            .map_err(SmtpError::Configuration)?;
        if let Some(credentials) = &self.credentials {
            builder =
                builder.credentials((credentials.username.clone(), credentials.password.clone()));
        }
        Ok(builder.implicit_tls(matches!(self.mode, SmtpMode::Tls)))
    }
}

#[async_trait]
impl EmailProvider for SmtpProvider {
    fn binding_key(&self) -> &'static str {
        "email.smtp"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
        let builder = self.builder()?;
        if matches!(self.mode, SmtpMode::Plain) {
            let mut client = builder.connect_plain().await.map_err(SmtpError::Delivery)?;
            client
                .send(build_message(email)?)
                .await
                .map_err(SmtpError::Delivery)?;
            client.quit().await.map_err(SmtpError::Delivery)?;
        } else {
            let mut client = builder.connect().await.map_err(SmtpError::Delivery)?;
            client
                .send(build_message(email)?)
                .await
                .map_err(SmtpError::Delivery)?;
            client.quit().await.map_err(SmtpError::Delivery)?;
        }
        Ok(SendResult::default())
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), EmailTransportError> {
        let builder = self.builder()?;
        if matches!(self.mode, SmtpMode::Plain) {
            builder
                .connect_plain()
                .await
                .map_err(SmtpError::Delivery)?
                .quit()
                .await
                .map_err(SmtpError::Delivery)?;
        } else {
            builder
                .connect()
                .await
                .map_err(SmtpError::Delivery)?
                .quit()
                .await
                .map_err(SmtpError::Delivery)?;
        }
        Ok(())
    }
}

struct SendmailProvider {
    command: OsString,
}

#[async_trait]
impl EmailProvider for SendmailProvider {
    fn binding_key(&self) -> &'static str {
        "email.sendmail"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
        let message = build_raw_message(email)?;
        let mut command = Command::new(&self.command);
        command
            .kill_on_drop(true)
            .arg("-i")
            .arg("-f")
            .arg(email.from.email.as_ref())
            .arg("--")
            .args(email.to.iter().map(|mailbox| mailbox.email.as_ref()))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = command.spawn().map_err(SendmailError::Io)?;
        let mut stdin = child.stdin.take().ok_or(SendmailError::MissingStdin)?;
        stdin.write_all(&message).await.map_err(SendmailError::Io)?;
        drop(stdin);

        let status = child.wait().await.map_err(SendmailError::Io)?;
        if !status.success() {
            return Err(SendmailError::Exit(status).into());
        }
        Ok(SendResult::default())
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), EmailTransportError> {
        Ok(())
    }
}

const fn default_smtp_port(mode: SmtpMode) -> u16 {
    match mode {
        SmtpMode::Plain => 25,
        SmtpMode::StartTls => 587,
        SmtpMode::Tls => 465,
    }
}

#[cfg(test)]
mod tests;
