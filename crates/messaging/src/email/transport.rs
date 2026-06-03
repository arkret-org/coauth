//! Email transport backends.
//!
//! Server callers inject the backend guarded `reqwest::Client`; this crate
//! stays backend-agnostic and therefore does not depend on `outbound_http`.
#![allow(clippy::disallowed_methods)]

use std::{collections::BTreeMap, ffi::OsString, num::NonZeroU16, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use lettre::{
    AsyncTransport, Message, Tokio1Executor,
    message::{
        Mailbox, MultiPart, SinglePart,
        header::{HeaderName, HeaderValue},
    },
    transport::{
        sendmail::AsyncSendmailTransport,
        smtp::{AsyncSmtpTransport, authentication::Credentials},
    },
};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;

use crate::crypto::{hex_sha256, hmac_sha256, paloud_internal_nonce, sign_paloud_internal_request};

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

struct HttpWebhookProvider {
    client: Client,
    url: Url,
    api_key: Option<String>,
    headers: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct HttpWebhookRequest<'a> {
    from: String,
    reply_to: Option<String>,
    to: Vec<String>,
    subject: &'a str,
    text_body: &'a str,
    html_body: Option<&'a str>,
    headers: &'a BTreeMap<String, String>,
    tags: &'a BTreeMap<String, String>,
}

#[async_trait]
impl EmailProvider for HttpWebhookProvider {
    fn binding_key(&self) -> &'static str {
        "email.http_webhook"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let payload = HttpWebhookRequest {
            from: email.from.to_string(),
            reply_to: email.reply_to.as_ref().map(ToString::to_string),
            to: email.to.iter().map(ToString::to_string).collect(),
            subject: &email.subject,
            text_body: &email.text_body,
            html_body: email.html_body.as_deref(),
            headers: &email.headers,
            tags: &email.tags,
        };

        let mut request = self.client.post(self.url.clone()).json(&payload);

        if let Some(api_key) = &self.api_key {
            request = request.bearer_auth(api_key);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        execute_provider_request(request).await
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        Ok(())
    }
}

struct PaloudInternalProvider {
    client: Client,
    url: Url,
    key_id: String,
    secret: String,
    workspace: Option<String>,
}

#[derive(Serialize)]
struct PaloudInternalRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<&'a str>,
    recipient: &'a str,
    subject: &'a str,
    body: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<&'a str>,
}

#[async_trait]
impl EmailProvider for PaloudInternalProvider {
    fn binding_key(&self) -> &'static str {
        "email.paloud_internal"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let recipient = match email.to.as_slice() {
            [recipient] => recipient.to_string(),
            _ => {
                return Err(Error::ProviderError {
                    status: 400,
                    code: Some("unsupported_recipient_count".to_owned()),
                    body: "Paloud internal email transport requires exactly one recipient"
                        .to_owned(),
                    retryable: false,
                });
            }
        };
        let payload = PaloudInternalRequest {
            workspace: self
                .workspace
                .as_deref()
                .filter(|value| !value.trim().is_empty()),
            recipient: &recipient,
            subject: &email.subject,
            body: email.html_body.as_deref().unwrap_or(&email.text_body),
            idempotency_key: email
                .tags
                .get("coauth_notification_request_id")
                .map(String::as_str)
                .filter(|value| !value.trim().is_empty()),
        };
        let body = serde_json::to_vec(&payload)?;
        let timestamp = Utc::now().timestamp();
        let nonce = paloud_internal_nonce(timestamp);
        let signature = sign_paloud_internal_request(
            &self.secret,
            Method::POST.as_str(),
            self.url.path(),
            timestamp,
            &nonce,
            &body,
        );

        let request = self
            .client
            .post(self.url.clone())
            .header("X-Paloud-Key-Id", &self.key_id)
            .header("X-Paloud-Timestamp", timestamp.to_string())
            .header("X-Paloud-Nonce", nonce)
            .header("X-Paloud-Signature", signature)
            .header("Content-Type", "application/json")
            .body(body);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        Ok(())
    }
}

struct ResendProvider {
    client: Client,
    base_url: Url,
    api_key: String,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    to: Vec<String>,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<ProviderTag<'a>>,
}

#[derive(Debug, Deserialize)]
struct ResendDomainsResponse {
    #[serde(default)]
    data: Vec<ResendDomain>,
}

#[derive(Debug, Deserialize)]
struct ResendDomain {
    name: String,
    capabilities: ResendDomainCapabilities,
}

#[derive(Debug, Deserialize)]
struct ResendDomainCapabilities {
    sending: String,
}

#[async_trait]
impl EmailProvider for ResendProvider {
    fn binding_key(&self) -> &'static str {
        "email.resend"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let payload = ResendRequest {
            from: email.from.to_string(),
            reply_to: email.reply_to.as_ref().map(ToString::to_string),
            to: email.to.iter().map(ToString::to_string).collect(),
            subject: &email.subject,
            text: Some(email.text_body.as_str()),
            html: email.html_body.as_deref(),
            headers: &email.headers,
            tags: provider_tags(&email.tags),
        };

        let request = self
            .client
            .post(provider_url(&self.base_url, "/emails"))
            .bearer_auth(&self.api_key)
            .json(&payload);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        let response: ResendDomainsResponse = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/domains"))
                .bearer_auth(&self.api_key),
        )
        .await?;

        let sender_domain = sender_domain(from).ok_or_else(|| {
            provider_client_error(
                "invalid_sender",
                format!("sender address {from} does not contain a domain"),
            )
        })?;

        if response.data.iter().any(|domain| {
            domain.name.eq_ignore_ascii_case(&sender_domain)
                && domain.capabilities.sending.eq_ignore_ascii_case("enabled")
        }) {
            return Ok(());
        }

        Err(provider_client_error(
            "sender_domain_unverified",
            format!("Resend domain {sender_domain} is not configured or sending is not enabled"),
        ))
    }
}

struct SendgridLikeProvider {
    client: Client,
    base_url: Url,
    api_key: String,
    binding_key: &'static str,
}

#[derive(Serialize)]
struct ProviderMailbox<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Serialize)]
struct SendgridPersonalization<'a> {
    to: Vec<ProviderMailbox<'a>>,
}

#[derive(Serialize)]
struct SendgridContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct SendgridRequest<'a> {
    personalizations: Vec<SendgridPersonalization<'a>>,
    from: ProviderMailbox<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<ProviderMailbox<'a>>,
    subject: &'a str,
    content: Vec<SendgridContent<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_args: Option<&'a BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct SendgridScopesResponse {
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SendgridAuthenticatedDomain {
    domain: String,
    valid: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SendgridVerifiedSendersResponse {
    #[serde(default)]
    results: Vec<SendgridVerifiedSender>,
}

#[derive(Debug, Deserialize)]
struct SendgridVerifiedSender {
    from_email: String,
    verified: bool,
}

#[async_trait]
impl EmailProvider for SendgridLikeProvider {
    fn binding_key(&self) -> &'static str {
        self.binding_key
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let mut content = vec![SendgridContent {
            content_type: "text/plain",
            value: &email.text_body,
        }];

        if let Some(html) = email.html_body.as_deref() {
            content.push(SendgridContent {
                content_type: "text/html",
                value: html,
            });
        }

        let payload = SendgridRequest {
            personalizations: vec![SendgridPersonalization {
                to: email.to.iter().map(provider_mailbox).collect(),
            }],
            from: provider_mailbox(&email.from),
            reply_to: email.reply_to.as_ref().map(provider_mailbox),
            subject: &email.subject,
            content,
            headers: map_ref(&email.headers),
            custom_args: map_ref(&email.tags),
        };

        let request = self
            .client
            .post(provider_url(&self.base_url, "/v3/mail/send"))
            .bearer_auth(&self.api_key)
            .json(&payload);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        let scopes: SendgridScopesResponse = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/v3/scopes"))
                .bearer_auth(&self.api_key),
        )
        .await?;

        if !scopes.scopes.iter().any(|scope| scope == "mail.send") {
            return Err(provider_client_error(
                "missing_scope",
                "Twilio SendGrid API key is missing the mail.send scope",
            ));
        }

        validate_sendgrid_sender(self, from).await
    }
}

struct BrevoProvider {
    client: Client,
    base_url: Url,
    api_key: String,
}

#[derive(Serialize)]
struct BrevoRequest<'a> {
    sender: ProviderMailbox<'a>,
    to: Vec<ProviderMailbox<'a>>,
    #[serde(rename = "replyTo", skip_serializing_if = "Option::is_none")]
    reply_to: Option<ProviderMailbox<'a>>,
    subject: &'a str,
    #[serde(rename = "textContent")]
    text_content: &'a str,
    #[serde(rename = "htmlContent", skip_serializing_if = "Option::is_none")]
    html_content: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

#[async_trait]
impl EmailProvider for BrevoProvider {
    fn binding_key(&self) -> &'static str {
        "email.brevo"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let payload = BrevoRequest {
            sender: provider_mailbox(&email.from),
            to: email.to.iter().map(provider_mailbox).collect(),
            reply_to: email.reply_to.as_ref().map(provider_mailbox),
            subject: &email.subject,
            text_content: &email.text_body,
            html_content: email.html_body.as_deref(),
            headers: map_ref(&email.headers),
            tags: brevo_tags(&email.tags),
        };

        let request = self
            .client
            .post(provider_url(&self.base_url, "/v3/smtp/email"))
            .header("api-key", &self.api_key)
            .json(&payload);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        let _: serde_json::Value = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/v3/account"))
                .header("api-key", &self.api_key),
        )
        .await?;
        Ok(())
    }
}

struct AwsSesProvider {
    client: Client,
    endpoint: Url,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    configuration_set_name: Option<String>,
}

#[derive(Serialize)]
struct AwsSesRequest<'a> {
    #[serde(rename = "FromEmailAddress")]
    from_email_address: String,
    #[serde(rename = "Destination")]
    destination: AwsSesDestination,
    #[serde(rename = "Content")]
    content: AwsSesContent,
    #[serde(
        rename = "ConfigurationSetName",
        skip_serializing_if = "Option::is_none"
    )]
    configuration_set_name: Option<&'a str>,
    #[serde(rename = "EmailTags", skip_serializing_if = "Vec::is_empty")]
    email_tags: Vec<AwsSesTag<'a>>,
}

#[derive(Serialize)]
struct AwsSesDestination {
    #[serde(rename = "ToAddresses")]
    to_addresses: Vec<String>,
}

#[derive(Serialize)]
struct AwsSesContent {
    #[serde(rename = "Raw")]
    raw: AwsSesRawContent,
}

#[derive(Serialize)]
struct AwsSesRawContent {
    #[serde(rename = "Data")]
    data: String,
}

#[derive(Serialize)]
struct AwsSesTag<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Value")]
    value: &'a str,
}

#[derive(Debug, Deserialize)]
struct AwsSesAccountResponse {
    #[serde(rename = "ProductionAccessEnabled")]
    production_access_enabled: bool,
    #[serde(rename = "SendingEnabled")]
    sending_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct AwsSesIdentityResponse {
    #[serde(rename = "VerificationStatus")]
    verification_status: Option<String>,
    #[serde(rename = "VerifiedForSendingStatus")]
    verified_for_sending_status: bool,
}

#[derive(Serialize)]
struct ProviderTag<'a> {
    name: &'a str,
    value: &'a str,
}

#[async_trait]
impl EmailProvider for AwsSesProvider {
    fn binding_key(&self) -> &'static str {
        "email.aws_ses"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let raw_message = build_lettre_message(email)?.formatted();
        let payload = AwsSesRequest {
            from_email_address: email.from.email.to_string(),
            destination: AwsSesDestination {
                to_addresses: email
                    .to
                    .iter()
                    .map(|mailbox| mailbox.email.to_string())
                    .collect(),
            },
            content: AwsSesContent {
                raw: AwsSesRawContent {
                    data: BASE64.encode(raw_message),
                },
            },
            configuration_set_name: self.configuration_set_name.as_deref(),
            email_tags: aws_ses_tags(&email.tags),
        };

        let body = serde_json::to_string(&payload)?;
        let url = provider_url(&self.endpoint, "/v2/email/outbound-emails");
        execute_provider_request(self.aws_signed_request(
            Method::POST,
            url,
            Some(body),
            Some("application/json"),
        )?)
        .await
    }

    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        let account: AwsSesAccountResponse =
            execute_provider_json_request(self.aws_signed_request(
                Method::GET,
                provider_url(&self.endpoint, "/v2/email/account"),
                None,
                None,
            )?)
            .await?;

        if !account.sending_enabled {
            return Err(provider_client_error(
                "sending_disabled",
                "AWS SES account sending is disabled in this region",
            ));
        }

        if !account.production_access_enabled {
            return Err(provider_client_error(
                "sandbox_mode",
                "AWS SES account is still in sandbox mode in this region",
            ));
        }

        self.ensure_verified_sender(from).await
    }
}

impl AwsSesProvider {
    fn aws_signed_request(
        &self,
        method: Method,
        url: Url,
        body: Option<String>,
        content_type: Option<&str>,
    ) -> Result<RequestBuilder, Error> {
        let host = url
            .host_str()
            .expect("AWS SES endpoint must contain a hostname");
        let body = body.unwrap_or_default();
        let payload_digest = hex_sha256(body.as_bytes());
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let mut canonical_headers = BTreeMap::from([
            ("host".to_owned(), host.to_owned()),
            ("x-amz-content-sha256".to_owned(), payload_digest.clone()),
            ("x-amz-date".to_owned(), amz_date.clone()),
        ]);

        if let Some(content_type) = content_type {
            canonical_headers.insert("content-type".to_owned(), content_type.to_owned());
        }

        if let Some(session_token) = &self.session_token {
            canonical_headers.insert("x-amz-security-token".to_owned(), session_token.clone());
        }

        let canonical_headers_text = canonical_headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", normalize_aws_header_value(value)))
            .collect::<String>();
        let signed_headers = canonical_headers
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{}\n{}\n{}\n{}{signed_headers}\n{payload_digest}",
            method.as_str(),
            canonical_uri(url.path()),
            canonical_query(url.query()),
            canonical_headers_text,
        );
        let credential_scope = format!("{date_stamp}/{}/ses/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes()),
        );
        let signing_key =
            aws_signing_key(&self.secret_access_key, &date_stamp, &self.region, "ses");
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id,
        );

        let mut request = self
            .client
            .request(method, url)
            .header("Authorization", authorization)
            .header("x-amz-content-sha256", payload_digest)
            .header("x-amz-date", amz_date);

        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }

        if let Some(session_token) = &self.session_token {
            request = request.header("x-amz-security-token", session_token);
        }

        if !body.is_empty() {
            request = request.body(body);
        }

        Ok(request)
    }

    async fn ensure_verified_sender(&self, from: &Mailbox) -> Result<(), Error> {
        let sender_email = from.email.to_string();

        if let Some(identity) = self
            .get_email_identity(&sender_email)
            .await?
            .filter(|identity| identity.verified_for_sending_status)
            && identity
                .verification_status
                .as_deref()
                .unwrap_or("SUCCESS")
                .eq_ignore_ascii_case("SUCCESS")
        {
            return Ok(());
        }

        let sender_domain = sender_domain(from).ok_or_else(|| {
            provider_client_error(
                "invalid_sender",
                format!("sender address {from} does not contain a domain"),
            )
        })?;

        if let Some(identity) = self
            .get_email_identity(&sender_domain)
            .await?
            .filter(|identity| identity.verified_for_sending_status)
            && identity
                .verification_status
                .as_deref()
                .unwrap_or("SUCCESS")
                .eq_ignore_ascii_case("SUCCESS")
        {
            return Ok(());
        }

        Err(provider_client_error(
            "sender_identity_unverified",
            format!(
                "AWS SES sender {sender_email} or domain {sender_domain} is not verified for sending"
            ),
        ))
    }

    async fn get_email_identity(
        &self,
        identity: &str,
    ) -> Result<Option<AwsSesIdentityResponse>, Error> {
        let mut url = self.endpoint.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                provider_client_error("invalid_endpoint", "AWS SES endpoint path is invalid")
            })?;
            segments.clear();
            segments.extend(["v2", "email", "identities", identity]);
        }
        url.set_query(None);
        url.set_fragment(None);

        execute_optional_provider_json_request(
            self.aws_signed_request(Method::GET, url, None, None)?,
            &[StatusCode::NOT_FOUND],
        )
        .await
    }
}

fn build_lettre_message(email: &OutboundEmail) -> Result<Message, Error> {
    let mut builder = Message::builder()
        .from(email.from.clone())
        .subject(email.subject.trim());

    if let Some(reply_to) = &email.reply_to {
        builder = builder.reply_to(reply_to.clone());
    }

    for mailbox in &email.to {
        builder = builder.to(mailbox.clone());
    }

    for (name, value) in &email.headers {
        if reserved_message_header(name) {
            return Err(provider_client_error(
                "reserved_header",
                format!("header {name} cannot be set explicitly"),
            ));
        }

        let header_name = HeaderName::new_from_ascii(name.clone()).map_err(|_| {
            provider_client_error(
                "invalid_header_name",
                format!("header {name} is not a valid RFC 5322 header name"),
            )
        })?;

        builder = builder.raw_header(HeaderValue::new(header_name, value.clone()));
    }

    match &email.html_body {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(
            email.text_body.clone(),
            html.clone(),
        )),
        None => builder.singlepart(SinglePart::plain(email.text_body.clone())),
    }
    .map_err(Error::from)
}

async fn execute_provider_request(request: RequestBuilder) -> Result<SendResult, Error> {
    let response = request.send().await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(provider_error(status.as_u16(), body));
    }

    Ok(SendResult {
        provider_message_id: extract_provider_message_id(&headers, &body),
    })
}

async fn execute_provider_json_request<T: DeserializeOwned>(
    request: RequestBuilder,
) -> Result<T, Error> {
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(provider_error(status.as_u16(), body));
    }

    Ok(serde_json::from_str(&body)?)
}

async fn execute_optional_provider_json_request<T: DeserializeOwned>(
    request: RequestBuilder,
    ignored_statuses: &[StatusCode],
) -> Result<Option<T>, Error> {
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if ignored_statuses.contains(&status) {
        return Ok(None);
    }

    if !status.is_success() {
        return Err(provider_error(status.as_u16(), body));
    }

    Ok(Some(serde_json::from_str(&body)?))
}

fn provider_error(status: u16, body: String) -> Error {
    Error::ProviderError {
        status,
        code: extract_provider_error_code(&body),
        retryable: status == 429 || status >= 500,
        body,
    }
}

fn provider_client_error(code: impl Into<String>, body: impl Into<String>) -> Error {
    Error::ProviderError {
        status: 400,
        code: Some(code.into()),
        retryable: false,
        body: body.into(),
    }
}

fn provider_url(base_url: &Url, path: &str) -> Url {
    let mut url = base_url.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn provider_mailbox(mailbox: &Mailbox) -> ProviderMailbox<'_> {
    ProviderMailbox {
        email: mailbox.email.as_ref(),
        name: mailbox_name(mailbox),
    }
}

fn mailbox_name(mailbox: &Mailbox) -> Option<&str> {
    mailbox
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn map_ref(map: &BTreeMap<String, String>) -> Option<&BTreeMap<String, String>> {
    (!map.is_empty()).then_some(map)
}

fn provider_tags(tags: &BTreeMap<String, String>) -> Vec<ProviderTag<'_>> {
    tags.iter()
        .map(|(name, value)| ProviderTag {
            name: name.as_str(),
            value: value.as_str(),
        })
        .collect()
}

fn brevo_tags(tags: &BTreeMap<String, String>) -> Vec<String> {
    tags.iter()
        .map(|(name, value)| {
            if value.trim().is_empty() {
                name.clone()
            } else {
                format!("{name}={value}")
            }
        })
        .collect()
}

fn aws_ses_tags(tags: &BTreeMap<String, String>) -> Vec<AwsSesTag<'_>> {
    tags.iter()
        .map(|(name, value)| AwsSesTag {
            name: name.as_str(),
            value: value.as_str(),
        })
        .collect()
}

async fn validate_sendgrid_sender(
    provider: &SendgridLikeProvider,
    from: &Mailbox,
) -> Result<(), Error> {
    let sender_email = from.email.to_string();
    let sender_domain = sender_domain(from).ok_or_else(|| {
        provider_client_error(
            "invalid_sender",
            format!("sender address {from} does not contain a domain"),
        )
    })?;

    let mut authenticated_domains_url = provider_url(&provider.base_url, "/v3/whitelabel/domains");
    authenticated_domains_url
        .query_pairs_mut()
        .append_pair("domain", &sender_domain)
        .append_pair("limit", "200");
    let authenticated_domains =
        execute_optional_provider_json_request::<Vec<SendgridAuthenticatedDomain>>(
            provider
                .client
                .get(authenticated_domains_url)
                .bearer_auth(&provider.api_key),
            &[StatusCode::FORBIDDEN, StatusCode::NOT_FOUND],
        )
        .await?;

    if authenticated_domains.as_ref().is_some_and(|domains| {
        domains.iter().any(|domain| {
            domain.domain.eq_ignore_ascii_case(&sender_domain) && domain.valid != Some(false)
        })
    }) {
        return Ok(());
    }

    let mut verified_senders_url = provider_url(&provider.base_url, "/v3/verified_senders");
    verified_senders_url
        .query_pairs_mut()
        .append_pair("limit", "200");
    let verified_senders =
        execute_optional_provider_json_request::<SendgridVerifiedSendersResponse>(
            provider
                .client
                .get(verified_senders_url)
                .bearer_auth(&provider.api_key),
            &[StatusCode::FORBIDDEN, StatusCode::NOT_FOUND],
        )
        .await?;

    if verified_senders.as_ref().is_some_and(|response| {
        response
            .results
            .iter()
            .any(|sender| sender.from_email.eq_ignore_ascii_case(&sender_email) && sender.verified)
    }) {
        return Ok(());
    }

    if authenticated_domains.is_none() && verified_senders.is_none() {
        return Ok(());
    }

    Err(provider_client_error(
        "sender_identity_unverified",
        format!(
            "Twilio SendGrid sender {sender_email} is not verified and domain {sender_domain} is not authenticated"
        ),
    ))
}

fn reserved_message_header(name: &str) -> bool {
    [
        "bcc",
        "cc",
        "content-disposition",
        "content-transfer-encoding",
        "content-type",
        "date",
        "from",
        "in-reply-to",
        "message-id",
        "mime-version",
        "references",
        "reply-to",
        "sender",
        "subject",
        "to",
    ]
    .iter()
    .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

fn sender_domain(mailbox: &Mailbox) -> Option<String> {
    mailbox
        .email
        .to_string()
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        aws_percent_encode(path, true)
    }
}

fn canonical_query(query: Option<&str>) -> String {
    let Some(query) = query else {
        return String::new();
    };

    let mut pairs = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (
                aws_percent_encode(name, false),
                aws_percent_encode(value, false),
            ),
            None => (aws_percent_encode(pair, false), String::new()),
        })
        .collect::<Vec<_>>();
    pairs.sort();

    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_percent_encode(value: &str, keep_slash: bool) -> String {
    let mut encoded = String::with_capacity(value.len());

    for byte in value.as_bytes() {
        let is_unreserved =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if is_unreserved || (keep_slash && *byte == b'/') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }

    encoded
}

fn normalize_aws_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn aws_signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let date_key = hmac_sha256(
        format!("AWS4{secret_access_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    hmac_sha256(&service_key, b"aws4_request")
}

#[derive(Debug, Default, Deserialize)]
struct ProviderResponse {
    id: Option<String>,
    message_id: Option<String>,
    #[serde(rename = "messageId")]
    message_id_camel: Option<String>,
    #[serde(rename = "MessageId")]
    message_id_pascal: Option<String>,
    provider_message_id: Option<String>,
    code: Option<String>,
    error: Option<String>,
    #[serde(default)]
    errors: Vec<ProviderResponseError>,
}

#[derive(Debug, Default, Deserialize)]
struct ProviderResponseError {
    code: Option<String>,
    field: Option<String>,
    id: Option<String>,
    message: Option<String>,
}

fn extract_provider_message_id(headers: &reqwest::header::HeaderMap, body: &str) -> Option<String> {
    for header_name in ["x-provider-message-id", "x-message-id", "x-request-id"] {
        if let Some(value) = headers.get(header_name)
            && let Ok(value) = value.to_str()
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }

    serde_json::from_str::<ProviderResponse>(body)
        .ok()
        .and_then(|payload| {
            payload
                .provider_message_id
                .or(payload.message_id)
                .or(payload.message_id_camel)
                .or(payload.message_id_pascal)
                .or(payload.id)
        })
        .filter(|value| !value.trim().is_empty())
}

fn extract_provider_error_code(body: &str) -> Option<String> {
    serde_json::from_str::<ProviderResponse>(body)
        .ok()
        .and_then(|payload| {
            payload.code.or(payload.error).or_else(|| {
                payload
                    .errors
                    .into_iter()
                    .find_map(|error| error.code.or(error.id).or(error.field).or(error.message))
            })
        })
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use reqwest::{
        Client,
        header::{HeaderMap, HeaderValue},
    };
    use rustls_platform_verifier::ConfigVerifierExt as _;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{body_partial_json, header, header_exists, method, path, query_param},
    };

    use super::*;

    fn sample_email() -> OutboundEmail {
        OutboundEmail {
            from: "coauth <noreply@example.com>".parse().unwrap(),
            reply_to: Some("Support <support@example.com>".parse().unwrap()),
            to: vec!["Alice <alice@example.com>".parse().unwrap()],
            subject: "Production check".to_owned(),
            text_body: "Plain body".to_owned(),
            html_body: Some("<p>HTML body</p>".to_owned()),
            headers: BTreeMap::from([(String::from("X-Test"), String::from("1"))]),
            tags: BTreeMap::from([(String::from("tenant"), String::from("auth"))]),
        }
    }

    fn install_default_crypto_provider_once() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // When this crate's tests are linked into a workspace test
            // binary that doesn't pre-install a rustls CryptoProvider,
            // `ClientConfig::with_platform_verifier()` panics. Installing
            // the aws-lc-rs default once per process is idempotent and safe
            // to share with any other test that already installed one — the
            // call returns Err in that case, which we ignore.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn test_client() -> Client {
        install_default_crypto_provider_once();
        let tls_config: rustls::ClientConfig =
            rustls::ClientConfig::with_platform_verifier().unwrap();

        Client::builder()
            .use_preconfigured_tls(tls_config)
            .build()
            .unwrap()
    }

    #[test]
    fn extracts_message_id_from_headers_first() {
        let mut headers = HeaderMap::new();
        headers.insert("x-provider-message-id", HeaderValue::from_static("msg-123"));

        let id = extract_provider_message_id(&headers, r#"{"message_id":"msg-456"}"#);

        assert_eq!(id.as_deref(), Some("msg-123"));
    }

    #[test]
    fn extracts_message_id_from_json_body() {
        let headers = HeaderMap::new();

        let id = extract_provider_message_id(&headers, r#"{"provider_message_id":"msg-456"}"#);

        assert_eq!(id.as_deref(), Some("msg-456"));
    }

    #[test]
    fn extracts_message_id_from_pascal_case_json_body() {
        let headers = HeaderMap::new();

        let id = extract_provider_message_id(&headers, r#"{"MessageId":"msg-789"}"#);

        assert_eq!(id.as_deref(), Some("msg-789"));
    }

    #[test]
    fn extracts_nested_provider_error_code() {
        let code = extract_provider_error_code(
            r#"{"errors":[{"field":"personalizations.0.to.0.email","message":"invalid email"}]}"#,
        );

        assert_eq!(code.as_deref(), Some("personalizations.0.to.0.email"));
    }

    #[test]
    fn provider_error_display_redacts_body() {
        let error = provider_error(
            400,
            "recovery link: https://example.com/reset?t=secret".into(),
        );

        assert_eq!(
            error.to_string(),
            "email provider returned non-success status 400"
        );
        assert!(!error.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn paloud_internal_transport_signs_request() {
        let mock_server = MockServer::start().await;
        let email = OutboundEmail {
            from: "coauth <noreply@example.com>".parse().unwrap(),
            reply_to: None,
            to: vec!["alice@example.com".parse().unwrap()],
            subject: "Verify your email".to_owned(),
            text_body: "Plain body".to_owned(),
            html_body: Some("<p>HTML body</p>".to_owned()),
            headers: BTreeMap::new(),
            tags: BTreeMap::from([(
                "coauth_notification_request_id".to_owned(),
                "req-123".to_owned(),
            )]),
        };

        Mock::given(method("POST"))
            .and(path("/api/v1/internal/notifications/email/send"))
            .and(header("x-paloud-key-id", "coauth-control-dev"))
            .and(header_exists("x-paloud-timestamp"))
            .and(header_exists("x-paloud-nonce"))
            .and(header_exists("x-paloud-signature"))
            .and(body_partial_json(json!({
                "workspace": "demo",
                "recipient": "alice@example.com",
                "subject": "Verify your email",
                "body": "<p>HTML body</p>",
                "idempotency_key": "req-123"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "accepted",
                "delivery": {
                    "provider_message_id": "provider-123"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = PaloudInternalProvider {
            client: test_client(),
            url: Url::parse(&mock_server.uri())
                .unwrap()
                .join("/api/v1/internal/notifications/email/send")
                .unwrap(),
            key_id: "coauth-control-dev".to_owned(),
            secret: "super-secret".to_owned(),
            workspace: Some("demo".to_owned()),
        };

        let result = provider.send(&email).await.unwrap();

        assert_eq!(result.provider_message_id, None);
    }

    #[tokio::test]
    async fn resend_send_posts_expected_payload() {
        let mock_server = MockServer::start().await;
        let email = sample_email();

        Mock::given(method("POST"))
            .and(path("/emails"))
            .and(header("authorization", "Bearer resend-key"))
            .and(body_partial_json(json!({
                "from": "coauth <noreply@example.com>",
                "reply_to": "Support <support@example.com>",
                "to": ["Alice <alice@example.com>"],
                "subject": "Production check",
                "text": "Plain body",
                "html": "<p>HTML body</p>",
                "headers": {
                    "X-Test": "1"
                },
                "tags": [{
                    "name": "tenant",
                    "value": "auth"
                }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "re_123" })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = ResendProvider {
            client: test_client(),
            base_url: Url::parse(&mock_server.uri()).unwrap(),
            api_key: "resend-key".to_owned(),
        };

        let result = provider.send(&email).await.unwrap();

        assert_eq!(result.provider_message_id.as_deref(), Some("re_123"));
    }

    #[tokio::test]
    async fn resend_test_connection_requires_enabled_sender_domain() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/domains"))
            .and(header("authorization", "Bearer resend-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "name": "example.com",
                    "capabilities": {
                        "sending": "enabled"
                    }
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = ResendProvider {
            client: test_client(),
            base_url: Url::parse(&mock_server.uri()).unwrap(),
            api_key: "resend-key".to_owned(),
        };

        provider
            .test_connection(&"coauth <noreply@example.com>".parse().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sendgrid_test_connection_requires_mail_send_scope() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v3/scopes"))
            .and(header("authorization", "Bearer sg-key"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "scopes": ["stats.read"] })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = SendgridLikeProvider {
            client: test_client(),
            base_url: Url::parse(&mock_server.uri()).unwrap(),
            api_key: "sg-key".to_owned(),
            binding_key: "email.sendgrid",
        };

        let error = provider
            .test_connection(&"coauth <noreply@example.com>".parse().unwrap())
            .await
            .unwrap_err();

        match error {
            Error::ProviderError {
                status,
                code,
                retryable,
                ..
            } => {
                assert_eq!(status, 400);
                assert_eq!(code.as_deref(), Some("missing_scope"));
                assert!(!retryable);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn sendgrid_test_connection_accepts_verified_sender() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v3/scopes"))
            .and(header("authorization", "Bearer sg-key"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "scopes": ["mail.send"] })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v3/whitelabel/domains"))
            .and(header("authorization", "Bearer sg-key"))
            .and(query_param("domain", "example.com"))
            .and(query_param("limit", "200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v3/verified_senders"))
            .and(header("authorization", "Bearer sg-key"))
            .and(query_param("limit", "200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "from_email": "noreply@example.com",
                    "verified": true
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = SendgridLikeProvider {
            client: test_client(),
            base_url: Url::parse(&mock_server.uri()).unwrap(),
            api_key: "sg-key".to_owned(),
            binding_key: "email.sendgrid",
        };

        provider
            .test_connection(&"coauth <noreply@example.com>".parse().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn aws_ses_send_signs_and_embeds_raw_mime_message() {
        let mock_server = MockServer::start().await;
        let email = sample_email();

        Mock::given(method("POST"))
            .and(path("/v2/email/outbound-emails"))
            .and(header_exists("authorization"))
            .and(header_exists("x-amz-date"))
            .and(header_exists("x-amz-content-sha256"))
            .and(|request: &Request| {
                let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let raw = payload["Content"]["Raw"]["Data"].as_str().unwrap();
                let decoded = BASE64_STANDARD.decode(raw).unwrap();
                let message = String::from_utf8_lossy(&decoded);

                payload["FromEmailAddress"] == "noreply@example.com"
                    && payload["Destination"]["ToAddresses"] == json!(["alice@example.com"])
                    && payload["EmailTags"]
                        == json!([{
                            "Name": "tenant",
                            "Value": "auth"
                        }])
                    && message.contains("Subject: Production check")
                    && message.contains("Reply-To: Support <support@example.com>")
                    && message.contains("X-Test: 1")
                    && message.contains("Plain body")
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "MessageId": "aws-123"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = AwsSesProvider {
            client: test_client(),
            endpoint: Url::parse(&mock_server.uri()).unwrap(),
            region: "us-east-1".to_owned(),
            access_key_id: "access-key".to_owned(),
            secret_access_key: "secret-key".to_owned(),
            session_token: None,
            configuration_set_name: None,
        };

        let result = provider.send(&email).await.unwrap();

        assert_eq!(result.provider_message_id.as_deref(), Some("aws-123"));
    }
}
