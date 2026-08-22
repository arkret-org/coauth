//! HTTP API email providers (webhook, Paloud internal, Resend, SendGrid-like,
//! Brevo).

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::Utc;
use coauth_email_types::Mailbox;
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

use super::common::{
    ProviderMailbox, ProviderTag, brevo_tags, execute_optional_provider_json_request,
    execute_provider_json_request, execute_provider_request, map_ref, provider_client_error,
    provider_mailbox, provider_tags, provider_url, sender_domain,
};
use super::{EmailProvider, EmailTransportError, OutboundEmail, SendResult};
use crate::crypto::{paloud_internal_nonce, sign_paloud_internal_request};

pub(crate) struct HttpWebhookProvider {
    pub(crate) client: Client,
    pub(crate) url: Url,
    pub(crate) api_key: Option<String>,
    pub(crate) headers: BTreeMap<String, String>,
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

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
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

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), EmailTransportError> {
        Ok(())
    }
}

pub(crate) struct PaloudInternalProvider {
    pub(crate) client: Client,
    pub(crate) url: Url,
    pub(crate) key_id: String,
    pub(crate) secret: String,
    pub(crate) workspace: Option<String>,
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

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
        let recipient = match email.to.as_slice() {
            [recipient] => recipient.to_string(),
            _ => {
                return Err(EmailTransportError::ProviderError {
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

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), EmailTransportError> {
        Ok(())
    }
}

pub(crate) struct ResendProvider {
    pub(crate) client: Client,
    pub(crate) base_url: Url,
    pub(crate) api_key: String,
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

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
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

    async fn test_connection(&self, from: &Mailbox) -> Result<(), EmailTransportError> {
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

pub(crate) struct SendgridLikeProvider {
    pub(crate) client: Client,
    pub(crate) base_url: Url,
    pub(crate) api_key: String,
    pub(crate) binding_key: &'static str,
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

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
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

    async fn test_connection(&self, from: &Mailbox) -> Result<(), EmailTransportError> {
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

pub(crate) struct BrevoProvider {
    pub(crate) client: Client,
    pub(crate) base_url: Url,
    pub(crate) api_key: String,
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

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, EmailTransportError> {
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

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), EmailTransportError> {
        let _: serde_json::Value = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/v3/account"))
                .header("api-key", &self.api_key),
        )
        .await?;
        Ok(())
    }
}

async fn validate_sendgrid_sender(
    provider: &SendgridLikeProvider,
    from: &Mailbox,
) -> Result<(), EmailTransportError> {
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
