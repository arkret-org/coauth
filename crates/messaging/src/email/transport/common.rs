//! Shared helpers for HTTP-based email providers.

use std::collections::BTreeMap;

use lettre::Message;
use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use reqwest::{RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{Error, OutboundEmail, SendResult};

#[derive(Serialize)]
pub(crate) struct ProviderMailbox<'a> {
    pub(crate) email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<&'a str>,
}

#[derive(Serialize)]
pub(crate) struct ProviderTag<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
}

pub(crate) fn build_lettre_message(email: &OutboundEmail) -> Result<Message, Error> {
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

pub(crate) async fn execute_provider_request(request: RequestBuilder) -> Result<SendResult, Error> {
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

pub(crate) async fn execute_provider_json_request<T: DeserializeOwned>(
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

pub(crate) async fn execute_optional_provider_json_request<T: DeserializeOwned>(
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

pub(crate) fn provider_error(status: u16, body: String) -> Error {
    Error::ProviderError {
        status,
        code: extract_provider_error_code(&body),
        retryable: status == 429 || status >= 500,
        body,
    }
}

pub(crate) fn provider_client_error(code: impl Into<String>, body: impl Into<String>) -> Error {
    Error::ProviderError {
        status: 400,
        code: Some(code.into()),
        retryable: false,
        body: body.into(),
    }
}

pub(crate) fn provider_url(base_url: &url::Url, path: &str) -> url::Url {
    let mut url = base_url.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

pub(crate) fn provider_mailbox(mailbox: &Mailbox) -> ProviderMailbox<'_> {
    ProviderMailbox {
        email: mailbox.email.as_ref(),
        name: mailbox_name(mailbox),
    }
}

pub(crate) fn mailbox_name(mailbox: &Mailbox) -> Option<&str> {
    mailbox
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

pub(crate) fn map_ref(map: &BTreeMap<String, String>) -> Option<&BTreeMap<String, String>> {
    (!map.is_empty()).then_some(map)
}

pub(crate) fn provider_tags(tags: &BTreeMap<String, String>) -> Vec<ProviderTag<'_>> {
    tags.iter()
        .map(|(name, value)| ProviderTag {
            name: name.as_str(),
            value: value.as_str(),
        })
        .collect()
}

pub(crate) fn brevo_tags(tags: &BTreeMap<String, String>) -> Vec<String> {
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

pub(crate) fn sender_domain(mailbox: &Mailbox) -> Option<String> {
    mailbox
        .email
        .to_string()
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
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

pub(crate) fn extract_provider_message_id(
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Option<String> {
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

pub(crate) fn extract_provider_error_code(body: &str) -> Option<String> {
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
