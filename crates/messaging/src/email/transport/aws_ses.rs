//! AWS SES v2 email provider with SigV4 request signing.

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use coauth_email_types::Mailbox;
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

use super::common::{
    build_raw_message, execute_optional_provider_json_request, execute_provider_json_request,
    execute_provider_request, provider_client_error, provider_url, sender_domain,
};
use super::{EmailProvider, Error, OutboundEmail, SendResult};
use crate::crypto::{hex_sha256, hmac_sha256};

pub(crate) struct AwsSesProvider {
    pub(crate) client: Client,
    pub(crate) endpoint: Url,
    pub(crate) region: String,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) session_token: Option<String>,
    pub(crate) configuration_set_name: Option<String>,
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

#[async_trait]
impl EmailProvider for AwsSesProvider {
    fn binding_key(&self) -> &'static str {
        "email.aws_ses"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let raw_message = build_raw_message(email)?;
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

fn aws_ses_tags(tags: &BTreeMap<String, String>) -> Vec<AwsSesTag<'_>> {
    tags.iter()
        .map(|(name, value)| AwsSesTag {
            name: name.as_str(),
            value: value.as_str(),
        })
        .collect()
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
