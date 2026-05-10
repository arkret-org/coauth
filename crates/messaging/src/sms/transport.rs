//! SMS transport backends

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use reqwest::Method;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use super::{aliyun::AliyunSmsTransport, tencent::TencentSmsTransport};

type HmacSha256 = Hmac<Sha256>;

/// Errors that can occur when sending an SMS
#[derive(Debug, Error)]
pub enum SmsTransportError {
    /// An error occurred in the HTTP client
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The SMS provider returned a non-success status
    #[error("SMS provider returned non-success status {status}")]
    ProviderError {
        /// HTTP status code
        status: u16,
        /// Response body
        body: String,
    },
}

/// A wrapper around multiple SMS transport backends
#[derive(Clone)]
pub struct SmsTransport {
    inner: Arc<SmsTransportInner>,
}

enum SmsTransportInner {
    Blackhole,
    Twilio {
        client: Client,
        account_sid: String,
        auth_token: String,
        from_number: String,
    },
    HttpWebhook {
        client: Client,
        url: Url,
        api_key: Option<String>,
        from_number: String,
    },
    PaloudInternal {
        client: Client,
        url: Url,
        key_id: String,
        secret: String,
        workspace: Option<String>,
    },
    AliyunSms(AliyunSmsTransport),
    TencentCloudSms(TencentSmsTransport),
}

impl Default for SmsTransport {
    fn default() -> Self {
        Self::blackhole()
    }
}

impl SmsTransport {
    fn new(inner: SmsTransportInner) -> Self {
        let inner = Arc::new(inner);
        Self { inner }
    }

    /// Construct a blackhole transport that discards all messages
    #[must_use]
    pub fn blackhole() -> Self {
        Self::new(SmsTransportInner::Blackhole)
    }

    /// Construct a Twilio transport
    #[must_use]
    pub fn twilio(account_sid: String, auth_token: String, from_number: String) -> Self {
        Self::new(SmsTransportInner::Twilio {
            client: Client::new(),
            account_sid,
            auth_token,
            from_number,
        })
    }

    /// Construct an HTTP webhook transport
    #[must_use]
    pub fn http_webhook(url: Url, api_key: Option<String>, from_number: String) -> Self {
        Self::new(SmsTransportInner::HttpWebhook {
            client: Client::new(),
            url,
            api_key,
            from_number,
        })
    }

    /// Construct a Paloud internal notification API transport
    #[must_use]
    pub fn paloud_internal(
        url: Url,
        key_id: String,
        secret: String,
        workspace: Option<String>,
    ) -> Self {
        Self::new(SmsTransportInner::PaloudInternal {
            client: Client::new(),
            url,
            key_id,
            secret,
            workspace,
        })
    }

    /// Construct an Aliyun SMS transport
    #[must_use]
    pub fn aliyun(
        access_key_id: String,
        access_key_secret: String,
        sign_name: String,
        template_code: String,
    ) -> Self {
        Self::new(SmsTransportInner::AliyunSms(AliyunSmsTransport {
            client: Client::new(),
            access_key_id,
            access_key_secret,
            sign_name,
            template_code,
        }))
    }

    /// Construct a Tencent Cloud SMS transport
    #[must_use]
    pub fn tencent_cloud(
        secret_id: String,
        secret_key: String,
        sdk_app_id: String,
        sign_name: String,
        template_id: String,
    ) -> Self {
        Self::new(SmsTransportInner::TencentCloudSms(TencentSmsTransport {
            client: Client::new(),
            secret_id,
            secret_key,
            sdk_app_id,
            sign_name,
            template_id,
        }))
    }

    /// Returns `true` if this transport is the Aliyun SMS backend
    #[must_use]
    pub fn is_aliyun(&self) -> bool {
        matches!(self.inner.as_ref(), SmsTransportInner::AliyunSms(_))
    }

    /// Returns `true` if this transport is the Tencent Cloud SMS backend
    #[must_use]
    pub fn is_tencent_cloud(&self) -> bool {
        matches!(self.inner.as_ref(), SmsTransportInner::TencentCloudSms(_))
    }

    /// Return the stable provider binding key for this transport.
    #[must_use]
    pub fn binding_key(&self) -> &'static str {
        match self.inner.as_ref() {
            SmsTransportInner::Blackhole => "sms.blackhole",
            SmsTransportInner::Twilio { .. } => "sms.twilio",
            SmsTransportInner::HttpWebhook { .. } => "sms.http_webhook",
            SmsTransportInner::PaloudInternal { .. } => "sms.paloud_internal",
            SmsTransportInner::AliyunSms(_) => "sms.aliyun",
            SmsTransportInner::TencentCloudSms(_) => "sms.tencent_cloud",
        }
    }

    /// Send an SMS message
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport fails to send the message
    pub async fn send(&self, to: &str, body: &str) -> Result<(), SmsTransportError> {
        tracing::debug!(
            sms.to = %to,
            sms.transport = self.binding_key(),
            "Sending SMS"
        );

        match self.inner.as_ref() {
            SmsTransportInner::Blackhole => {
                tracing::warn!("An SMS was supposed to be sent but no SMS backend is configured");
            }

            SmsTransportInner::Twilio {
                client,
                account_sid,
                auth_token,
                from_number,
            } => {
                tracing::debug!(sms.transport = "sms.twilio", "Sending SMS through provider");
                let url = format!(
                    "https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
                );
                let credentials = BASE64.encode(format!("{account_sid}:{auth_token}"));

                let response = client
                    .post(&url)
                    .header("Authorization", format!("Basic {credentials}"))
                    .form(&[("To", to), ("From", from_number.as_str()), ("Body", body)])
                    .send()
                    .await?;

                let status = response.status();
                if !status.is_success() {
                    let provider_body = response.text().await.unwrap_or_default();
                    tracing::warn!(
                        sms.transport = "sms.twilio",
                        http.status = status.as_u16(),
                        "SMS provider rejected message"
                    );
                    return Err(SmsTransportError::ProviderError {
                        status: status.as_u16(),
                        body: provider_body,
                    });
                }
                tracing::debug!(sms.transport = "sms.twilio", "SMS accepted by provider");
            }

            SmsTransportInner::HttpWebhook {
                client,
                url,
                api_key,
                from_number,
            } => {
                tracing::debug!(
                    sms.transport = "sms.http_webhook",
                    "Sending SMS through provider"
                );
                let payload = serde_json::json!({
                    "to": to,
                    "from": from_number,
                    "body": body,
                });

                let mut request = client.post(url.as_str()).json(&payload);

                if let Some(api_key) = api_key {
                    request = request.header("Authorization", format!("Bearer {api_key}"));
                }

                let response = request.send().await?;

                let status = response.status();
                if !status.is_success() {
                    let provider_body = response.text().await.unwrap_or_default();
                    tracing::warn!(
                        sms.transport = "sms.http_webhook",
                        http.status = status.as_u16(),
                        "SMS provider rejected message"
                    );
                    return Err(SmsTransportError::ProviderError {
                        status: status.as_u16(),
                        body: provider_body,
                    });
                }
                tracing::debug!(
                    sms.transport = "sms.http_webhook",
                    "SMS accepted by provider"
                );
            }

            SmsTransportInner::PaloudInternal {
                client,
                url,
                key_id,
                secret,
                workspace,
            } => {
                tracing::debug!(
                    sms.transport = "sms.paloud_internal",
                    "Sending SMS through provider"
                );
                let payload = serde_json::json!({
                    "workspace": workspace.as_deref().filter(|value| !value.trim().is_empty()),
                    "recipient": to,
                    "body": body,
                });
                let body = serde_json::to_vec(&payload)
                    .expect("paloud internal sms payload should serialize");
                let timestamp = Utc::now().timestamp();
                let nonce = paloud_internal_nonce(timestamp);
                let signature = sign_paloud_internal_request(
                    secret,
                    Method::POST.as_str(),
                    url.path(),
                    timestamp,
                    &nonce,
                    &body,
                );

                let response = client
                    .post(url.clone())
                    .header("X-Paloud-Key-Id", key_id)
                    .header("X-Paloud-Timestamp", timestamp.to_string())
                    .header("X-Paloud-Nonce", nonce)
                    .header("X-Paloud-Signature", signature)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await?;

                let status = response.status();
                if !status.is_success() {
                    let provider_body = response.text().await.unwrap_or_default();
                    tracing::warn!(
                        sms.transport = "sms.paloud_internal",
                        http.status = status.as_u16(),
                        "SMS provider rejected message"
                    );
                    return Err(SmsTransportError::ProviderError {
                        status: status.as_u16(),
                        body: provider_body,
                    });
                }
                tracing::debug!(
                    sms.transport = "sms.paloud_internal",
                    "SMS accepted by provider"
                );
            }

            SmsTransportInner::AliyunSms(transport) => {
                tracing::debug!(sms.transport = "sms.aliyun", "Sending SMS through provider");
                // Parse body as template params: try JSON first, fall back to
                // {"code": body}
                let params: std::collections::HashMap<String, String> = serde_json::from_str(body)
                    .unwrap_or_else(|_| {
                        let mut m = std::collections::HashMap::new();
                        m.insert("code".to_owned(), body.to_owned());
                        m
                    });
                transport.send(to, &params).await?;
                tracing::debug!(sms.transport = "sms.aliyun", "SMS accepted by provider");
            }

            SmsTransportInner::TencentCloudSms(transport) => {
                tracing::debug!(
                    sms.transport = "sms.tencent_cloud",
                    "Sending SMS through provider"
                );
                // Parse body as template params: try JSON array first, fall
                // back to [body]
                let params: Vec<String> =
                    serde_json::from_str(body).unwrap_or_else(|_| vec![body.to_owned()]);
                transport.send(to, &params).await?;
                tracing::debug!(
                    sms.transport = "sms.tencent_cloud",
                    "SMS accepted by provider"
                );
            }
        }

        Ok(())
    }
}

fn hex_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn paloud_internal_nonce(timestamp: i64) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!(
        "{timestamp:x}-{:x}-{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn sign_paloud_internal_request(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let payload = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.trim().to_ascii_uppercase(),
        path.trim(),
        timestamp,
        nonce.trim(),
        hex_sha256(body)
    );
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts arbitrary key lengths");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, header_exists, method, path},
    };

    fn install_default_crypto_provider_once() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // reqwest pulls in rustls; under workspace test runs no other
            // binary has installed a `CryptoProvider` so the default lookup
            // panics. Install aws-lc-rs once per process. Idempotent.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[tokio::test]
    async fn paloud_internal_transport_signs_request() {
        install_default_crypto_provider_once();
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/internal/notifications/sms/send"))
            .and(header("x-paloud-key-id", "coauth-control-dev"))
            .and(header_exists("x-paloud-timestamp"))
            .and(header_exists("x-paloud-nonce"))
            .and(header_exists("x-paloud-signature"))
            .and(body_partial_json(json!({
                "workspace": "demo",
                "recipient": "+8613711112222",
                "body": "123456"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "accepted",
                "channel": "sms"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let transport = SmsTransport::paloud_internal(
            Url::parse(&mock_server.uri())
                .unwrap()
                .join("/api/v1/internal/notifications/sms/send")
                .unwrap(),
            "coauth-control-dev".to_owned(),
            "super-secret".to_owned(),
            Some("demo".to_owned()),
        );

        transport.send("+8613711112222", "123456").await.unwrap();
    }

    #[test]
    fn provider_error_display_redacts_body() {
        let error = SmsTransportError::ProviderError {
            status: 400,
            body: "Your verification code is 123456".to_owned(),
        };

        assert_eq!(
            error.to_string(),
            "SMS provider returned non-success status 400"
        );
        assert!(!error.to_string().contains("123456"));
    }
}
