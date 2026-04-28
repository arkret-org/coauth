//! Tencent Cloud SMS (腾讯云短信) transport

use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};

use super::transport::SmsTransportError;

type HmacSha256 = Hmac<Sha256>;

/// Tencent Cloud SMS transport backend
pub struct TencentSmsTransport {
    /// HTTP client
    pub client: Client,
    /// Tencent Cloud secret ID
    pub secret_id: String,
    /// Tencent Cloud secret key
    pub secret_key: String,
    /// SMS SDK App ID
    pub sdk_app_id: String,
    /// SMS sign name (签名)
    pub sign_name: String,
    /// SMS template ID (模板 ID)
    pub template_id: String,
}

impl TencentSmsTransport {
    /// Send an SMS via Tencent Cloud
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the provider returns an
    /// error
    pub async fn send(
        &self,
        to: &str,
        template_params: &[String],
    ) -> Result<(), SmsTransportError> {
        let host = "sms.tencentcloudapi.com";
        let service = "sms";
        let action = "SendSms";
        let version = "2021-01-11";

        let timestamp = chrono::Utc::now().timestamp();
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Build JSON request body
        let payload = serde_json::json!({
            "SmsSdkAppId": self.sdk_app_id,
            "SignName": self.sign_name,
            "TemplateId": self.template_id,
            "PhoneNumberSet": [to],
            "TemplateParamSet": template_params,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();

        // Step 1: Build canonical request
        let hashed_payload = hex_sha256(payload_str.as_bytes());
        let canonical_request = format!(
            "POST\n/\n\ncontent-type:application/json\nhost:{host}\n\ncontent-type;host\n{hashed_payload}"
        );

        // Step 2: Build string to sign
        let credential_scope = format!("{date}/{service}/tc3_request");
        let hashed_canonical = hex_sha256(canonical_request.as_bytes());
        let string_to_sign =
            format!("TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hashed_canonical}");

        // Step 3: Calculate signature via HMAC chain
        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, service.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature_bytes = hmac_sha256(&secret_signing, string_to_sign.as_bytes());
        let signature = hex::encode(signature_bytes);

        // Step 4: Build authorization header
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host, Signature={}",
            self.secret_id, credential_scope, signature
        );

        let response = self
            .client
            .post(format!("https://{host}"))
            .header("Content-Type", "application/json")
            .header("Host", host)
            .header("X-TC-Action", action)
            .header("X-TC-Version", version)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Region", "")
            .header("Authorization", authorization)
            .body(payload_str)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Check for errors in the response
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if json.get("Response").and_then(|r| r.get("Error")).is_some() {
                return Err(SmsTransportError::ProviderError {
                    status: status.as_u16(),
                    body,
                });
            }
        } else {
            return Err(SmsTransportError::ProviderError {
                status: status.as_u16(),
                body,
            });
        }

        Ok(())
    }
}

/// Compute SHA-256 hash and return as hex string
fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute HMAC-SHA256 and return raw bytes
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Private hex encoding module to avoid adding hex as a dependency
mod hex {
    /// Encode bytes as lowercase hex string
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}
