//! Tencent Cloud SMS transport
// Production server callers inject the backend guarded client through
// `SmsTransport::tencent_cloud_with_client`; this crate stays backend-agnostic.
#![allow(clippy::disallowed_methods)]

use reqwest::Client;

use super::transport::SmsTransportError;
use crate::crypto::{hex_sha256, hmac_sha256};

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
    /// SMS sign name
    pub sign_name: String,
    /// SMS template id
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

        // Step 3: Calculate signature via the TC3 HMAC-SHA256 key-derivation
        // chain. Extracted into a pure helper so the brittle chain has
        // offline contract coverage (see tests) without live credentials.
        let signature = tc3_signature(&self.secret_key, &date, service, &string_to_sign);

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

/// Compute a Tencent Cloud TC3-HMAC-SHA256 signature.
///
/// Runs the documented key-derivation chain
/// `HMAC(HMAC(HMAC(HMAC("TC3"+secret_key, date), service), "tc3_request"),
/// string_to_sign)` and returns the lowercase hex signature.
fn tc3_signature(secret_key: &str, date: &str, service: &str, string_to_sign: &str) -> String {
    let secret_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let secret_service = hmac_sha256(&secret_date, service.as_bytes());
    let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
    let signature_bytes = hmac_sha256(&secret_signing, string_to_sign.as_bytes());
    hex::encode(signature_bytes)
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

#[cfg(test)]
mod tests {
    use super::tc3_signature;

    #[test]
    fn tc3_signature_matches_offline_vector() {
        // Offline contract vector for the TC3-HMAC-SHA256 key-derivation
        // chain. The expected hex was computed independently with OpenSSL
        // (HMAC-SHA256 applied stepwise: TC3<key> -> date -> service ->
        // tc3_request -> string_to_sign), guarding against drift in the
        // chain ordering / hex encoding without live Tencent credentials.
        let signature = tc3_signature(
            "Gu5t9xGARNpq86cd98joQYCN3EXAMPLE",
            "2019-02-25",
            "cvm",
            "TC3-HMAC-SHA256\n1551113065\n2019-02-25/cvm/tc3_request\n\
5ffe6a04c0664d6b969fab9a13bdab201d63ee709638e2749d62a09ca18d7031",
        );
        assert_eq!(
            signature,
            "72e494ea809ad7a8c8f7a4507b9bddcbaa8e581f516e8da2f66e2c5a96525168"
        );
    }
}
