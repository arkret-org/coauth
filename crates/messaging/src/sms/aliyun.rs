//! Aliyun SMS (阿里云短信) transport

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha1::Sha1;

use super::transport::SmsTransportError;

type HmacSha1 = Hmac<Sha1>;

/// Aliyun SMS transport backend
pub struct AliyunSmsTransport {
    /// HTTP client
    pub client: Client,
    /// Aliyun access key ID
    pub access_key_id: String,
    /// Aliyun access key secret
    pub access_key_secret: String,
    /// SMS sign name (签名)
    pub sign_name: String,
    /// SMS template code (模板编号)
    pub template_code: String,
}

/// Percent-encode a string according to Aliyun's requirements (RFC 3986).
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{byte:02X}"));
            }
        }
    }
    result
}

impl AliyunSmsTransport {
    /// Send an SMS via Aliyun
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the provider returns an
    /// error
    pub async fn send(
        &self,
        to: &str,
        template_params: &HashMap<String, String>,
    ) -> Result<(), SmsTransportError> {
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = uuid_v4_string();
        let template_param_json =
            serde_json::to_string(template_params).unwrap_or_else(|_| String::from("{}"));

        let mut params: Vec<(&str, String)> = vec![
            ("Action", "SendSms".to_owned()),
            ("Format", "JSON".to_owned()),
            ("Version", "2017-05-25".to_owned()),
            ("AccessKeyId", self.access_key_id.clone()),
            ("SignatureMethod", "HMAC-SHA1".to_owned()),
            ("SignatureVersion", "1.0".to_owned()),
            ("SignatureNonce", nonce),
            ("Timestamp", timestamp),
            ("PhoneNumbers", to.to_owned()),
            ("SignName", self.sign_name.clone()),
            ("TemplateCode", self.template_code.clone()),
            ("TemplateParam", template_param_json),
        ];

        // Sort parameters alphabetically by key
        params.sort_by(|a, b| a.0.cmp(b.0));

        // Build the canonicalized query string
        let canonical_query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Construct StringToSign
        let string_to_sign = format!(
            "POST&{}&{}",
            percent_encode("/"),
            percent_encode(&canonical_query)
        );

        // Sign with HMAC-SHA1 using access_key_secret + "&"
        let signing_key = format!("{}&", self.access_key_secret);
        let mut mac =
            HmacSha1::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key size");
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());

        // Add signature to params
        let mut form_params: Vec<(&str, &str)> =
            params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        // We need to own the signature string for the borrow to work
        form_params.push(("Signature", &signature));

        let response = self
            .client
            .post("https://dysmsapi.aliyuncs.com/")
            .form(&form_params)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Check for success: Aliyun returns {"Code": "OK", ...}
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if json.get("Code").and_then(serde_json::Value::as_str) != Some("OK") {
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

/// Generate a simple UUID v4-like random string for the nonce
fn uuid_v4_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // Use a combination of timestamp and a hash to produce a unique nonce
    format!("{now:032x}")
}
