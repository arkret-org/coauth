//! Aliyun SMS transport
// Production server callers inject the backend guarded client through
// `SmsTransport::aliyun_with_client`; this crate stays backend-agnostic.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
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
    /// SMS sign name
    pub sign_name: String,
    /// SMS template code
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
        let nonce = random_nonce();
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

        // Construct StringToSign + sign. Extracted into pure helpers so the
        // brittle canonicalization + HMAC-SHA1 chain has offline contract
        // coverage (see tests) without needing live Aliyun credentials.
        let string_to_sign = aliyun_string_to_sign("POST", &params);
        let signature = aliyun_signature(&self.access_key_secret, &string_to_sign);

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

/// Build the Aliyun RPC `StringToSign` for the given HTTP verb and the
/// already key-sorted parameter list.
///
/// `StringToSign = HTTPMethod + "&" + pe("/") + "&" + pe(canonical_query)`
/// where `pe` is RFC-3986 percent-encoding and `canonical_query` joins the
/// sorted `pe(key)=pe(value)` pairs with `&`.
fn aliyun_string_to_sign(http_method: &str, sorted_params: &[(&str, String)]) -> String {
    let canonical_query: String = sorted_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!(
        "{}&{}&{}",
        http_method,
        percent_encode("/"),
        percent_encode(&canonical_query)
    )
}

/// Sign an Aliyun `StringToSign` with HMAC-SHA1 keyed by
/// `access_key_secret + "&"`, returning the base64 signature.
fn aliyun_signature(access_key_secret: &str, string_to_sign: &str) -> String {
    let signing_key = format!("{access_key_secret}&");
    let mut mac =
        HmacSha1::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(string_to_sign.as_bytes());
    BASE64.encode(mac.finalize().into_bytes())
}

/// Generate a cryptographically random UUID v4 string for use as the Aliyun
/// `SignatureNonce`.
fn random_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::{aliyun_signature, aliyun_string_to_sign, percent_encode};

    #[test]
    fn percent_encode_matches_aliyun_rules() {
        // Unreserved characters pass through; everything else is %XX
        // upper-hex. Notably space -> %20 and `:` -> %3A.
        assert_eq!(percent_encode("aZ09-_.~"), "aZ09-_.~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("12:46:24"), "12%3A46%3A24");
        assert_eq!(percent_encode("a+b/c="), "a%2Bb%2Fc%3D");
    }

    #[test]
    fn string_to_sign_canonicalises_sorted_params() {
        let params = vec![
            ("Action", "SendSms".to_owned()),
            ("Format", "JSON".to_owned()),
        ];
        // POST & pe("/") & pe("Action=SendSms&Format=JSON")
        assert_eq!(
            aliyun_string_to_sign("POST", &params),
            "POST&%2F&Action%3DSendSms%26Format%3DJSON"
        );
    }

    #[test]
    fn signature_matches_offline_hmac_sha1_vector() {
        // Offline contract vector for the HMAC-SHA1 chain, anchored to
        // Aliyun's documented DescribeRegions `StringToSign` and signing key
        // (`AccessKeySecret + "&"`). The expected base64 was computed
        // independently with OpenSSL:
        //   printf '%s' "<string_to_sign>" \
        //     | openssl dgst -sha1 -hmac 'testsecret&' -binary \
        //     | openssl base64
        // so this guards against drift in the HMAC keying / base64 encoding
        // without needing live Aliyun credentials.
        let string_to_sign = "GET&%2F&AccessKeyId%3Dtestid&Action%3DDescribeRegions\
&Format%3DXML&SignatureMethod%3DHMAC-SHA1\
&SignatureNonce%3D3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf\
&SignatureVersion%3D1.0&Timestamp%3D2016-02-23T12%253A46%253A24Z\
&Version%3D2014-05-26";
        assert_eq!(
            aliyun_signature("testsecret", string_to_sign),
            "VyBL52idtt+oImX0NZC+2ngk15Q="
        );
    }
}
