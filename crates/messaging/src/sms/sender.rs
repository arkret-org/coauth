//! Send SMS messages to users

use super::transport::{SmsTransport, SmsTransportError};

/// Helps sending SMS messages to users
#[derive(Clone)]
pub struct SmsSender {
    transport: SmsTransport,
}

impl SmsSender {
    /// Constructs a new [`SmsSender`]
    #[must_use]
    pub fn new(transport: SmsTransport) -> Self {
        Self { transport }
    }

    /// Send a verification code via SMS
    ///
    /// The `language` parameter controls the message language. For Chinese SMS
    /// providers (Aliyun / Tencent Cloud) the code is passed as a template
    /// parameter; for text-based transports the message is formatted based
    /// on `language`.
    ///
    /// # Errors
    ///
    /// Returns an error if the SMS failed to send
    pub async fn send_verification_code(
        &self,
        to: &str,
        code: &str,
        language: &str,
    ) -> Result<(), SmsTransportError> {
        println!("[SMS] send_verification_code to={to}, code={code}, language={language}");

        if self.transport.is_aliyun() {
            // Aliyun: pass code as JSON template params
            let params = serde_json::json!({"code": code});
            let body = serde_json::to_string(&params).unwrap_or_default();
            return self.transport.send(to, &body).await;
        }

        if self.transport.is_tencent_cloud() {
            // Tencent Cloud: pass code as JSON array of template params
            let params = serde_json::json!([code]);
            let body = serde_json::to_string(&params).unwrap_or_default();
            return self.transport.send(to, &body).await;
        }

        // Text-based transports (Twilio, HttpWebhook, Blackhole)
        let body = match language {
            "zh" | "zh-Hans" | "zh-CN" => {
                format!("\u{60A8}\u{7684}\u{9A8C}\u{8BC1}\u{7801}\u{662F}\u{FF1A}{code}")
            }
            _ => format!("Your verification code is: {code}"),
        };

        self.transport.send(to, &body).await
    }

    /// Return the stable provider binding key for the configured transport.
    #[must_use]
    pub fn provider_binding_key(&self) -> &'static str {
        self.transport.binding_key()
    }
}
