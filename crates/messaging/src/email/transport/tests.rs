use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use rustls_platform_verifier::ConfigVerifierExt as _;
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

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
    let tls_config: rustls::ClientConfig = rustls::ClientConfig::with_platform_verifier().unwrap();

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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "scopes": ["stats.read"] })))
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
        EmailTransportError::ProviderError {
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "scopes": ["mail.send"] })))
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
                && message.contains("Reply-To: \"Support\" <support@example.com>")
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
