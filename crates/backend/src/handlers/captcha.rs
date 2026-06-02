// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use coauth_data::{CaptchaConfig, CaptchaService};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::outbound_http::RequestBuilderExt as _;

// https://developers.google.com/recaptcha/docs/verify#api_request
const RECAPTCHA_VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

// https://docs.hcaptcha.com/#verify-the-user-response-server-side
const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";

// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
const CF_TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

#[derive(Debug, Error)]
pub enum Error {
    #[error("A CAPTCHA response was expected, but none was provided")]
    MissingCaptchaResponse,

    #[error("A CAPTCHA response was provided, but no CAPTCHA provider is configured")]
    NoCaptchaConfigured,

    #[error("The CAPTCHA response provided is invalid: {0:?}")]
    InvalidCaptcha(Vec<CaptchaProviderErrorCode>),

    #[error("The CAPTCHA provider returned an invalid response")]
    InvalidResponse,

    #[error(
        "The hostname in the CAPTCHA response ({got:?}) does not match the site hostname ({expected:?})"
    )]
    HostnameMismatch { expected: String, got: String },

    #[error("The CAPTCHA provider returned an error")]
    RequestFailed(#[from] reqwest::Error),
}

#[derive(Debug, Serialize)]
struct VerificationRequest<'a> {
    secret: &'a str,
    response: &'a str,
    remoteip: Option<IpAddr>,
}

#[derive(Debug, Deserialize)]
struct VerificationResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<CaptchaProviderErrorCode>>,

    challenge_ts: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum CaptchaProviderErrorCode {
    /// The secret parameter is missing.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    MissingInputSecret,

    /// The secret parameter is invalid or malformed.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    InvalidInputSecret,

    /// The response parameter is missing.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    MissingInputResponse,

    /// The response parameter is invalid or malformed.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    InvalidInputResponse,

    /// The widget ID extracted from the parsed site secret key was invalid or
    /// did not exist.
    ///
    /// Used by Cloudflare Turnstile
    InvalidWidgetId,

    /// The secret extracted from the parsed site secret key was invalid.
    ///
    /// Used by Cloudflare Turnstile
    InvalidParsedSecret,

    /// The request is invalid or malformed.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    BadRequest,

    /// The remoteip parameter is missing.
    ///
    /// Used by hCaptcha
    MissingRemoteip,

    /// The remoteip parameter is not a valid IP address or blinded value.
    ///
    /// Used by hCaptcha
    InvalidRemoteip,

    /// The response parameter has already been checked, or has another issue.
    ///
    /// Used by hCaptcha
    InvalidOrAlreadySeenResponse,

    /// You have used a testing sitekey but have not used its matching secret.
    ///
    /// Used by hCaptcha
    NotUsingDummyPasscode,

    /// The sitekey is not registered with the provided secret.
    ///
    /// Used by hCaptcha
    SitekeySecretMismatch,

    /// The response is no longer valid: either is too old or has been used
    /// previously.
    ///
    /// Used by Cloudflare Turnstile, reCAPTCHA
    TimeoutOrDisplicate,

    /// An internal error happened while validating the response. The request
    /// can be retried.
    ///
    /// Used by Cloudflare Turnstile
    InternalError,
}

/// Verify a single CAPTCHA token, regardless of which provider issued it.
///
/// Use this from REST endpoints (login, registration, recovery,
/// DID-binding admin write paths) where the request body carries one
/// `captcha_token` string instead of a per-provider field. The token is
/// dispatched to the configured provider's `siteverify` endpoint.
///
/// When `config` is `None` and `token` is `None` the call is a no-op and
/// returns `Ok(())`. When `config` is `None` but a token is supplied the
/// call returns [`Error::NoCaptchaConfigured`], so misconfigured
/// deployments can't silently accept attacker-supplied tokens.
#[tracing::instrument(
    skip_all,
    name = "captcha.verify_token",
    fields(captcha.hostname, captcha.challenge_ts, captcha.service),
)]
pub async fn verify_token(
    remote_ip: Option<IpAddr>,
    http_client: &reqwest::Client,
    site_hostname: &str,
    config: Option<&CaptchaConfig>,
    token: Option<&str>,
) -> Result<(), Error> {
    let Some(config) = config else {
        if token.is_some() {
            return Err(Error::NoCaptchaConfigured);
        }
        return Ok(());
    };

    let token = token.ok_or(Error::MissingCaptchaResponse)?;
    if token.is_empty() {
        return Err(Error::MissingCaptchaResponse);
    }

    let remoteip = remote_ip;
    let secret = &config.secret_key;

    let span = tracing::Span::current();
    span.record("captcha.service", tracing::field::debug(config.service));

    let verify_url = match config.service {
        CaptchaService::RecaptchaV2 => RECAPTCHA_VERIFY_URL,
        CaptchaService::HCaptcha => HCAPTCHA_VERIFY_URL,
        CaptchaService::CloudflareTurnstile => CF_TURNSTILE_VERIFY_URL,
    };

    let response: VerificationResponse = http_client
        .post(verify_url)
        .form(&VerificationRequest {
            secret,
            response: token,
            remoteip,
        })
        .send_traced()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if !response.success {
        return Err(Error::InvalidCaptcha(
            response.error_codes.unwrap_or_default(),
        ));
    }

    let Some(hostname) = response.hostname else {
        return Err(Error::InvalidResponse);
    };

    let Some(challenge_ts) = response.challenge_ts else {
        return Err(Error::InvalidResponse);
    };

    span.record("captcha.hostname", &hostname);
    span.record("captcha.challenge_ts", &challenge_ts);

    if hostname != site_hostname {
        return Err(Error::HostnameMismatch {
            expected: site_hostname.to_owned(),
            got: hostname,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_client() -> reqwest::Client {
        crate::handlers::test_utils::setup();
        reqwest::Client::builder()
            .build()
            .expect("reqwest client builds")
    }

    #[tokio::test]
    async fn verify_token_no_config_no_token_is_noop() {
        let client = http_client();

        verify_token(None, &client, "example.com", None, None)
            .await
            .expect("no-config + no-token must succeed without making a network call");
    }

    #[tokio::test]
    async fn verify_token_no_config_with_token_rejects() {
        let client = http_client();

        let err = verify_token(None, &client, "example.com", None, Some("attacker-token"))
            .await
            .expect_err("supplying a token without configured CAPTCHA must error fail-closed");
        assert!(matches!(err, Error::NoCaptchaConfigured));
    }
}
