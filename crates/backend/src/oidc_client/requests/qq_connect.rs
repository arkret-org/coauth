//! QQ Connect OAuth2 specific request implementations.
//!
//! QQ Connect uses a non-standard OAuth2 flow:
//! - Token endpoint returns URL-encoded by default (use `fmt=json` for JSON)
//! - A separate `/me` endpoint is needed to get the user's OpenID
//! - UserInfo endpoint requires `openid` and `oauth_consumer_key` as query
//!   params

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::super::error::{TokenRequestError, UserInfoError};
use crate::outbound_http::RequestBuilderExt;

const QQ_ME_ENDPOINT: &str = "https://graph.qq.com/oauth2.0/me";
const QQ_USERINFO_ENDPOINT: &str = "https://graph.qq.com/user/get_user_info";

/// QQ token endpoint response.
#[derive(Debug, Deserialize)]
pub struct QQTokenResponse {
    /// The access token.
    pub access_token: String,

    /// Token expiry in seconds.
    #[serde(default)]
    pub expires_in: u64,

    /// The refresh token, if provided.
    pub refresh_token: Option<String>,
}

/// QQ `/me` endpoint response, containing the user's OpenID.
#[derive(Debug, Deserialize)]
pub struct QQOpenIdResponse {
    /// The QQ App ID.
    pub client_id: Option<String>,

    /// The user's unique OpenID for this app.
    pub openid: String,
}

/// QQ token exchange request body.
#[derive(Serialize)]
struct QQTokenRequest<'a> {
    grant_type: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    fmt: &'a str,
}

/// Exchange an authorization code for an access token with QQ Connect.
///
/// Posts to the QQ token endpoint with `fmt=json` to get a JSON response.
#[tracing::instrument(skip_all, fields(%token_endpoint))]
pub async fn request_access_token(
    http_client: &reqwest::Client,
    token_endpoint: &Url,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &Url,
) -> Result<QQTokenResponse, TokenRequestError> {
    tracing::debug!("Requesting QQ access token...");

    let body = QQTokenRequest {
        grant_type: "authorization_code",
        client_id,
        client_secret,
        code,
        redirect_uri: redirect_uri.as_str(),
        fmt: "json",
    };

    let response: QQTokenResponse = http_client
        .post(token_endpoint.as_str())
        .form(&body)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    Ok(response)
}

/// Strip JSONP `callback(...)` wrapper if present, returning the inner JSON
/// string.
fn strip_jsonp(text: &str) -> &str {
    let trimmed = text.trim();
    if trimmed.starts_with("callback") {
        trimmed
            .trim_start_matches("callback")
            .trim_start()
            .trim_start_matches('(')
            .trim_end_matches(");")
            .trim_end_matches(')')
            .trim()
    } else {
        trimmed
    }
}

/// Fetch the user's OpenID from QQ's `/me` endpoint.
///
/// `GET https://graph.qq.com/oauth2.0/me?access_token=xxx&fmt=json`
#[tracing::instrument(skip_all)]
pub async fn fetch_openid(
    http_client: &reqwest::Client,
    access_token: &str,
) -> Result<QQOpenIdResponse, UserInfoError> {
    tracing::debug!("Fetching QQ OpenID...");

    let mut url = Url::parse(QQ_ME_ENDPOINT).expect("QQ_ME_ENDPOINT is a valid URL");
    url.query_pairs_mut()
        .append_pair("access_token", access_token)
        .append_pair("fmt", "json");

    let response_text = http_client
        .get(url)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .text()
        .await?;

    // QQ may return JSONP format even with fmt=json; handle both.
    let json_str = strip_jsonp(&response_text);

    // Check for error response first (QQ uses "error" + "error_description" fields)
    let raw: Value = serde_json::from_str(json_str).map_err(|e| UserInfoError::ProviderError {
        code: -1,
        msg: format!("Failed to parse QQ /me response: {e}"),
    })?;
    if let Some(code) = raw.get("error").and_then(|v| v.as_i64()) {
        let msg = raw
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error")
            .to_owned();
        return Err(UserInfoError::ProviderError {
            code: code as i32,
            msg,
        });
    }

    let response: QQOpenIdResponse =
        serde_json::from_value(raw).map_err(|e| UserInfoError::ProviderError {
            code: -1,
            msg: format!("Failed to parse QQ OpenID response: {e}"),
        })?;

    Ok(response)
}

/// Fetch user info from QQ's user info endpoint.
///
/// `GET https://graph.qq.com/user/get_user_info?access_token=xxx&oauth_consumer_key=appid&openid=xxx`
///
/// Returns a map of user claims (nickname, figureurl_qq_2, gender, etc.).
#[tracing::instrument(skip_all)]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    access_token: &str,
    client_id: &str,
    openid: &str,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Fetching QQ user info...");

    let mut url = Url::parse(QQ_USERINFO_ENDPOINT).expect("QQ_USERINFO_ENDPOINT is a valid URL");
    url.query_pairs_mut()
        .append_pair("access_token", access_token)
        .append_pair("oauth_consumer_key", client_id)
        .append_pair("openid", openid);

    let response: HashMap<String, Value> = http_client
        .get(url)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    // QQ userinfo uses "ret" field for error code (0 = success)
    if let Some(ret) = response.get("ret").and_then(|v| v.as_i64()) {
        if ret != 0 {
            let msg = response
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_owned();
            return Err(UserInfoError::ProviderError {
                code: ret as i32,
                msg,
            });
        }
    }

    Ok(response)
}
