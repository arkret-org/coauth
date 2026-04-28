//! WeChat Open Platform OAuth2 specific request implementations.
//!
//! WeChat uses a non-standard OAuth2 flow:
//! - Uses `appid` instead of `client_id`, `secret` instead of `client_secret`
//! - Token response includes `openid` and `unionid` directly
//! - UserInfo requires `openid` as a query parameter
//! - Error responses use `errcode` and `errmsg` fields

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::super::error::{TokenRequestError, UserInfoError};
use crate::outbound_http::RequestBuilderExt;

/// WeChat token endpoint response.
#[derive(Debug, Deserialize)]
pub struct WeChatTokenResponse {
    /// The access token.
    pub access_token: String,
    /// Token expiry in seconds.
    #[serde(default)]
    pub expires_in: u64,
    /// The refresh token.
    pub refresh_token: Option<String>,
    /// The user's OpenID (unique per app).
    pub openid: String,
    /// The user's UnionID (unique across apps under the same open platform).
    pub unionid: Option<String>,
    /// Granted scope.
    pub scope: Option<String>,
    /// Error code (0 or absent means success).
    pub errcode: Option<i32>,
    /// Error message.
    pub errmsg: Option<String>,
}

/// Exchange an authorization code for an access token with WeChat.
///
/// `GET https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code`
#[tracing::instrument(skip_all, fields(%token_endpoint))]
pub async fn request_access_token(
    http_client: &reqwest::Client,
    token_endpoint: &Url,
    appid: &str,
    secret: &str,
    code: &str,
) -> Result<WeChatTokenResponse, TokenRequestError> {
    tracing::debug!("Requesting WeChat access token...");

    let mut url = token_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("appid", appid)
        .append_pair("secret", secret)
        .append_pair("code", code)
        .append_pair("grant_type", "authorization_code");

    let response: WeChatTokenResponse = http_client
        .get(url)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    if let Some(errcode) = response.errcode {
        if errcode != 0 {
            return Err(TokenRequestError::ProviderError {
                code: errcode,
                msg: response.errmsg.unwrap_or_default(),
            });
        }
    }

    Ok(response)
}

/// Fetch user info from WeChat's SNS userinfo endpoint.
///
/// `GET https://api.weixin.qq.com/sns/userinfo?access_token=TOKEN&openid=OPENID&lang=zh_CN`
///
/// Returns claims including `nickname`, `headimgurl`, `sex`, `province`,
/// `city`, `country`, etc.
#[tracing::instrument(skip_all)]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    access_token: &str,
    openid: &str,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Fetching WeChat user info...");

    let mut url = Url::parse("https://api.weixin.qq.com/sns/userinfo").expect("valid URL");
    url.query_pairs_mut()
        .append_pair("access_token", access_token)
        .append_pair("openid", openid)
        .append_pair("lang", "zh_CN");

    let response: HashMap<String, Value> = http_client
        .get(url)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    // Check for error
    if let Some(errcode) = response.get("errcode").and_then(|v| v.as_i64()) {
        if errcode != 0 {
            let msg = response
                .get("errmsg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_owned();
            return Err(UserInfoError::ProviderError {
                code: errcode as i32,
                msg,
            });
        }
    }

    Ok(response)
}
