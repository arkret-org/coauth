//! WeCom (企业微信) OAuth2 specific request implementations.
//!
//! WeCom uses a non-standard OAuth2 flow:
//! - First obtain a corp access_token using corpid + corpsecret
//! - Then use the authorization code to get user identity (userid)
//! - Optionally fetch full user profile
//! - Error responses use `errcode` and `errmsg` fields

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::super::error::{TokenRequestError, UserInfoError};
use crate::outbound_http::RequestBuilderExt;

const WECOM_TOKEN_ENDPOINT: &str = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";
const WECOM_USERINFO_ENDPOINT: &str = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo";
const WECOM_USER_GET_ENDPOINT: &str = "https://qyapi.weixin.qq.com/cgi-bin/user/get";

/// WeCom corp access_token response.
#[derive(Debug, Deserialize)]
pub struct WeComTokenResponse {
    /// Error code (0 means success).
    pub errcode: i32,
    /// Error message.
    #[serde(default)]
    pub errmsg: String,
    /// The corp access token.
    #[serde(default)]
    pub access_token: String,
    /// Token expiry in seconds.
    #[serde(default)]
    pub expires_in: u64,
}

/// WeCom user identity response from the getuserinfo endpoint.
#[derive(Debug, Deserialize)]
pub struct WeComUserIdentity {
    /// Error code (0 means success).
    pub errcode: i32,
    /// Error message.
    #[serde(default)]
    pub errmsg: String,
    /// The user's ID within the enterprise (present for enterprise members).
    #[serde(rename = "UserId")]
    pub user_id: Option<String>,
    /// The user's OpenID (present for non-enterprise members).
    #[serde(rename = "OpenId")]
    pub open_id: Option<String>,
    /// The user's external userid, if applicable.
    pub external_userid: Option<String>,
}

/// Obtain a WeCom corp access_token.
///
/// `GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=CORPID&corpsecret=SECRET`
#[tracing::instrument(skip_all)]
pub async fn get_corp_access_token(
    http_client: &reqwest::Client,
    corpid: &str,
    corpsecret: &str,
) -> Result<String, TokenRequestError> {
    tracing::debug!("Requesting WeCom corp access_token...");

    let mut url = Url::parse(WECOM_TOKEN_ENDPOINT).expect("valid URL");
    url.query_pairs_mut()
        .append_pair("corpid", corpid)
        .append_pair("corpsecret", corpsecret);

    let response: WeComTokenResponse = http_client
        .get(url)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    if response.errcode != 0 {
        return Err(TokenRequestError::ProviderError {
            code: response.errcode,
            msg: response.errmsg,
        });
    }

    Ok(response.access_token)
}

/// Get the user's identity from an authorization code.
///
/// `GET https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=TOKEN&code=CODE`
///
/// Returns the user's `UserId` (enterprise member) or `OpenId` (external user).
#[tracing::instrument(skip_all)]
pub async fn get_user_identity(
    http_client: &reqwest::Client,
    access_token: &str,
    code: &str,
) -> Result<WeComUserIdentity, TokenRequestError> {
    tracing::debug!("Fetching WeCom user identity...");

    let mut url = Url::parse(WECOM_USERINFO_ENDPOINT).expect("valid URL");
    url.query_pairs_mut()
        .append_pair("access_token", access_token)
        .append_pair("code", code);

    let response: WeComUserIdentity = http_client
        .get(url)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    if response.errcode != 0 {
        return Err(TokenRequestError::ProviderError {
            code: response.errcode,
            msg: response.errmsg.clone(),
        });
    }

    Ok(response)
}

/// Fetch full user profile from WeCom.
///
/// `GET https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=TOKEN&userid=USERID`
///
/// Returns claims including `name`, `email`, `mobile`, `avatar`, `position`,
/// etc.
#[tracing::instrument(skip_all)]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    access_token: &str,
    userid: &str,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Fetching WeCom user info...");

    let mut url = Url::parse(WECOM_USER_GET_ENDPOINT).expect("valid URL");
    url.query_pairs_mut()
        .append_pair("access_token", access_token)
        .append_pair("userid", userid);

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
