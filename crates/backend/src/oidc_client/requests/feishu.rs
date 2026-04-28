//! Feishu (Lark) OAuth2 specific request implementations.
//!
//! Feishu uses a non-standard OAuth2 flow:
//! - A separate step is needed to obtain an `app_access_token`
//! - The token exchange uses `app_access_token` as Bearer auth (not
//!   client_secret)
//! - Request bodies are JSON (not form-encoded)
//! - All responses are wrapped in a `{"code": 0, "msg": "...", "data": {...}}`
//!   envelope

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::super::error::{TokenRequestError, UserInfoError};
use crate::outbound_http::RequestBuilderExt;

/// Feishu (China) app_access_token endpoint.
pub const FEISHU_APP_TOKEN_ENDPOINT: &str =
    "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/";

/// Lark (International) app_access_token endpoint.
pub const LARK_APP_TOKEN_ENDPOINT: &str =
    "https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal/";

/// Feishu response envelope.
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    code: i32,
    #[serde(default)]
    msg: String,
    data: Option<T>,
}

/// Feishu app_access_token response (flat, non-envelope format).
#[derive(Debug, Deserialize)]
struct AppAccessTokenResponse {
    code: i32,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    app_access_token: String,
    #[allow(dead_code)]
    expire: Option<u64>,
}

/// Feishu user token response data.
#[derive(Debug, Deserialize)]
pub struct FeishuTokenData {
    /// The user access token.
    pub access_token: String,
    /// The refresh token, if provided.
    pub refresh_token: Option<String>,
    /// The token type (typically "Bearer").
    #[serde(default)]
    pub token_type: String,
    /// Token expiry in seconds.
    #[serde(default)]
    pub expires_in: u64,
    /// The user's Feishu open ID (unique per app).
    pub open_id: Option<String>,
    /// The user's Feishu union ID (unique across apps in the same enterprise).
    pub union_id: Option<String>,
    /// The user's display name.
    pub name: Option<String>,
    /// The user's English name.
    pub en_name: Option<String>,
    /// The user's avatar URL.
    pub avatar_url: Option<String>,
    /// The user's email address.
    pub email: Option<String>,
    /// The user's mobile phone number.
    pub mobile: Option<String>,
    /// The tenant key of the user's organization.
    pub tenant_key: Option<String>,
}

impl FeishuTokenData {
    /// Convert token data fields into a claims map for attribute mapping.
    #[must_use]
    pub fn to_claims_map(&self) -> HashMap<String, Value> {
        let mut map = HashMap::new();
        if let Some(ref v) = self.open_id {
            map.insert("open_id".to_owned(), Value::String(v.clone()));
            // Also set as "sub" for standard subject extraction
            map.insert("sub".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.union_id {
            map.insert("union_id".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.name {
            map.insert("name".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.en_name {
            map.insert("en_name".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.avatar_url {
            map.insert("avatar_url".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.email {
            map.insert("email".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.mobile {
            map.insert("mobile".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.tenant_key {
            map.insert("tenant_key".to_owned(), Value::String(v.clone()));
        }
        map
    }
}

/// Request body for getting app_access_token.
#[derive(Serialize)]
struct AppAccessTokenRequest<'a> {
    app_id: &'a str,
    app_secret: &'a str,
}

/// Request body for exchanging authorization code.
#[derive(Serialize)]
struct CodeExchangeRequest<'a> {
    grant_type: &'a str,
    code: &'a str,
}

/// Obtain a Feishu/Lark app_access_token using app credentials.
///
/// Use [`FEISHU_APP_TOKEN_ENDPOINT`] for Feishu (China)
/// or [`LARK_APP_TOKEN_ENDPOINT`] for Lark (International).
#[tracing::instrument(skip_all, fields(%app_token_endpoint))]
pub async fn get_app_access_token(
    http_client: &reqwest::Client,
    app_token_endpoint: &str,
    app_id: &str,
    app_secret: &str,
) -> Result<String, TokenRequestError> {
    tracing::debug!("Requesting Feishu/Lark app_access_token...");

    let body = AppAccessTokenRequest { app_id, app_secret };

    let response: AppAccessTokenResponse = http_client
        .post(app_token_endpoint)
        .json(&body)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    if response.code != 0 {
        return Err(TokenRequestError::ProviderError {
            code: response.code,
            msg: response.msg,
        });
    }

    Ok(response.app_access_token)
}

/// Exchange an authorization code for a user access token with Feishu.
///
/// Uses `app_access_token` as Bearer auth. The request body is JSON.
/// The response is wrapped in `{"code": 0, "data": {...}}`.
#[tracing::instrument(skip_all, fields(%token_endpoint))]
pub async fn request_access_token(
    http_client: &reqwest::Client,
    token_endpoint: &Url,
    app_access_token: &str,
    code: &str,
) -> Result<FeishuTokenData, TokenRequestError> {
    tracing::debug!("Requesting Feishu user access token...");

    let body = CodeExchangeRequest {
        grant_type: "authorization_code",
        code,
    };

    let response: Envelope<FeishuTokenData> = http_client
        .post(token_endpoint.as_str())
        .bearer_auth(app_access_token)
        .json(&body)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    if response.code != 0 {
        return Err(TokenRequestError::ProviderError {
            code: response.code,
            msg: response.msg,
        });
    }

    response
        .data
        .ok_or_else(|| TokenRequestError::ProviderError {
            code: response.code,
            msg: "missing data in response".to_owned(),
        })
}

/// Fetch user info from Feishu's userinfo endpoint.
///
/// Uses the user's access token as Bearer auth.
/// The response is wrapped in `{"code": 0, "data": {...}}`.
#[tracing::instrument(skip_all, fields(%userinfo_endpoint))]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    userinfo_endpoint: &Url,
    user_access_token: &str,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Fetching Feishu user info...");

    let response: Envelope<HashMap<String, Value>> = http_client
        .get(userinfo_endpoint.as_str())
        .bearer_auth(user_access_token)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    if response.code != 0 {
        return Err(UserInfoError::ProviderError {
            code: response.code,
            msg: response.msg,
        });
    }

    response.data.ok_or_else(|| UserInfoError::ProviderError {
        code: response.code,
        msg: "missing data in response".to_owned(),
    })
}
