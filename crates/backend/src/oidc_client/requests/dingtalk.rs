//! DingTalk (钉钉) OAuth2 specific request implementations.
//!
//! DingTalk uses a mostly standard OAuth2 flow with JSON request/response
//! bodies and a custom header for the access token in userinfo requests.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::super::error::{TokenRequestError, UserInfoError};
use crate::outbound_http::RequestBuilderExt;

/// DingTalk token exchange request body.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DingTalkTokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    grant_type: &'a str,
}

/// DingTalk token endpoint response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DingTalkTokenResponse {
    /// The user access token.
    pub access_token: String,
    /// Token expiry in seconds.
    #[serde(default)]
    pub expires_in: u64,
    /// The refresh token, if provided.
    pub refresh_token: Option<String>,
    /// The OpenID of the user.
    pub open_id: Option<String>,
    /// The UnionID of the user.
    pub union_id: Option<String>,
}

impl DingTalkTokenResponse {
    /// Convert token data into a claims map for attribute mapping.
    #[must_use]
    pub fn to_claims_map(&self) -> HashMap<String, Value> {
        let mut map = HashMap::new();
        if let Some(ref v) = self.open_id {
            map.insert("open_id".to_owned(), Value::String(v.clone()));
            map.insert("sub".to_owned(), Value::String(v.clone()));
        }
        if let Some(ref v) = self.union_id {
            map.insert("union_id".to_owned(), Value::String(v.clone()));
        }
        map
    }
}

/// Exchange an authorization code for an access token with DingTalk.
///
/// `POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken`
#[tracing::instrument(skip_all, fields(%token_endpoint))]
pub async fn request_access_token(
    http_client: &reqwest::Client,
    token_endpoint: &Url,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> Result<DingTalkTokenResponse, TokenRequestError> {
    tracing::debug!("Requesting DingTalk access token...");

    let body = DingTalkTokenRequest {
        client_id,
        client_secret,
        code,
        grant_type: "authorization_code",
    };

    let response: DingTalkTokenResponse = http_client
        .post(token_endpoint.as_str())
        .json(&body)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    Ok(response)
}

/// Fetch user info from DingTalk's contact API.
///
/// `GET https://api.dingtalk.com/v1.0/contact/users/me`
///
/// DingTalk uses the `x-acs-dingtalk-access-token` header instead of
/// standard Bearer auth.
#[tracing::instrument(skip_all, fields(%userinfo_endpoint))]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    userinfo_endpoint: &Url,
    access_token: &str,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Fetching DingTalk user info...");

    let response: HashMap<String, Value> = http_client
        .get(userinfo_endpoint.as_str())
        .header("x-acs-dingtalk-access-token", access_token)
        .send_traced()
        .await?
        .error_for_status()
        .map_err(reqwest::Error::from)?
        .json()
        .await?;

    Ok(response)
}
