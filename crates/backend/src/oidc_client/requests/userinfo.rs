// Copyright 2022-2024 Kevin Commaille.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Requests for obtaining [Claims] about an end-user.
//!
//! [Claims]: https://openid.net/specs/openid-connect-core-1_0.html#Claims

use std::collections::HashMap;

use headers::{ContentType, HeaderMapExt, HeaderValue};
use http::header::ACCEPT;
use mime::Mime;
use serde_json::Value;
use url::Url;

use super::super::error::{IdTokenError, ResponseExt, UserInfoError};
use super::super::requests::jose::verify_signed_jwt;
use super::jose::JwtVerificationData;
use crate::outbound_http::{oidc_upstream_policy, send_with_policy};

/// Upper bound on the userinfo response body (COA-SEC-02). Discovery / JWKS
/// already cap at 1 MiB; userinfo claim sets are far smaller, but an unbounded
/// read let a hostile/buggy upstream amplify memory use. 1 MiB is generous for
/// any legitimate claim set.
const MAX_USERINFO_BYTES: usize = 1_048_576;

/// Obtain information about an authenticated end-user.
///
/// Returns a map of claims with their value, that should be extracted with
/// one of the [`Claim`] methods.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
///
/// * `userinfo_endpoint` - The URL of the issuer's User Info endpoint.
///
/// * `access_token` - The access token of the end-user.
///
/// * `jwt_verification_data` - The data required to verify the response if a signed response was
///   requested during client registration.
///
///   The signing algorithm corresponds to the `userinfo_signed_response_alg`
///   field in the client metadata.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or the
/// validation of the signed response fails.
///
/// [`Claim`]: coauth_jose::claims::Claim
#[tracing::instrument(skip_all, fields(userinfo_endpoint))]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    userinfo_endpoint: &Url,
    access_token: &str,
    jwt_verification_data: Option<JwtVerificationData<'_>>,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Obtaining user info...");

    let expected_content_type = if jwt_verification_data.is_some() {
        "application/jwt"
    } else {
        mime::APPLICATION_JSON.as_ref()
    };

    let userinfo_response = send_with_policy(oidc_upstream_policy("userinfo"), || {
        http_client
            .get(userinfo_endpoint.as_str())
            .bearer_auth(access_token)
            .header(ACCEPT, HeaderValue::from_static(expected_content_type))
    })
    .await?
    .error_from_oauth_error_response()
    .await?;

    let content_type: Mime = userinfo_response
        .headers()
        .typed_try_get::<ContentType>()
        .map_err(|_| UserInfoError::InvalidResponseContentTypeValue)?
        .ok_or(UserInfoError::MissingResponseContentType)?
        .into();

    if content_type.essence_str() != expected_content_type {
        return Err(UserInfoError::UnexpectedResponseContentType {
            expected: expected_content_type.to_owned(),
            got: content_type.to_string(),
        });
    }

    // Bound the response body before parsing (COA-SEC-02). `Content-Length`, when
    // present, lets us reject early; the post-read length check catches
    // chunked / mislabeled responses.
    if userinfo_response
        .content_length()
        .is_some_and(|len| len > MAX_USERINFO_BYTES as u64)
    {
        return Err(UserInfoError::ResponseTooLarge {
            limit: MAX_USERINFO_BYTES,
            actual: usize::MAX,
        });
    }
    let body_bytes = userinfo_response.bytes().await?;
    if body_bytes.len() > MAX_USERINFO_BYTES {
        return Err(UserInfoError::ResponseTooLarge {
            limit: MAX_USERINFO_BYTES,
            actual: body_bytes.len(),
        });
    }

    let claims = if let Some(verification_data) = jwt_verification_data {
        let response_body = std::str::from_utf8(&body_bytes)
            .map_err(|_| UserInfoError::InvalidResponseContentTypeValue)?;
        verify_signed_jwt(response_body, verification_data)
            .map_err(IdTokenError::from)?
            .into_parts()
            .1
    } else {
        serde_json::from_slice(&body_bytes).map_err(UserInfoError::from)?
    };

    Ok(claims)
}
