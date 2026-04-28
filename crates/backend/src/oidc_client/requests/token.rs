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

//! Requests for the Token endpoint.

use chrono::{DateTime, Utc};
use http::header::ACCEPT;
use mime::APPLICATION_JSON;
use oauth2_types::requests::{AccessTokenRequest, AccessTokenResponse};
use rand_core::RngCore as Rng;
use url::Url;

use super::super::{
    error::{ResponseExt, TokenRequestError},
    types::client_credentials::ClientCredentials,
};
use crate::outbound_http::RequestBuilderExt;

/// Request an access token.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `token_endpoint` - The URL of the issuer's Token endpoint.
///
/// * `request` - The request to make at the Token endpoint.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(token_endpoint, request))]
pub async fn request_access_token(
    http_client: &reqwest::Client,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    request: AccessTokenRequest,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<AccessTokenResponse, TokenRequestError> {
    tracing::debug!(?request, "Requesting access token...");

    let token_request = http_client
        .post(token_endpoint.as_str())
        .header(ACCEPT, APPLICATION_JSON.as_ref());

    let token_response = client_credentials
        .authenticated_form(token_request, &request, now, rng)?
        .send_traced()
        .await?
        .error_from_oauth2_error_response()
        .await?
        .json()
        .await?;

    Ok(token_response)
}
