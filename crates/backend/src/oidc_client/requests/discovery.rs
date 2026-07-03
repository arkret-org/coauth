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

//! Requests for OpenID Connect Provider [Discovery].
//!
//! [Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html

use coauth_oauth_types::oidc::{ProviderMetadata, VerifiedProviderMetadata};
use url::Url;

use super::super::error::DiscoveryError;
use crate::outbound_http::{oidc_upstream_policy, send_with_policy};

const MAX_PROVIDER_METADATA_BYTES: usize = 1_048_576;

/// Fetch the provider metadata.
async fn discover_inner(
    client: &reqwest::Client,
    issuer: Url,
) -> Result<ProviderMetadata, DiscoveryError> {
    tracing::debug!("Fetching provider metadata...");

    let mut config_url = issuer;

    // If the path doesn't end with a slash, the last segment is removed when
    // using `join`.
    if !config_url.path().ends_with('/') {
        let mut path = config_url.path().to_owned();
        path.push('/');
        config_url.set_path(&path);
    }

    let config_url = config_url.join(".well-known/openid-configuration")?;

    let response = send_with_policy(oidc_upstream_policy("discovery"), || {
        client.get(config_url.as_str())
    })
    .await?
    .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_PROVIDER_METADATA_BYTES as u64)
    {
        return Err(DiscoveryError::ResponseTooLarge {
            limit: MAX_PROVIDER_METADATA_BYTES,
            actual: usize::MAX,
        });
    }
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_PROVIDER_METADATA_BYTES {
        return Err(DiscoveryError::ResponseTooLarge {
            limit: MAX_PROVIDER_METADATA_BYTES,
            actual: bytes.len(),
        });
    }
    let response = serde_json::from_slice(&bytes)?;

    tracing::debug!(?response);

    Ok(response)
}

/// Fetch the provider metadata and validate it.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
#[tracing::instrument(skip_all, fields(issuer))]
pub async fn discover(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<VerifiedProviderMetadata, DiscoveryError> {
    let provider_metadata = discover_inner(client, issuer.parse()?).await?;

    Ok(provider_metadata.validate(issuer)?)
}

/// Fetch the [provider metadata] and make basic checks.
///
/// Contrary to [`discover()`], this uses
/// [`ProviderMetadata::insecure_verify_metadata()`] to check the received
/// metadata instead of validating it according to the specification.
///
/// # Arguments
///
/// * `client` - The reqwest client to use for making HTTP requests.
///
/// * `issuer` - The URL of the OpenID Connect Provider to fetch metadata for.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
///
/// # Warning
///
/// It is not recommended to use this method in production as it doesn't
/// ensure that the issuer implements the proper security practices.
///
/// [provider metadata]: https://openid.net/specs/openid-connect-discovery-1_0.html
#[tracing::instrument(skip_all, fields(issuer))]
pub async fn insecure_discover(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<VerifiedProviderMetadata, DiscoveryError> {
    let provider_metadata = discover_inner(client, issuer.parse()?).await?;

    Ok(provider_metadata.insecure_verify_metadata()?)
}
