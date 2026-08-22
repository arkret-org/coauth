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

//! Requests for the [Authorization Code strand].
//!
//! [Authorization Code strand]: https://openid.net/specs/openid-connect-core-1_0.html#CodeStrandAuth

use base64ct::{Base64UrlUnpadded, Encoding};
use coauth_iana::oauth::{OAuthAuthorizationEndpointResponseType, PkceCodeChallengeMethod};
use coauth_oauth_types::pkce;
use coauth_oauth_types::prelude::CodeChallengeMethodExt;
use coauth_oauth_types::requests::{AuthorizationRequest, ResponseMode};
use coauth_oauth_types::scope::{OPENID, Scope};
use rand_core::RngCore as Rng;
use serde::Serialize;
use url::Url;

use super::super::error::AuthorizationError;

/// The data necessary to build an authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizationRequestData {
    /// The ID obtained when registering the client.
    pub client_id: String,

    /// The scope to authorize.
    ///
    /// If the OpenID Connect scope token (`openid`) is not included, it will be
    /// added.
    pub scope: Scope,

    /// The URI to redirect the end-user to after the authorization.
    ///
    /// It must be one of the redirect URIs provided during registration.
    pub redirect_uri: Url,

    /// The PKCE methods supported by the issuer.
    ///
    /// This field should be cloned from the provider metadata. If it is not
    /// set, this security measure will not be used.
    pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in.
    pub login_hint: Option<String>,

    /// Requested response mode.
    ///
    /// coauth addition: allows callers to request a specific response mode
    /// (e.g. `form_post` for certain social providers).
    pub response_mode: Option<ResponseMode>,
}

impl AuthorizationRequestData {
    /// Constructs a new `AuthorizationRequestData` with all the required
    /// fields.
    #[must_use]
    pub fn new(client_id: String, scope: Scope, redirect_uri: Url) -> Self {
        Self {
            client_id,
            scope,
            redirect_uri,
            code_challenge_methods_supported: None,
            login_hint: None,
            response_mode: None,
        }
    }

    /// Set the `code_challenge_methods_supported` field of this
    /// `AuthorizationRequestData`.
    #[must_use]
    pub fn with_code_challenge_methods_supported(
        mut self,
        code_challenge_methods_supported: Vec<PkceCodeChallengeMethod>,
    ) -> Self {
        self.code_challenge_methods_supported = Some(code_challenge_methods_supported);
        self
    }

    /// Set the `login_hint` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_login_hint(mut self, login_hint: String) -> Self {
        self.login_hint = Some(login_hint);
        self
    }

    /// Set the `response_mode` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_response_mode(mut self, response_mode: ResponseMode) -> Self {
        self.response_mode = Some(response_mode);
        self
    }
}

/// The data necessary to validate a response from the Token endpoint in the
/// Authorization Code strand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationValidationData {
    /// A unique identifier for the request.
    pub state: String,

    /// A string to mitigate replay attacks.
    ///
    /// Present when the `openid` scope was requested (i.e. when operating
    /// in OpenID Connect mode). `None` for plain OAuth strands.
    pub nonce: Option<String>,

    /// The URI where the end-user will be redirected after authorization.
    pub redirect_uri: Url,

    /// A string to correlate the authorization request to the token request.
    pub code_challenge_verifier: Option<String>,
}

#[derive(Clone, Serialize)]
struct FullAuthorizationRequest {
    #[serde(flatten)]
    inner: AuthorizationRequest,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pkce: Option<pkce::AuthorizationRequest>,
}

/// Generate a random alphanumeric string of the given length.
///
/// Each character is drawn by unbiased rejection sampling over the 62-char set
/// (COA-COR-02): a plain `byte % 62` over a 256-value byte over-weights the
/// first `256 % 62` characters. `next_u32` rejection sampling makes every
/// character equiprobable.
fn rand_alphanumeric_string(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let bound = CHARSET.len() as u32;
    let zone = u32::MAX - (u32::MAX % bound);
    (0..len)
        .map(|_| {
            let index = loop {
                let value = rng.next_u32();
                if value < zone {
                    break (value % bound) as usize;
                }
            };
            CHARSET[index] as char
        })
        .collect()
}

/// Build the authorization request.
fn build_authorization_request(
    authorization_data: AuthorizationRequestData,
    rng: &mut impl Rng,
) -> Result<(FullAuthorizationRequest, AuthorizationValidationData), AuthorizationError> {
    let AuthorizationRequestData {
        client_id,
        scope,
        redirect_uri,
        code_challenge_methods_supported,
        login_hint,
        response_mode,
    } = authorization_data;

    // Check whether this is an OpenID Connect strand (has the `openid` scope).
    let is_openid = scope.contains(&OPENID);

    // Generate a random CSRF "state" token.
    let state = rand_alphanumeric_string(rng, 16);

    // Only generate a nonce when operating in OpenID Connect mode.
    let nonce = if is_openid {
        Some(rand_alphanumeric_string(rng, 16))
    } else {
        None
    };

    // Use PKCE whenever the provider supports S256.
    let (pkce, code_challenge_verifier) = if code_challenge_methods_supported
        .iter()
        .any(|methods| methods.contains(&PkceCodeChallengeMethod::S256))
    {
        let mut verifier = [0u8; 32];
        rng.fill_bytes(&mut verifier);

        let method = PkceCodeChallengeMethod::S256;
        let verifier = Base64UrlUnpadded::encode_string(&verifier);
        let code_challenge = method.compute_challenge(&verifier)?.into();

        let pkce = pkce::AuthorizationRequest {
            code_challenge_method: method,
            code_challenge,
        };

        (Some(pkce), Some(verifier))
    } else {
        (None, None)
    };

    let auth_request = FullAuthorizationRequest {
        inner: AuthorizationRequest {
            response_type: OAuthAuthorizationEndpointResponseType::Code.into(),
            client_id,
            redirect_uri: Some(redirect_uri.clone()),
            scope,
            state: Some(state.clone()),
            response_mode,
            nonce: nonce.clone(),
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint,
            acr_values: None,
            request: None,
            request_uri: None,
            registration: None,
        },
        pkce,
    };

    let auth_data = AuthorizationValidationData {
        state,
        nonce,
        redirect_uri,
        code_challenge_verifier,
    };

    Ok((auth_request, auth_data))
}

/// Build the URL for authenticating at the Authorization endpoint.
///
/// # Arguments
///
/// * `authorization_endpoint` - The URL of the issuer's authorization endpoint.
///
/// * `authorization_data` - The data necessary to build the authorization request.
///
/// * `rng` - A random number generator.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// authorize the given scope, and the [`AuthorizationValidationData`] to
/// validate this request.
///
/// The redirect URI will receive parameters in its query:
///
/// * A successful response will receive a `code` and a `state`.
///
/// * If the authorization fails, it should receive an `error` parameter with a [`ClientErrorCode`]
///   and optionally an `error_description`.
///
/// # Errors
///
/// Returns an error if preparing the URL fails.
///
/// [`VerifiedClientMetadata`]: coauth_oauth_types::registration::VerifiedClientMetadata
/// [`ClientErrorCode`]: coauth_oauth_types::errors::ClientErrorCode
pub fn build_authorization_url(
    authorization_endpoint: Url,
    authorization_data: AuthorizationRequestData,
    rng: &mut impl Rng,
) -> Result<(Url, AuthorizationValidationData), AuthorizationError> {
    tracing::debug!(
        scope = ?authorization_data.scope,
        "Authorizing..."
    );

    let (authorization_request, validation_data) =
        build_authorization_request(authorization_data, rng)?;

    let authorization_query = serde_urlencoded::to_string(authorization_request)?;

    let mut authorization_url = authorization_endpoint;

    // Add our parameters to the query, because the URL might already have one.
    let mut full_query = authorization_url
        .query()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if !full_query.is_empty() {
        full_query.push('&');
    }
    full_query.push_str(&authorization_query);

    authorization_url.set_query(Some(&full_query));

    Ok((authorization_url, validation_data))
}
