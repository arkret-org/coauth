// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! Errors produced while verifying [`ProviderMetadata`].
//!
//! [`ProviderMetadata`]: super::ProviderMetadata

use thiserror::Error;
use url::Url;

/// All errors that can happen when verifying [`ProviderMetadata`]
#[derive(Debug, Error)]
pub enum ProviderMetadataVerificationError {
    /// The issuer is missing.
    #[error("issuer is missing")]
    MissingIssuer,

    /// The issuer is not a valid URL.
    #[error("issuer is not a valid URL")]
    IssuerNotUrl,

    /// The authorization endpoint is missing.
    #[error("authorization endpoint is missing")]
    MissingAuthorizationEndpoint,

    /// The token endpoint is missing.
    #[error("token endpoint is missing")]
    MissingTokenEndpoint,

    /// The JWK Set URI is missing.
    #[error("JWK Set URI is missing")]
    MissingJwksUri,

    /// The supported response types are missing.
    #[error("supported response types are missing")]
    MissingResponseTypesSupported,

    /// The supported subject types are missing.
    #[error("supported subject types are missing")]
    MissingSubjectTypesSupported,

    /// The supported ID token signing algorithm values are missing.
    #[error("supported ID token signing algorithm values are missing")]
    MissingIdTokenSigningAlgValuesSupported,

    /// The URL of the given field doesn't use a `https` scheme.
    #[error("{0}'s URL doesn't use a https scheme: {1}")]
    UrlNonHttpsScheme(&'static str, Url),

    /// The URL of the given field contains a query, but it's not allowed.
    #[error("{0}'s URL contains a query: {1}")]
    UrlWithQuery(&'static str, Url),

    /// The URL of the given field contains a fragment, but it's not allowed.
    #[error("{0}'s URL contains a fragment: {1}")]
    UrlWithFragment(&'static str, Url),

    /// The issuer URL doesn't match the one that was discovered.
    #[error("issuer URLs don't match: expected {expected:?}, got {actual:?}")]
    IssuerUrlsDontMatch {
        /// The expected issuer URL.
        expected: String,
        /// The issuer URL that was discovered.
        actual: String,
    },

    /// `openid` is missing from the supported scopes.
    #[error("missing openid scope")]
    ScopesMissingOpenid,

    /// `code` is missing from the supported response types.
    #[error("missing `code` response type")]
    ResponseTypesMissingCode,

    /// `id_token` is missing from the supported response types.
    #[error("missing `id_token` response type")]
    ResponseTypesMissingIdToken,

    /// `id_token token` is missing from the supported response types.
    #[error("missing `id_token token` response type")]
    ResponseTypesMissingIdTokenToken,

    /// `authorization_code` is missing from the supported grant types.
    #[error("missing `authorization_code` grant type")]
    GrantTypesMissingAuthorizationCode,

    /// `implicit` is missing from the supported grant types.
    #[error("missing `implicit` grant type")]
    GrantTypesMissingImplicit,

    /// `none` is in the given endpoint's signing algorithm values, but is not
    /// allowed.
    #[error("{0} signing algorithm values contain `none`")]
    SigningAlgValuesWithNone(&'static str),
}
