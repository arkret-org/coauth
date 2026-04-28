//! Verified client metadata and validation error types.

use std::{fmt, ops::Deref};

use serde::Serialize;
use thiserror::Error;
use url::Url;

use super::{client_metadata_serde::ClientMetadataSerdeHelper, metadata::ClientMetadata};
use crate::response_type::ResponseType;

/// The verified client metadata.
///
/// All the fields required by the [OpenID Connect Dynamic Client Registration
/// Spec 1.0] or with a default value are accessible via methods.
///
/// To access other fields, use this type's `Deref` implementation.
///
/// [OpenID Connect Dynamic Client Registration Spec 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(into = "ClientMetadataSerdeHelper")]
pub struct VerifiedClientMetadata {
    pub(super) inner: ClientMetadata,
}

impl VerifiedClientMetadata {
    /// Construct a new `VerifiedClientMetadata` from validated inner metadata.
    pub(super) fn new(inner: ClientMetadata) -> Self {
        Self { inner }
    }

    /// Array of redirection URIs for use in redirect-based flows such as the
    /// [authorization code flow].
    ///
    /// All the URIs used by the client in an authorization request's
    /// `redirect_uri` field must appear in this list.
    ///
    /// [authorization code flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
    #[must_use]
    pub fn redirect_uris(&self) -> &[Url] {
        self.redirect_uris.as_deref().unwrap_or(&[])
    }
}

impl Deref for VerifiedClientMetadata {
    type Target = ClientMetadata;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// All errors that can happen when verifying [`ClientMetadata`].
#[derive(Debug, Error)]
pub enum ClientMetadataVerificationError {
    /// The redirect URIs are missing.
    #[error("redirect URIs are missing")]
    MissingRedirectUris,

    /// The redirect URI has a fragment, which is not allowed.
    #[error("redirect URI with fragment: {0}")]
    RedirectUriWithFragment(Url),

    /// The given response type is not compatible with the grant types.
    #[error("'{0}' response type not compatible with grant types")]
    IncoherentResponseType(ResponseType),

    /// Both the `jwks_uri` and `jwks` fields are present but only one is
    /// allowed.
    #[error("jwks_uri and jwks are mutually exclusive")]
    JwksUriAndJwksMutuallyExclusive,

    /// The URL of the given field doesn't use a `https` scheme.
    #[error("{0}'s URL doesn't use a https scheme: {1}")]
    UrlNonHttpsScheme(&'static str, Url),

    /// No JWK Set was provided but one is required for the token auth method.
    #[error("missing JWK Set for token auth method")]
    MissingJwksForTokenMethod,

    /// The given endpoint doesn't allow `none` as a signing algorithm.
    #[error("none signing alg unauthorized for {0}")]
    UnauthorizedSigningAlgNone(&'static str),

    /// The given endpoint is missing an auth signing algorithm, but it is
    /// required because it uses one of the `client_secret_jwt` or
    /// `private_key_jwt` authentication methods.
    #[error("{0} missing auth signing algorithm")]
    MissingAuthSigningAlg(&'static str),

    /// `none` is used as the signing algorithm for ID Tokens, but is not
    /// allowed.
    #[error("ID Token signing alg is none")]
    IdTokenSigningAlgNone,

    /// The given encryption field has an `enc` value but not `alg` value.
    #[error("{0} missing encryption alg value")]
    MissingEncryptionAlg(&'static str),

    /// Multiple validation errors were found.
    #[error("multiple validation errors: {}", MultipleErrorsDisplay(.0))]
    Multiple(Vec<ClientMetadataVerificationError>),
}

/// Helper for displaying a list of errors.
struct MultipleErrorsDisplay<'a>(&'a [ClientMetadataVerificationError]);

impl fmt::Display for MultipleErrorsDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, err) in self.0.iter().enumerate() {
            if idx > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{err}")?;
        }
        Ok(())
    }
}
