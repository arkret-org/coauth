// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! OpenID Connect Discovery 1.0 and RFC 8414 types.
//!
//! This module provides Rust types for working with OpenID Connect provider
//! metadata as defined in OpenID Connect Discovery 1.0 Section 3 and
//! OAuth 2.0 Authorization Server Metadata (RFC 8414).

use std::{fmt, ops::Deref};

use language_tags::LanguageTag;
use coauth_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
    oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod, PkceCodeChallengeMethod},
};
use serde::{Deserialize, Serialize};
use serde_with::{
    DeserializeFromStr, SerializeDisplay, StringWithSeparator, formats::SpaceSeparator, serde_as,
    skip_serializing_none,
};
use thiserror::Error;
use url::Url;

use crate::{
    requests::{Display, GrantType, Prompt, ResponseMode},
    response_type::ResponseType,
};

// ---------------------------------------------------------------------------
// Macro: string_enum!
//
// Generates Display, FromStr, Serialize (via SerializeDisplay), and
// Deserialize (via DeserializeFromStr) for simple string-backed enums that
// carry an Unknown(String) catch-all variant.
// ---------------------------------------------------------------------------
macro_rules! string_enum {
    (
        $(#[$outer_meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $wire:literal,
            )*
        }
    ) => {
        $(#[$outer_meta])*
        #[derive(SerializeDisplay, DeserializeFromStr, Clone, PartialEq, Eq, Hash, Debug)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// An unknown value.
            Unknown(String),
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let repr = match self {
                    $( Self::$variant => $wire, )*
                    Self::Unknown(raw) => raw.as_str(),
                };
                f.write_str(repr)
            }
        }

        impl core::str::FromStr for $name {
            type Err = core::convert::Infallible;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let parsed = match input {
                    $( $wire => Self::$variant, )*
                    other => Self::Unknown(other.to_owned()),
                };
                Ok(parsed)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// AuthenticationMethodOrAccessTokenType
// ---------------------------------------------------------------------------

/// An enum for types that accept either an [`OAuthClientAuthenticationMethod`]
/// or an [`OAuthAccessTokenType`].
#[derive(SerializeDisplay, DeserializeFromStr, Clone, PartialEq, Eq, Hash, Debug)]
pub enum AuthenticationMethodOrAccessTokenType {
    /// An authentication method.
    AuthenticationMethod(OAuthClientAuthenticationMethod),

    /// An access token type.
    AccessTokenType(OAuthAccessTokenType),

    /// An unknown value.
    ///
    /// Note that this variant should only be used as the result parsing a
    /// string of unknown type. To build a custom variant, first parse a
    /// string with the wanted type then use `.into()`.
    Unknown(String),
}

impl core::fmt::Display for AuthenticationMethodOrAccessTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationMethod(method) => write!(f, "{method}"),
            Self::AccessTokenType(tok) => write!(f, "{tok}"),
            Self::Unknown(raw) => f.write_str(raw),
        }
    }
}

impl core::str::FromStr for AuthenticationMethodOrAccessTokenType {
    type Err = core::convert::Infallible;

    /// Parse the string, trying access token types first, then authentication
    /// methods, falling back to Unknown.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt access token type resolution first.
        let tok = OAuthAccessTokenType::from_str(s)?;
        if !matches!(tok, OAuthAccessTokenType::Unknown(_)) {
            return Ok(Self::AccessTokenType(tok));
        }

        // Then try authentication method.
        let method = OAuthClientAuthenticationMethod::from_str(s)?;
        if !matches!(method, OAuthClientAuthenticationMethod::Unknown(_)) {
            return Ok(Self::AuthenticationMethod(method));
        }

        Ok(Self::Unknown(s.to_owned()))
    }
}

impl AuthenticationMethodOrAccessTokenType {
    /// Get the authentication method of this
    /// `AuthenticationMethodOrAccessTokenType`.
    #[must_use]
    pub fn authentication_method(&self) -> Option<&OAuthClientAuthenticationMethod> {
        match self {
            Self::AuthenticationMethod(m) => Some(m),
            _ => None,
        }
    }

    /// Get the access token type of this
    /// `AuthenticationMethodOrAccessTokenType`.
    #[must_use]
    pub fn access_token_type(&self) -> Option<&OAuthAccessTokenType> {
        match self {
            Self::AccessTokenType(t) => Some(t),
            _ => None,
        }
    }
}

impl From<OAuthClientAuthenticationMethod> for AuthenticationMethodOrAccessTokenType {
    fn from(method: OAuthClientAuthenticationMethod) -> Self {
        Self::AuthenticationMethod(method)
    }
}

impl From<OAuthAccessTokenType> for AuthenticationMethodOrAccessTokenType {
    fn from(tok: OAuthAccessTokenType) -> Self {
        Self::AccessTokenType(tok)
    }
}

// ---------------------------------------------------------------------------
// Simple string enums generated via the macro
// ---------------------------------------------------------------------------

string_enum! {
    /// The kind of an application.
    pub enum ApplicationType {
        /// A web application.
        Web => "web",
        /// A native application.
        Native => "native",
    }
}

string_enum! {
    /// Subject Identifier types.
    ///
    /// A Subject Identifier is a locally unique and never reassigned identifier
    /// within the Issuer for the End-User, which is intended to be consumed by the
    /// Client.
    pub enum SubjectType {
        /// This provides the same `sub` (subject) value to all Clients.
        Public => "public",
        /// This provides a different `sub` value to each Client, so as not to
        /// enable Clients to correlate the End-User's activities without
        /// permission.
        Pairwise => "pairwise",
    }
}

string_enum! {
    /// Claim types.
    pub enum ClaimType {
        /// Claims that are directly asserted by the OpenID Provider.
        Normal => "normal",
        /// Claims that are asserted by a Claims Provider other than the OpenID
        /// Provider but are returned by OpenID Provider.
        Aggregated => "aggregated",
        /// Claims that are asserted by a Claims Provider other than the OpenID
        /// Provider but are returned as references by the OpenID Provider.
        Distributed => "distributed",
    }
}

// AccountManagementAction has extra derives, so we use the macro but add them
// via the outer_meta.
string_enum! {
    /// An account management action that a user can take.
    ///
    /// Source: <https://github.com/matrix-org/matrix-spec-proposals/pull/2965>
    #[non_exhaustive]
    #[derive(PartialOrd, Ord)]
    pub enum AccountManagementAction {
        /// `org.matrix.profile`
        ///
        /// The user wishes to view their profile (name, avatar, contact details).
        Profile => "org.matrix.profile",

        /// `org.matrix.sessions_list`
        ///
        /// The user wishes to view a list of their sessions.
        SessionsList => "org.matrix.sessions_list",

        /// `org.matrix.session_view`
        ///
        /// The user wishes to view the details of a specific session.
        SessionView => "org.matrix.session_view",

        /// `org.matrix.session_end`
        ///
        /// The user wishes to end/log out of a specific session.
        SessionEnd => "org.matrix.session_end",

        /// `org.matrix.account_deactivate`
        ///
        /// The user wishes to deactivate their account.
        AccountDeactivate => "org.matrix.account_deactivate",

        /// `org.matrix.cross_signing_reset`
        ///
        /// The user wishes to reset their cross-signing keys.
        CrossSigningReset => "org.matrix.cross_signing_reset",
    }
}

// ---------------------------------------------------------------------------
// Default static arrays (per OIDC Discovery 1.0 Section 3)
// ---------------------------------------------------------------------------

/// The default value of `response_modes_supported` if it is not set.
pub static DEFAULT_RESPONSE_MODES_SUPPORTED: &[ResponseMode] =
    &[ResponseMode::Query, ResponseMode::Fragment];

/// The default value of `grant_types_supported` if it is not set.
pub static DEFAULT_GRANT_TYPES_SUPPORTED: &[GrantType] =
    &[GrantType::AuthorizationCode, GrantType::Implicit];

/// The default value of `token_endpoint_auth_methods_supported` if it is not
/// set.
pub static DEFAULT_AUTH_METHODS_SUPPORTED: &[OAuthClientAuthenticationMethod] =
    &[OAuthClientAuthenticationMethod::ClientSecretBasic];

/// The default value of `claim_types_supported` if it is not set.
pub static DEFAULT_CLAIM_TYPES_SUPPORTED: &[ClaimType] = &[ClaimType::Normal];

// ---------------------------------------------------------------------------
// ProviderMetadata
//
// Fields are grouped by specification section:
//   1. Core OAuth 2.0 AS metadata (RFC 8414)
//   2. OpenID Connect Discovery 1.0 extensions
//   3. Additional protocol extensions (PAR, RP-Initiated Logout, etc.)
//   4. Matrix-specific extensions (MSC 2965)
// ---------------------------------------------------------------------------

/// Authorization server metadata, as described by the [IANA registry].
///
/// All the fields with a default value are accessible via methods.
///
/// [IANA registry]: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProviderMetadata {
    // -- Section 1: Core OAuth 2.0 Authorization Server Metadata (RFC 8414) --
    /// Authorization server's issuer identifier URL.
    ///
    /// This field is required. The URL must use a `https` scheme, and must not
    /// contain a query or fragment. It must match the one used to build the
    /// well-known URI to query this metadata.
    pub issuer: Option<String>,

    /// URL of the authorization server's [authorization endpoint].
    ///
    /// This field is required. The URL must use a `https` scheme, and must not
    /// contain a fragment.
    ///
    /// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
    pub authorization_endpoint: Option<Url>,

    /// URL of the authorization server's [token endpoint].
    ///
    /// This field is required. The URL must use a `https` scheme, and must not
    /// contain a fragment.
    ///
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    pub token_endpoint: Option<Url>,

    /// URL of the authorization server's [JWK] Set document.
    ///
    /// This field is required. The URL must use a `https` scheme.
    ///
    /// [JWK]: https://www.rfc-editor.org/rfc/rfc7517.html
    pub jwks_uri: Option<Url>,

    /// URL of the authorization server's [OAuth 2.0 Dynamic Client
    /// Registration] endpoint.
    ///
    /// If this field is present, the URL must use a `https` scheme.
    ///
    /// [OAuth 2.0 Dynamic Client Registration]: https://www.rfc-editor.org/rfc/rfc7591
    pub registration_endpoint: Option<Url>,

    /// JSON array containing a list of the OAuth 2.0 `scope` values that this
    /// authorization server supports.
    ///
    /// If this field is present, it must contain at least the `openid` scope
    /// value.
    pub scopes_supported: Option<Vec<String>>,

    /// JSON array containing a list of the [OAuth 2.0 `response_type` values]
    /// that this authorization server supports.
    ///
    /// This field is required.
    ///
    /// [OAuth 2.0 `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    pub response_types_supported: Option<Vec<ResponseType>>,

    /// JSON array containing a list of the [OAuth 2.0 `response_mode` values]
    /// that this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_MODES_SUPPORTED`].
    ///
    /// [OAuth 2.0 `response_mode` values]: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
    pub response_modes_supported: Option<Vec<ResponseMode>>,

    /// JSON array containing a list of the [OAuth 2.0 `grant_type` values] that
    /// this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES_SUPPORTED`].
    ///
    /// [OAuth 2.0 `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    pub grant_types_supported: Option<Vec<GrantType>>,

    /// JSON array containing a list of client authentication methods supported
    /// by this token endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    pub token_endpoint_auth_methods_supported: Option<Vec<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported
    /// by the token endpoint for the signature on the JWT used to
    /// authenticate the client at the token endpoint.
    ///
    /// If this field is present, it must not contain
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `token_endpoint_auth_methods_supported` contains
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// URL of a page containing human-readable information that developers
    /// might want or need to know when using the authorization server.
    pub service_documentation: Option<Url>,

    /// Languages and scripts supported for the user interface, represented as a
    /// JSON array of language tag values from BCP 47.
    ///
    /// If omitted, the set of supported languages and scripts is unspecified.
    pub ui_locales_supported: Option<Vec<LanguageTag>>,

    /// URL that the authorization server provides to the person registering the
    /// client to read about the authorization server's requirements on how the
    /// client can use the data provided by the authorization server.
    pub op_policy_uri: Option<Url>,

    /// URL that the authorization server provides to the person registering the
    /// client to read about the authorization server's terms of service.
    pub op_tos_uri: Option<Url>,

    /// URL of the authorization server's [OAuth 2.0 revocation endpoint].
    ///
    /// If this field is present, the URL must use a `https` scheme, and must
    /// not contain a fragment.
    ///
    /// [OAuth 2.0 revocation endpoint]: https://www.rfc-editor.org/rfc/rfc7009
    pub revocation_endpoint: Option<Url>,

    /// JSON array containing a list of client authentication methods supported
    /// by this revocation endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    pub revocation_endpoint_auth_methods_supported: Option<Vec<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the revocation endpoint for the signature on the JWT used to
    /// authenticate the client at the revocation endpoint.
    ///
    /// If this field is present, it must not contain
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `revocation_endpoint_auth_methods_supported` contains
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// URL of the authorization server's [OAuth 2.0 introspection endpoint].
    ///
    /// If this field is present, the URL must use a `https` scheme.
    ///
    /// [OAuth 2.0 introspection endpoint]: https://www.rfc-editor.org/rfc/rfc7662
    pub introspection_endpoint: Option<Url>,

    /// JSON array containing a list of client authentication methods or token
    /// types supported by this introspection endpoint.
    pub introspection_endpoint_auth_methods_supported:
        Option<Vec<AuthenticationMethodOrAccessTokenType>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the introspection endpoint for the signature on the JWT used to
    /// authenticate the client at the introspection endpoint.
    ///
    /// If this field is present, it must not contain
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `intospection_endpoint_auth_methods_supported` contains
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// [PKCE code challenge methods] supported by this authorization server.
    /// If omitted, the authorization server does not support PKCE.
    ///
    /// [PKCE code challenge]: https://www.rfc-editor.org/rfc/rfc7636
    pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,

    // -- Section 2: OpenID Connect Discovery 1.0 extensions --
    /// URL of the OP's [UserInfo Endpoint].
    ///
    /// [UserInfo Endpoint]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    pub userinfo_endpoint: Option<Url>,

    /// JSON array containing a list of the Authentication Context Class
    /// References that this OP supports.
    pub acr_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports.
    ///
    /// This field is required.
    pub subject_types_supported: Option<Vec<SubjectType>>,

    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the OP for the ID Token.
    ///
    /// This field is required.
    pub id_token_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`alg`
    /// values) supported by the OP for the ID Token.
    pub id_token_encryption_alg_values_supported: Option<Vec<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`enc`
    /// values) supported by the OP for the ID Token.
    pub id_token_encryption_enc_values_supported: Option<Vec<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the UserInfo Endpoint.
    pub userinfo_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`alg`
    /// values) supported by the UserInfo Endpoint.
    pub userinfo_encryption_alg_values_supported: Option<Vec<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`enc`
    /// values) supported by the UserInfo Endpoint.
    pub userinfo_encryption_enc_values_supported: Option<Vec<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the OP for Request Objects.
    pub request_object_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`alg`
    /// values) supported by the OP for Request Objects.
    pub request_object_encryption_alg_values_supported: Option<Vec<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`enc`
    /// values) supported by the OP for Request Objects.
    pub request_object_encryption_enc_values_supported: Option<Vec<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the "display" parameter values that the
    /// OpenID Provider supports.
    pub display_values_supported: Option<Vec<Display>>,

    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports.
    ///
    /// Defaults to [`DEFAULT_CLAIM_TYPES_SUPPORTED`].
    pub claim_types_supported: Option<Vec<ClaimType>>,

    /// JSON array containing a list of the Claim Names of the Claims that the
    /// OpenID Provider MAY be able to supply values for.
    pub claims_supported: Option<Vec<String>>,

    /// Languages and scripts supported for values in Claims being returned,
    /// represented as a JSON array of BCP 47 language tag values.
    pub claims_locales_supported: Option<Vec<LanguageTag>>,

    /// Boolean value specifying whether the OP supports use of the `claims`
    /// parameter.
    ///
    /// Defaults to `false`.
    pub claims_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the `request`
    /// parameter.
    ///
    /// Defaults to `false`.
    pub request_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the
    /// `request_uri` parameter.
    ///
    /// Defaults to `true`.
    pub request_uri_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP requires any `request_uri`
    /// values used to be pre-registered.
    ///
    /// Defaults to `false`.
    pub require_request_uri_registration: Option<bool>,

    // -- Section 3: Additional protocol extensions --
    /// Indicates where authorization request needs to be protected as [Request
    /// Object] and provided through either request or `request_uri` parameter.
    ///
    /// Defaults to `false`.
    ///
    /// [Request Object]: https://www.rfc-editor.org/rfc/rfc9101.html
    pub require_signed_request_object: Option<bool>,

    /// URL of the authorization server's [pushed authorization request
    /// endpoint].
    ///
    /// [pushed authorization request endpoint]: https://www.rfc-editor.org/rfc/rfc9126.html
    pub pushed_authorization_request_endpoint: Option<Url>,

    /// Indicates whether the authorization server accepts authorization
    /// requests only via PAR.
    ///
    /// Defaults to `false`.
    pub require_pushed_authorization_requests: Option<bool>,

    /// Array containing the list of prompt values that this OP supports.
    ///
    /// This field can be used to detect if the OP supports the [prompt
    /// `create`] value.
    ///
    /// [prompt `create`]: https://openid.net/specs/openid-connect-prompt-create-1_0.html
    pub prompt_values_supported: Option<Vec<Prompt>>,

    /// URL of the authorization server's [device authorization endpoint].
    ///
    /// [device authorization endpoint]: https://www.rfc-editor.org/rfc/rfc8628
    pub device_authorization_endpoint: Option<Url>,

    /// URL of the authorization server's [RP-Initiated Logout endpoint].
    ///
    /// [RP-Initiated Logout endpoint]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    pub end_session_endpoint: Option<Url>,

    // -- Section 4: Matrix-specific extensions (MSC 2965) --
    /// URL where the user is able to access the account management capabilities
    /// of this OP.
    ///
    /// This is a Matrix extension introduced in [MSC2965](https://github.com/matrix-org/matrix-spec-proposals/pull/2965).
    pub account_management_uri: Option<Url>,

    /// Array of actions that the account management URL supports.
    ///
    /// This is a Matrix extension introduced in [MSC2965](https://github.com/matrix-org/matrix-spec-proposals/pull/2965).
    pub account_management_actions_supported: Option<Vec<AccountManagementAction>>,
}

// ---------------------------------------------------------------------------
// URL validation — builder-style UrlValidator
// ---------------------------------------------------------------------------

/// Fluent URL constraint checker used during provider metadata validation.
///
/// By default only the HTTPS scheme requirement is enforced. Call
/// [`UrlValidator::forbid_fragment`] and/or [`UrlValidator::forbid_query`] to
/// tighten the constraints before calling [`UrlValidator::check`].
struct UrlValidator {
    field_name: &'static str,
    allow_query: bool,
    allow_fragment: bool,
}

impl UrlValidator {
    /// Create a new validator for the given metadata field name.
    fn new(field_name: &'static str) -> Self {
        Self {
            field_name,
            allow_query: true,
            allow_fragment: true,
        }
    }

    /// Forbid the URL from containing a fragment component.
    fn forbid_fragment(mut self) -> Self {
        self.allow_fragment = false;
        self
    }

    /// Forbid the URL from containing a query component.
    fn forbid_query(mut self) -> Self {
        self.allow_query = false;
        self
    }

    /// Validate `url` against the accumulated constraints.
    fn check(self, url: &Url) -> Result<(), ProviderMetadataVerificationError> {
        if url.scheme() != "https" {
            return Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(
                self.field_name,
                url.clone(),
            ));
        }

        if !self.allow_query && url.query().is_some() {
            return Err(ProviderMetadataVerificationError::UrlWithQuery(
                self.field_name,
                url.clone(),
            ));
        }

        if !self.allow_fragment && url.fragment().is_some() {
            return Err(ProviderMetadataVerificationError::UrlWithFragment(
                self.field_name,
                url.clone(),
            ));
        }

        Ok(())
    }
}

/// Ensure that none of the provided JWS algorithm values is
/// [`JsonWebSignatureAlg::None`].
fn reject_none_signing_alg<'a>(
    endpoint: &'static str,
    alg_values: impl Iterator<Item = &'a JsonWebSignatureAlg>,
) -> Result<(), ProviderMetadataVerificationError> {
    for alg in alg_values {
        if *alg == JsonWebSignatureAlg::None {
            return Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(
                endpoint,
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ProviderMetadata — impl
// ---------------------------------------------------------------------------

/// A single validation rule applied during [`ProviderMetadata::validate`].
///
/// Each closure receives a reference to the already-verified metadata and
/// returns `Ok(())` when the rule passes.
type ValidationRule =
    Box<dyn FnOnce(&VerifiedProviderMetadata) -> Result<(), ProviderMetadataVerificationError>>;

impl ProviderMetadata {
    /// Validate this `ProviderMetadata` according to the [OpenID Connect
    /// Discovery Spec 1.0].
    ///
    /// # Parameters
    ///
    /// - `issuer`: The issuer that was discovered to get this
    ///   `ProviderMetadata`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if validation fails.
    ///
    /// [OpenID Connect Discovery Spec 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    pub fn validate(
        self,
        issuer: &str,
    ) -> Result<VerifiedProviderMetadata, ProviderMetadataVerificationError> {
        // First, verify required fields are present.
        let verified = self.insecure_verify_metadata()?;

        // Collect all validation rules into a list and run them sequentially.
        let expected_issuer = issuer.to_owned();
        let rules: Vec<ValidationRule> = vec![
            // Rule: issuer must match the expected value.
            Box::new(move |m| {
                if m.issuer() != expected_issuer {
                    return Err(ProviderMetadataVerificationError::IssuerUrlsDontMatch {
                        expected: expected_issuer,
                        actual: m.issuer().to_owned(),
                    });
                }
                Ok(())
            }),
            // Rule: issuer URL must be https, no query, no fragment.
            Box::new(|m| {
                let issuer_url: Url = m
                    .issuer()
                    .parse()
                    .map_err(|_| ProviderMetadataVerificationError::IssuerNotUrl)?;
                UrlValidator::new("issuer")
                    .forbid_query()
                    .forbid_fragment()
                    .check(&issuer_url)
            }),
            // Rule: authorization_endpoint — https, no fragment.
            Box::new(|m| {
                UrlValidator::new("authorization_endpoint")
                    .forbid_fragment()
                    .check(m.authorization_endpoint())
            }),
            // Rule: token_endpoint — https, no fragment.
            Box::new(|m| {
                UrlValidator::new("token_endpoint")
                    .forbid_fragment()
                    .check(m.token_endpoint())
            }),
            // Rule: jwks_uri — https only.
            Box::new(|m| UrlValidator::new("jwks_uri").check(m.jwks_uri())),
            // Rule: registration_endpoint (optional) — https only.
            Box::new(|m| {
                if let Some(url) = &m.registration_endpoint {
                    UrlValidator::new("registration_endpoint").check(url)?;
                }
                Ok(())
            }),
            // Rule: scopes_supported must include "openid" when present.
            Box::new(|m| {
                if let Some(scopes) = &m.scopes_supported {
                    let has_openid = scopes.iter().any(|s| s == "openid");
                    if !has_openid {
                        return Err(ProviderMetadataVerificationError::ScopesMissingOpenid);
                    }
                }
                Ok(())
            }),
            // Rule: token endpoint signing alg values must not contain "none".
            Box::new(|m| {
                reject_none_signing_alg(
                    "token_endpoint",
                    m.token_endpoint_auth_signing_alg_values_supported
                        .iter()
                        .flatten(),
                )
            }),
            // Rule: revocation_endpoint (optional) — https, no fragment.
            Box::new(|m| {
                if let Some(url) = &m.revocation_endpoint {
                    UrlValidator::new("revocation_endpoint")
                        .forbid_fragment()
                        .check(url)?;
                }
                Ok(())
            }),
            // Rule: revocation endpoint signing alg values must not contain "none".
            Box::new(|m| {
                reject_none_signing_alg(
                    "revocation_endpoint",
                    m.revocation_endpoint_auth_signing_alg_values_supported
                        .iter()
                        .flatten(),
                )
            }),
            // Rule: introspection_endpoint (optional) — https only.
            Box::new(|m| {
                if let Some(url) = &m.introspection_endpoint {
                    UrlValidator::new("introspection_endpoint").check(url)?;
                }
                Ok(())
            }),
            // Rule: introspection endpoint signing alg values must not contain "none".
            Box::new(|m| {
                reject_none_signing_alg(
                    "introspection_endpoint",
                    m.introspection_endpoint_auth_signing_alg_values_supported
                        .iter()
                        .flatten(),
                )
            }),
            // Rule: userinfo_endpoint (optional) — https only.
            Box::new(|m| {
                if let Some(url) = &m.userinfo_endpoint {
                    UrlValidator::new("userinfo_endpoint").check(url)?;
                }
                Ok(())
            }),
            // Rule: pushed_authorization_request_endpoint (optional) — https only.
            Box::new(|m| {
                if let Some(url) = &m.pushed_authorization_request_endpoint {
                    UrlValidator::new("pushed_authorization_request_endpoint").check(url)?;
                }
                Ok(())
            }),
            // Rule: end_session_endpoint (optional) — https only.
            Box::new(|m| {
                if let Some(url) = &m.end_session_endpoint {
                    UrlValidator::new("end_session_endpoint").check(url)?;
                }
                Ok(())
            }),
        ];

        for rule in rules {
            rule(&verified)?;
        }

        Ok(verified)
    }

    /// Verify this `ProviderMetadata`.
    ///
    /// Contrary to [`ProviderMetadata::validate()`], it only checks that the
    /// required fields are present.
    ///
    /// This can be used during development to test against a local OpenID
    /// Provider, for example.
    ///
    /// # Parameters
    ///
    /// - `issuer`: The issuer that was discovered to get this
    ///   `ProviderMetadata`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if a required field is missing.
    ///
    /// # Warning
    ///
    /// It is not recommended to use this method in production as it doesn't
    /// ensure that the issuer implements the proper security practices.
    pub fn insecure_verify_metadata(
        self,
    ) -> Result<VerifiedProviderMetadata, ProviderMetadataVerificationError> {
        // Use a helper macro to reduce repetition when checking required fields.
        macro_rules! require_field {
            ($field:ident, $err:ident) => {
                if self.$field.is_none() {
                    return Err(ProviderMetadataVerificationError::$err);
                }
            };
        }

        require_field!(issuer, MissingIssuer);
        require_field!(authorization_endpoint, MissingAuthorizationEndpoint);
        require_field!(token_endpoint, MissingTokenEndpoint);
        require_field!(jwks_uri, MissingJwksUri);
        require_field!(response_types_supported, MissingResponseTypesSupported);
        require_field!(subject_types_supported, MissingSubjectTypesSupported);
        require_field!(
            id_token_signing_alg_values_supported,
            MissingIdTokenSigningAlgValuesSupported
        );

        Ok(VerifiedProviderMetadata { inner: self })
    }

    /// JSON array containing a list of the OAuth 2.0 `response_mode` values
    /// that this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_MODES_SUPPORTED`].
    #[must_use]
    pub fn response_modes_supported(&self) -> &[ResponseMode] {
        self.response_modes_supported
            .as_deref()
            .unwrap_or(DEFAULT_RESPONSE_MODES_SUPPORTED)
    }

    /// JSON array containing a list of the OAuth 2.0 grant type values that
    /// this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES_SUPPORTED`].
    #[must_use]
    pub fn grant_types_supported(&self) -> &[GrantType] {
        self.grant_types_supported
            .as_deref()
            .unwrap_or(DEFAULT_GRANT_TYPES_SUPPORTED)
    }

    /// JSON array containing a list of client authentication methods supported
    /// by the token endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    #[must_use]
    pub fn token_endpoint_auth_methods_supported(&self) -> &[OAuthClientAuthenticationMethod] {
        self.token_endpoint_auth_methods_supported
            .as_deref()
            .unwrap_or(DEFAULT_AUTH_METHODS_SUPPORTED)
    }

    /// JSON array containing a list of client authentication methods supported
    /// by the revocation endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    #[must_use]
    pub fn revocation_endpoint_auth_methods_supported(&self) -> &[OAuthClientAuthenticationMethod] {
        self.revocation_endpoint_auth_methods_supported
            .as_deref()
            .unwrap_or(DEFAULT_AUTH_METHODS_SUPPORTED)
    }

    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports.
    ///
    /// Defaults to [`DEFAULT_CLAIM_TYPES_SUPPORTED`].
    #[must_use]
    pub fn claim_types_supported(&self) -> &[ClaimType] {
        self.claim_types_supported
            .as_deref()
            .unwrap_or(DEFAULT_CLAIM_TYPES_SUPPORTED)
    }

    /// Boolean value specifying whether the OP supports use of the `claims`
    /// parameter.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn claims_parameter_supported(&self) -> bool {
        self.claims_parameter_supported.unwrap_or(false)
    }

    /// Boolean value specifying whether the OP supports use of the `request`
    /// parameter.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn request_parameter_supported(&self) -> bool {
        self.request_parameter_supported.unwrap_or(false)
    }

    /// Boolean value specifying whether the OP supports use of the
    /// `request_uri` parameter.
    ///
    /// Defaults to `true`.
    #[must_use]
    pub fn request_uri_parameter_supported(&self) -> bool {
        self.request_uri_parameter_supported.unwrap_or(true)
    }

    /// Boolean value specifying whether the OP requires any `request_uri`
    /// values used to be pre-registered.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_request_uri_registration(&self) -> bool {
        self.require_request_uri_registration.unwrap_or(false)
    }

    /// Indicates where authorization request needs to be protected as Request
    /// Object and provided through either `request` or `request_uri` parameter.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_signed_request_object(&self) -> bool {
        self.require_signed_request_object.unwrap_or(false)
    }

    /// Indicates whether the authorization server accepts authorization
    /// requests only via PAR.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_pushed_authorization_requests(&self) -> bool {
        self.require_pushed_authorization_requests.unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// VerifiedProviderMetadata
// ---------------------------------------------------------------------------

/// The verified authorization server metadata.
///
/// All the fields required by the [OpenID Connect Discovery Spec 1.0] or with
/// a default value are accessible via methods.
///
/// To access other fields, use this type's `Deref` implementation.
///
/// [OpenID Connect Discovery Spec 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
#[derive(Debug, Clone)]
pub struct VerifiedProviderMetadata {
    inner: ProviderMetadata,
}

impl VerifiedProviderMetadata {
    /// Authorization server's issuer identifier URL.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.issuer
            .as_ref()
            .expect("issuer was verified to be present")
    }

    /// URL of the authorization server's authorization endpoint.
    #[must_use]
    pub fn authorization_endpoint(&self) -> &Url {
        self.authorization_endpoint
            .as_ref()
            .expect("authorization_endpoint was verified to be present")
    }

    /// URL of the authorization server's userinfo endpoint.
    #[must_use]
    pub fn userinfo_endpoint(&self) -> &Url {
        self.userinfo_endpoint
            .as_ref()
            .expect("userinfo_endpoint was verified to be present")
    }

    /// URL of the authorization server's token endpoint.
    #[must_use]
    pub fn token_endpoint(&self) -> &Url {
        self.token_endpoint
            .as_ref()
            .expect("token_endpoint was verified to be present")
    }

    /// URL of the authorization server's JWK Set document.
    #[must_use]
    pub fn jwks_uri(&self) -> &Url {
        self.jwks_uri
            .as_ref()
            .expect("jwks_uri was verified to be present")
    }

    /// JSON array containing a list of the OAuth 2.0 `response_type` values
    /// that this authorization server supports.
    #[must_use]
    pub fn response_types_supported(&self) -> &[ResponseType] {
        self.response_types_supported
            .as_ref()
            .expect("response_types_supported was verified to be present")
    }

    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports.
    #[must_use]
    pub fn subject_types_supported(&self) -> &[SubjectType] {
        self.subject_types_supported
            .as_ref()
            .expect("subject_types_supported was verified to be present")
    }

    /// JSON array containing a list of the JWS `alg` values supported by the OP
    /// for the ID Token.
    #[must_use]
    pub fn id_token_signing_alg_values_supported(&self) -> &[JsonWebSignatureAlg] {
        self.id_token_signing_alg_values_supported
            .as_ref()
            .expect("id_token_signing_alg_values_supported was verified to be present")
    }
}

impl Deref for VerifiedProviderMetadata {
    type Target = ProviderMetadata;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// ProviderMetadataVerificationError
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// RpInitiatedLogoutRequest
// ---------------------------------------------------------------------------

/// The body of a request to the [RP-Initiated Logout Endpoint].
///
/// [RP-Initiated Logout Endpoint]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
#[skip_serializing_none]
#[serde_as]
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct RpInitiatedLogoutRequest {
    /// OAuth 2.0 Client Identifier valid at the Authorization Server.
    ///
    /// The most common use case for this parameter is to specify the Client
    /// Identifier when `post_logout_redirect_uri` is used but `id_token_hint`
    /// is not. Another use is for symmetrically encrypted ID Tokens used as
    /// `id_token_hint` values that require the Client Identifier to be
    /// specified by other means, so that the ID Tokens can be decrypted by
    /// the OP.
    pub client_id: Option<String>,

    /// ID Token previously issued by the OP to the RP.
    ///
    /// Recommended, used as a hint about the End-User's current authenticated
    /// session with the Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the End-User that is logging out.
    ///
    /// The value and meaning of this parameter is left up to the OP's
    /// discretion. For instance, the value might contain an email address,
    /// phone number, username, or session identifier pertaining to the RP's
    /// session with the OP for the End-User.
    pub logout_hint: Option<String>,

    /// URI to which the RP is requesting that the End-User's User Agent be
    /// redirected after a logout has been performed.
    ///
    /// The value MUST have been previously registered with the OP, using the
    /// `post_logout_redirect_uris` registration parameter.
    pub post_logout_redirect_uri: Option<Url>,

    /// Opaque value used by the RP to maintain state between the logout request
    /// and the callback to the endpoint specified by the
    /// `post_logout_redirect_uri` parameter.
    pub state: Option<String>,

    /// End-User's preferred languages and scripts for the user interface,
    /// ordered by preference.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    pub ui_locales: Option<Vec<LanguageTag>>,
}

impl fmt::Debug for RpInitiatedLogoutRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpInitiatedLogoutRequest")
            .field("logout_hint", &self.logout_hint)
            .field("post_logout_redirect_uri", &self.post_logout_redirect_uri)
            .field("ui_locales", &self.ui_locales)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use coauth_iana::{
        jose::JsonWebSignatureAlg,
        oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
    };
    use url::Url;

    use super::*;

    // -- Test metadata builder -----------------------------------------------

    /// Builder for constructing [`ProviderMetadata`] in tests with sensible
    /// defaults that satisfy all required-field checks.
    struct TestMetadataBuilder {
        base_url: String,
        metadata: ProviderMetadata,
    }

    impl TestMetadataBuilder {
        /// Create a builder pre-populated with the minimal valid metadata
        /// pointing at the given base URL.
        fn new(base_url: &str) -> Self {
            let metadata = ProviderMetadata {
                issuer: Some(base_url.to_owned()),
                authorization_endpoint: Some(Url::parse(&format!("{base_url}/authorize")).unwrap()),
                token_endpoint: Some(Url::parse(&format!("{base_url}/token")).unwrap()),
                jwks_uri: Some(Url::parse(&format!("{base_url}/jwks")).unwrap()),
                response_types_supported: Some(vec![
                    OAuthAuthorizationEndpointResponseType::Code.into(),
                ]),
                subject_types_supported: Some(vec![SubjectType::Public]),
                id_token_signing_alg_values_supported: Some(vec![JsonWebSignatureAlg::Rs256]),
                ..Default::default()
            };
            Self {
                base_url: base_url.to_owned(),
                metadata,
            }
        }

        /// Return the issuer string that this builder uses.
        fn issuer_str(&self) -> &str {
            &self.base_url
        }

        /// Consume the builder, returning the metadata and its issuer string.
        fn build(self) -> (ProviderMetadata, String) {
            (self.metadata, self.base_url)
        }

        /// Obtain a mutable reference to the inner metadata for ad-hoc tweaks.
        fn metadata_mut(&mut self) -> &mut ProviderMetadata {
            &mut self.metadata
        }
    }

    /// Shorthand: build the default valid provider metadata pair.
    fn valid_provider_metadata() -> (ProviderMetadata, String) {
        TestMetadataBuilder::new("https://localhost").build()
    }

    // -- Required-field tests ------------------------------------------------

    #[test]
    fn validate_required_metadata() {
        let (metadata, issuer) = valid_provider_metadata();
        metadata.validate(&issuer).unwrap();
    }

    // -- Issuer tests --------------------------------------------------------

    #[test]
    fn validate_issuer() {
        let mut b = TestMetadataBuilder::new("https://localhost");
        let issuer = b.issuer_str().to_owned();

        // Err - Missing
        b.metadata_mut().issuer = None;
        assert_matches!(
            b.metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingIssuer)
        );

        // Err - Not an url
        b.metadata_mut().issuer = Some("not-an-url".to_owned());
        assert_matches!(
            b.metadata.clone().validate("not-an-url"),
            Err(ProviderMetadataVerificationError::IssuerNotUrl)
        );

        // Err - Wrong issuer
        b.metadata_mut().issuer = Some("https://example.com/".to_owned());
        assert_matches!(
            b.metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::IssuerUrlsDontMatch { .. })
        );

        // Err - Not https
        let bad_issuer = "http://localhost/".to_owned();
        b.metadata_mut().issuer = Some(bad_issuer.clone());
        let (field, url) = assert_matches!(
            b.metadata.clone().validate(&bad_issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "issuer");
        assert_eq!(url.as_str(), bad_issuer);

        // Err - Query
        let q_issuer = "https://localhost/?query".to_owned();
        b.metadata_mut().issuer = Some(q_issuer.clone());
        let (field, url) = assert_matches!(
            b.metadata.clone().validate(&q_issuer),
            Err(ProviderMetadataVerificationError::UrlWithQuery(field, url)) => (field, url)
        );
        assert_eq!(field, "issuer");
        assert_eq!(url.as_str(), q_issuer);

        // Err - Fragment
        let f_issuer = "https://localhost/#fragment".to_owned();
        b.metadata_mut().issuer = Some(f_issuer.clone());
        let (field, url) = assert_matches!(
            b.metadata.clone().validate(&f_issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "issuer");
        assert_eq!(url.as_str(), f_issuer);

        // Ok - Path
        let path_issuer = "https://localhost/issuer1".to_owned();
        b.metadata_mut().issuer = Some(path_issuer.clone());
        b.metadata.validate(&path_issuer).unwrap();
    }

    // -- authorization_endpoint tests ----------------------------------------

    #[test]
    fn validate_authorization_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.authorization_endpoint = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingAuthorizationEndpoint)
        );

        // Err - Not https
        let endpoint = Url::parse("http://localhost/auth").unwrap();
        metadata.authorization_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "authorization_endpoint");
        assert_eq!(url, endpoint);

        // Err - Fragment
        let endpoint = Url::parse("https://localhost/auth#fragment").unwrap();
        metadata.authorization_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "authorization_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query
        metadata.authorization_endpoint = Some(Url::parse("https://localhost/auth?query").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- token_endpoint tests ------------------------------------------------

    #[test]
    fn validate_token_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.token_endpoint = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingTokenEndpoint)
        );

        // Err - Not https
        let endpoint = Url::parse("http://localhost/token").unwrap();
        metadata.token_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "token_endpoint");
        assert_eq!(url, endpoint);

        // Err - Fragment
        let endpoint = Url::parse("https://localhost/token#fragment").unwrap();
        metadata.token_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "token_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query
        metadata.token_endpoint = Some(Url::parse("https://localhost/token?query").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- jwks_uri tests ------------------------------------------------------

    #[test]
    fn validate_jwks_uri() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.jwks_uri = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingJwksUri)
        );

        // Err - Not https
        let endpoint = Url::parse("http://localhost/jwks").unwrap();
        metadata.jwks_uri = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "jwks_uri");
        assert_eq!(url, endpoint);

        // Ok - Query & fragment
        metadata.jwks_uri = Some(Url::parse("https://localhost/token?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- registration_endpoint tests -----------------------------------------

    #[test]
    fn validate_registration_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/registration").unwrap();
        metadata.registration_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "registration_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Missing
        metadata.registration_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Ok - Query & fragment
        metadata.registration_endpoint =
            Some(Url::parse("https://localhost/registration?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- scopes_supported tests ----------------------------------------------

    #[test]
    fn validate_scopes_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - No `openid`
        metadata.scopes_supported = Some(vec!["custom".to_owned()]);
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::ScopesMissingOpenid)
        );

        // Ok - Missing
        metadata.scopes_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Ok - With `openid`
        metadata.scopes_supported = Some(vec!["openid".to_owned(), "custom".to_owned()]);
        metadata.validate(&issuer).unwrap();
    }

    // -- response_types_supported tests --------------------------------------

    #[test]
    fn validate_response_types_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.response_types_supported = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingResponseTypesSupported)
        );

        // Ok - Present
        metadata.response_types_supported =
            Some(vec![OAuthAuthorizationEndpointResponseType::Code.into()]);
        metadata.validate(&issuer).unwrap();
    }

    // -- token endpoint signing alg tests ------------------------------------

    #[test]
    fn validate_token_endpoint_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        metadata.token_endpoint_auth_methods_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - With `none`
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::None]);
        let endpoint = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "token_endpoint");

        // Ok - Other signing alg values.
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256, JsonWebSignatureAlg::EdDsa]);
        metadata.clone().validate(&issuer).unwrap();

        // Ok - `client_secret_jwt` with signing alg values.
        metadata.token_endpoint_auth_methods_supported =
            Some(vec![OAuthClientAuthenticationMethod::ClientSecretJwt]);
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256]);
        metadata.clone().validate(&issuer).unwrap();

        // Ok - `private_key_jwt` with signing alg values.
        metadata.token_endpoint_auth_methods_supported =
            Some(vec![OAuthClientAuthenticationMethod::PrivateKeyJwt]);
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256]);
        metadata.clone().validate(&issuer).unwrap();

        // Ok - `client_secret_jwt` without signing alg values.
        metadata.token_endpoint_auth_methods_supported =
            Some(vec![OAuthClientAuthenticationMethod::ClientSecretJwt]);
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Ok - `private_key_jwt` without signing alg values.
        metadata.token_endpoint_auth_methods_supported =
            Some(vec![OAuthClientAuthenticationMethod::PrivateKeyJwt]);
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Ok - Other auth methods without signing alg values.
        metadata.token_endpoint_auth_methods_supported = Some(vec![
            OAuthClientAuthenticationMethod::ClientSecretBasic,
            OAuthClientAuthenticationMethod::ClientSecretPost,
        ]);
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        metadata.validate(&issuer).unwrap();
    }

    // -- revocation_endpoint tests -------------------------------------------

    #[test]
    fn validate_revocation_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.revocation_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/revocation").unwrap();
        metadata.revocation_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "revocation_endpoint");
        assert_eq!(url, endpoint);

        // Err - Fragment
        let endpoint = Url::parse("https://localhost/revocation#fragment").unwrap();
        metadata.revocation_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "revocation_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query
        metadata.revocation_endpoint =
            Some(Url::parse("https://localhost/revocation?query").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- revocation endpoint signing alg tests -------------------------------

    #[test]
    fn validate_revocation_endpoint_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Only check that this field is validated, algorithm checks are already
        // tested for the token endpoint.

        // Ok - Missing
        metadata.revocation_endpoint_auth_signing_alg_values_supported = None;
        metadata.revocation_endpoint_auth_methods_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - With `none`
        metadata.revocation_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::None]);
        let endpoint = assert_matches!(
            metadata.validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "revocation_endpoint");
    }

    // -- introspection_endpoint tests ----------------------------------------

    #[test]
    fn validate_introspection_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.introspection_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/introspection").unwrap();
        metadata.introspection_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "introspection_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query & Fragment
        metadata.introspection_endpoint =
            Some(Url::parse("https://localhost/introspection?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- introspection endpoint signing alg tests ----------------------------

    #[test]
    fn validate_introspection_endpoint_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Only check that this field is validated, algorithm checks are already
        // tested for the token endpoint.

        // Ok - Missing
        metadata.introspection_endpoint_auth_signing_alg_values_supported = None;
        metadata.introspection_endpoint_auth_methods_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - With `none`
        metadata.introspection_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::None]);
        let endpoint = assert_matches!(
            metadata.validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "introspection_endpoint");
    }

    // -- userinfo_endpoint tests ---------------------------------------------

    #[test]
    fn validate_userinfo_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.userinfo_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/userinfo").unwrap();
        metadata.userinfo_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "userinfo_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query & Fragment
        metadata.userinfo_endpoint =
            Some(Url::parse("https://localhost/userinfo?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- subject_types_supported tests ---------------------------------------

    #[test]
    fn validate_subject_types_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.subject_types_supported = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingSubjectTypesSupported)
        );

        // Ok - Present
        metadata.subject_types_supported = Some(vec![SubjectType::Public, SubjectType::Pairwise]);
        metadata.validate(&issuer).unwrap();
    }

    // -- id_token_signing_alg tests ------------------------------------------

    #[test]
    fn validate_id_token_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.id_token_signing_alg_values_supported = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingIdTokenSigningAlgValuesSupported)
        );

        // Ok - Present
        metadata.id_token_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256, JsonWebSignatureAlg::EdDsa]);
        metadata.validate(&issuer).unwrap();
    }

    // -- pushed_authorization_request_endpoint tests -------------------------

    #[test]
    fn validate_pushed_authorization_request_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.pushed_authorization_request_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/par").unwrap();
        metadata.pushed_authorization_request_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "pushed_authorization_request_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query & Fragment
        metadata.pushed_authorization_request_endpoint =
            Some(Url::parse("https://localhost/par?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    // -- Enum serialization round-trip tests ---------------------------------

    #[test]
    fn serialize_application_type() {
        assert_eq!(
            serde_json::to_string(&ApplicationType::Web).unwrap(),
            "\"web\""
        );
        assert_eq!(
            serde_json::to_string(&ApplicationType::Native).unwrap(),
            "\"native\""
        );
    }

    #[test]
    fn deserialize_application_type() {
        assert_eq!(
            serde_json::from_str::<ApplicationType>("\"web\"").unwrap(),
            ApplicationType::Web
        );
        assert_eq!(
            serde_json::from_str::<ApplicationType>("\"native\"").unwrap(),
            ApplicationType::Native
        );
    }

    #[test]
    fn serialize_subject_type() {
        assert_eq!(
            serde_json::to_string(&SubjectType::Public).unwrap(),
            "\"public\""
        );
        assert_eq!(
            serde_json::to_string(&SubjectType::Pairwise).unwrap(),
            "\"pairwise\""
        );
    }

    #[test]
    fn deserialize_subject_type() {
        assert_eq!(
            serde_json::from_str::<SubjectType>("\"public\"").unwrap(),
            SubjectType::Public
        );
        assert_eq!(
            serde_json::from_str::<SubjectType>("\"pairwise\"").unwrap(),
            SubjectType::Pairwise
        );
    }

    #[test]
    fn serialize_claim_type() {
        assert_eq!(
            serde_json::to_string(&ClaimType::Normal).unwrap(),
            "\"normal\""
        );
        assert_eq!(
            serde_json::to_string(&ClaimType::Aggregated).unwrap(),
            "\"aggregated\""
        );
        assert_eq!(
            serde_json::to_string(&ClaimType::Distributed).unwrap(),
            "\"distributed\""
        );
    }

    #[test]
    fn deserialize_claim_type() {
        assert_eq!(
            serde_json::from_str::<ClaimType>("\"normal\"").unwrap(),
            ClaimType::Normal
        );
        assert_eq!(
            serde_json::from_str::<ClaimType>("\"aggregated\"").unwrap(),
            ClaimType::Aggregated
        );
        assert_eq!(
            serde_json::from_str::<ClaimType>("\"distributed\"").unwrap(),
            ClaimType::Distributed
        );
    }

    #[test]
    fn deserialize_auth_method_or_token_type_type() {
        assert_eq!(
            serde_json::from_str::<AuthenticationMethodOrAccessTokenType>("\"none\"").unwrap(),
            AuthenticationMethodOrAccessTokenType::AuthenticationMethod(
                OAuthClientAuthenticationMethod::None
            )
        );
        assert_eq!(
            serde_json::from_str::<AuthenticationMethodOrAccessTokenType>("\"Bearer\"").unwrap(),
            AuthenticationMethodOrAccessTokenType::AccessTokenType(OAuthAccessTokenType::Bearer)
        );
        assert_eq!(
            serde_json::from_str::<AuthenticationMethodOrAccessTokenType>("\"unknown_value\"")
                .unwrap(),
            AuthenticationMethodOrAccessTokenType::Unknown("unknown_value".to_owned())
        );
    }
}
