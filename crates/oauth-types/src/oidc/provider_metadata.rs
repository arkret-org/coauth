// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! The unverified OpenID Connect / OAuth authorization server metadata struct.

use coauth_iana::jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg};
use coauth_iana::oauth::{OAuthClientAuthenticationMethod, PkceCodeChallengeMethod};
use language_tags::LanguageTag;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::oidc::{
    AccountManagementAction, AuthenticationMethodOrAccessTokenType, ClaimType, SubjectType,
};
use crate::requests::{Display, GrantType, Prompt, ResponseMode};
use crate::response_type::ResponseType;

/// Authorization server metadata, as described by the [IANA registry].
///
/// All the fields with a default value are accessible via methods.
///
/// [IANA registry]: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProviderMetadata {
    // -- Section 1: Core OAuth Authorization Server Metadata (RFC 8414) --
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

    /// URL of the authorization server's [OAuth Dynamic Client
    /// Registration] endpoint.
    ///
    /// If this field is present, the URL must use a `https` scheme.
    ///
    /// [OAuth Dynamic Client Registration]: https://www.rfc-editor.org/rfc/rfc7591
    pub registration_endpoint: Option<Url>,

    /// JSON array containing a list of the OAuth `scope` values that this
    /// authorization server supports.
    ///
    /// If this field is present, it must contain at least the `openid` scope
    /// value.
    pub scopes_supported: Option<Vec<String>>,

    /// JSON array containing a list of the [OAuth `response_type` values]
    /// that this authorization server supports.
    ///
    /// This field is required.
    ///
    /// [OAuth `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    pub response_types_supported: Option<Vec<ResponseType>>,

    /// JSON array containing a list of the [OAuth `response_mode` values]
    /// that this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_MODES_SUPPORTED`].
    ///
    /// [OAuth `response_mode` values]: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
    pub response_modes_supported: Option<Vec<ResponseMode>>,

    /// JSON array containing a list of the [OAuth `grant_type` values] that
    /// this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES_SUPPORTED`].
    ///
    /// [OAuth `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
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

    /// URL of the authorization server's [OAuth revocation endpoint].
    ///
    /// If this field is present, the URL must use a `https` scheme, and must
    /// not contain a fragment.
    ///
    /// [OAuth revocation endpoint]: https://www.rfc-editor.org/rfc/rfc7009
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

    /// URL of the authorization server's [OAuth introspection endpoint].
    ///
    /// If this field is present, the URL must use a `https` scheme.
    ///
    /// [OAuth introspection endpoint]: https://www.rfc-editor.org/rfc/rfc7662
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

    // -- Section 4: Account-management extensions --
    /// URL where the user is able to access the account management capabilities
    /// of this OP.
    pub account_management_uri: Option<Url>,

    /// Array of actions that the account management URL supports.
    pub account_management_actions_supported: Option<Vec<AccountManagementAction>>,
}
