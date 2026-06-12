//! The [`ClientMetadata`] struct and its accessor methods.

use chrono::Duration;
use coauth_iana::jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg};
use coauth_iana::oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod};
use coauth_jose::jwk::PublicJsonWebKeySet;
use serde::{Deserialize, Serialize};
use url::Url;

use super::client_metadata_serde::ClientMetadataSerdeHelper;
use super::localized::Localized;
use super::validation::{ClientMetadataVerificationError, VerifiedClientMetadata};
use super::{
    DEFAULT_APPLICATION_TYPE, DEFAULT_ENCRYPTION_ENC_ALGORITHM, DEFAULT_GRANT_TYPES,
    DEFAULT_RESPONSE_TYPES, DEFAULT_SIGNING_ALGORITHM, DEFAULT_TOKEN_AUTH_METHOD,
};
use crate::oidc::{ApplicationType, SubjectType};
use crate::requests::GrantType;
use crate::response_type::ResponseType;

/// Client metadata, as described by the [IANA registry].
///
/// All the fields with a default value are accessible via methods.
///
/// Fields are organized by spec section:
/// - RFC 7591 (OAuth Dynamic Client Registration) core fields
/// - OpenID Connect Registration 1.0 fields
/// - RFC 9101 / RFC 9126 extension fields
/// - Token introspection extension fields
/// - RP-Initiated Logout fields
///
/// [IANA registry]: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(from = "ClientMetadataSerdeHelper", into = "ClientMetadataSerdeHelper")]
pub struct ClientMetadata {
    // -- RFC 7591: OAuth Dynamic Client Registration Protocol --
    /// Array of redirection URIs for use in redirect-based flows such as the
    /// [authorization code flow].
    ///
    /// All the URIs used by the client in an authorization request's
    /// `redirect_uri` field must appear in this list.
    ///
    /// This field is required and the URIs must not contain a fragment.
    ///
    /// [authorization code flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
    pub redirect_uris: Option<Vec<Url>>,

    /// Array of the [OAuth `response_type` values] that the client can use
    /// at the [authorization endpoint].
    ///
    /// All the types used by the client in an authorization request's
    /// `response_type` field must appear in this list.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_TYPES`].
    ///
    /// [OAuth `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
    pub response_types: Option<Vec<ResponseType>>,

    /// Array of [OAuth `grant_type` values] that the client can use at the
    /// [token endpoint].
    ///
    /// The possible grant types depend on the response types. Declaring support
    /// for a grant type that is not compatible with the supported response
    /// types will trigger an error during validation.
    ///
    /// All the types used by the client in a token request's `grant_type` field
    /// must appear in this list.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES`].
    ///
    /// [OAuth `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    pub grant_types: Option<Vec<GrantType>>,

    /// Requested client authentication method for the [token endpoint].
    ///
    /// If this is set to [`OAuthClientAuthenticationMethod::PrivateKeyJwt`],
    /// one of the `jwks_uri` or `jwks` fields is required.
    ///
    /// Defaults to [`DEFAULT_TOKEN_AUTH_METHOD`].
    ///
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    pub token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,

    /// [JWS] `alg` algorithm that must be used for signing the [JWT] used to
    /// authenticate the client at the token endpoint.
    ///
    /// If this field is present, it must not be
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `token_endpoint_auth_method` is one of
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    /// [JWT]: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// Name of the client to be presented to the end-user during authorization.
    pub client_name: Option<Localized<String>>,

    /// URL that references a logo for the client application.
    pub logo_uri: Option<Localized<Url>>,

    /// URL of the home page of the client.
    pub client_uri: Option<Localized<Url>>,

    /// URL that the client provides to the end-user to read about the how the
    /// profile data will be used.
    pub policy_uri: Option<Localized<Url>>,

    /// URL that the client provides to the end-user to read about the client's
    /// terms of service.
    pub tos_uri: Option<Localized<Url>>,

    /// Array of e-mail addresses of people responsible for this client.
    pub contacts: Option<Vec<String>>,

    /// URL for the client's [JWK] Set document.
    ///
    /// If the client signs requests to the server, it contains the signing
    /// key(s) the server uses to validate signatures from the client. The JWK
    /// Set may also contain the client's encryption keys(s), which are used by
    /// the server to encrypt responses to the client.
    ///
    /// This field is mutually exclusive with `jwks`.
    ///
    /// [JWK]: https://www.rfc-editor.org/rfc/rfc7517.html
    pub jwks_uri: Option<Url>,

    /// Client's [JWK] Set document, passed by value.
    ///
    /// The semantics of this field are the same as `jwks_uri`, other than that
    /// the JWK Set is passed by value, rather than by reference.
    ///
    /// This field is mutually exclusive with `jwks_uri`.
    ///
    /// [JWK]: https://www.rfc-editor.org/rfc/rfc7517.html
    pub jwks: Option<PublicJsonWebKeySet>,

    /// A unique identifier string assigned by the client developer or software
    /// publisher used by registration endpoints to identify the client software
    /// to be dynamically registered.
    ///
    /// It should remain the same for all instances and versions of the client
    /// software.
    pub software_id: Option<String>,

    /// A version identifier string for the client software identified by
    /// `software_id`.
    pub software_version: Option<String>,

    // -- OpenID Connect Registration 1.0 --
    /// The kind of the application.
    ///
    /// Defaults to [`DEFAULT_APPLICATION_TYPE`].
    pub application_type: Option<ApplicationType>,

    /// URL to be used in calculating pseudonymous identifiers by the OpenID
    /// Connect provider when [pairwise subject identifiers] are used.
    ///
    /// If present, this must use the `https` scheme.
    ///
    /// [pairwise subject identifiers]: https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
    pub sector_identifier_uri: Option<Url>,

    /// Subject type requested for responses to this client.
    ///
    /// This field must match one of the supported types by the provider.
    pub subject_type: Option<SubjectType>,

    /// [JWS] `alg` algorithm required for signing the ID Token issued to this
    /// client.
    ///
    /// If this field is present, it must not be
    /// [`JsonWebSignatureAlg::None`], unless the client uses only response
    /// types that return no ID Token from the authorization endpoint.
    ///
    /// Defaults to [`DEFAULT_SIGNING_ALGORITHM`].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    pub id_token_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm required for encrypting the ID Token issued to
    /// this client.
    ///
    /// This field is required if `id_token_encrypted_response_enc` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub id_token_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm required for encrypting the ID Token issued to
    /// this client.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `id_token_encrypted_response_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub id_token_encrypted_response_enc: Option<JsonWebEncryptionEnc>,

    /// [JWS] `alg` algorithm required for signing user info responses.
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm required for encrypting user info responses.
    ///
    /// If `userinfo_signed_response_alg` is not provided, this field has no
    /// effect.
    ///
    /// This field is required if `userinfo_encrypted_response_enc` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub userinfo_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm required for encrypting user info responses.
    ///
    /// If `userinfo_signed_response_alg` is not provided, this field has no
    /// effect.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `userinfo_encrypted_response_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub userinfo_encrypted_response_enc: Option<JsonWebEncryptionEnc>,

    /// [JWS] `alg` algorithm that must be used for signing Request Objects sent
    /// to the provider.
    ///
    /// Defaults to any algorithm supported by the client and the provider.
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    pub request_object_signing_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm the client is declaring that it may use for
    /// encrypting Request Objects sent to the provider.
    ///
    /// This field is required if `request_object_encryption_enc` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub request_object_encryption_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm the client is declaring that it may use for
    /// encrypting Request Objects sent to the provider.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `request_object_encryption_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub request_object_encryption_enc: Option<JsonWebEncryptionEnc>,

    /// Default maximum authentication age.
    ///
    /// Specifies that the End-User must be actively authenticated if the
    /// end-user was authenticated longer ago than the specified number of
    /// seconds.
    ///
    /// The `max_age` request parameter overrides this default value.
    pub default_max_age: Option<Duration>,

    /// Whether the `auth_time` Claim in the ID Token is required.
    ///
    /// Defaults to `false`.
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference values.
    pub default_acr_values: Option<Vec<String>>,

    /// URI that a third party can use to [initiate a login by the client].
    ///
    /// If present, this must use the `https` scheme.
    ///
    /// [initiate a login by the client]: https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin
    pub initiate_login_uri: Option<Url>,

    /// `request_uri` values that are pre-registered by the client for use at
    /// the provider.
    ///
    /// Providers can require that `request_uri` values used be pre-registered
    /// with the `require_request_uri_registration` discovery parameter.
    ///
    /// Servers MAY cache the contents of the files referenced by these URIs and
    /// not retrieve them at the time they are used in a request. If the
    /// contents of the request file could ever change, these URI values should
    /// include the base64url encoded SHA-256 hash value of the file contents
    /// referenced by the URI as the value of the URI fragment. If the fragment
    /// value used for a URI changes, that signals the server that its cached
    /// value for that URI with the old fragment value is no longer valid.
    pub request_uris: Option<Vec<Url>>,

    // -- RFC 9101 / RFC 9126 extensions --
    /// Whether the client will only send authorization requests as [Request
    /// Objects].
    ///
    /// Defaults to `false`.
    ///
    /// [Request Object]: https://www.rfc-editor.org/rfc/rfc9101.html
    pub require_signed_request_object: Option<bool>,

    /// Whether the client will only send authorization requests via the [pushed
    /// authorization request endpoint].
    ///
    /// Defaults to `false`.
    ///
    /// [pushed authorization request endpoint]: https://www.rfc-editor.org/rfc/rfc9126.html
    pub require_pushed_authorization_requests: Option<bool>,

    // -- Token introspection extensions --
    /// [JWS] `alg` algorithm for signing responses of the [introspection
    /// endpoint].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    pub introspection_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm for encrypting responses of the [introspection
    /// endpoint].
    ///
    /// If `introspection_signed_response_alg` is not provided, this field has
    /// no effect.
    ///
    /// This field is required if `introspection_encrypted_response_enc` is
    /// provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    pub introspection_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm for encrypting responses of the [introspection
    /// endpoint].
    ///
    /// If `introspection_signed_response_alg` is not provided, this field has
    /// no effect.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `introspection_encrypted_response_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    pub introspection_encrypted_response_enc: Option<JsonWebEncryptionEnc>,

    // -- RP-Initiated Logout --
    /// `post_logout_redirect_uri` values that are pre-registered by the client
    /// for use at the provider's [RP-Initiated Logout endpoint].
    ///
    /// [RP-Initiated Logout endpoint]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    pub post_logout_redirect_uris: Option<Vec<Url>>,
}

impl ClientMetadata {
    /// Validate this `ClientMetadata` according to the [OpenID Connect Dynamic
    /// Client Registration Spec 1.0].
    ///
    /// This method collects all validation errors rather than stopping at the
    /// first one. When multiple errors are found, they are returned as a
    /// [`ClientMetadataVerificationError::Multiple`] variant.
    ///
    /// # Errors
    ///
    /// Will return `Err` if validation fails.
    ///
    /// [OpenID Connect Dynamic Client Registration Spec 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
    pub fn validate(self) -> Result<VerifiedClientMetadata, ClientMetadataVerificationError> {
        let mut collected_errors: Vec<ClientMetadataVerificationError> = Vec::new();

        let grant_types = self.grant_types();
        let has_implicit = grant_types.contains(&GrantType::Implicit);
        let has_authorization_code = grant_types.contains(&GrantType::AuthorizationCode);
        let has_both = has_implicit && has_authorization_code;

        // Validate redirect URIs
        if let Some(uris) = &self.redirect_uris {
            for uri in uris {
                if uri.fragment().is_some() {
                    collected_errors.push(
                        ClientMetadataVerificationError::RedirectUriWithFragment(uri.clone()),
                    );
                }
            }
        } else if has_authorization_code || has_implicit {
            collected_errors.push(ClientMetadataVerificationError::MissingRedirectUris);
        }

        // Validate response types against grant types
        let response_type_code = [OAuthAuthorizationEndpointResponseType::Code.into()];
        let response_types = match &self.response_types {
            Some(types) => &types[..],
            None if has_authorization_code || has_implicit => &response_type_code[..],
            None => &[],
        };

        for response_type in response_types {
            let has_code = response_type.has_code();
            let has_id_token = response_type.has_id_token();
            let has_token = response_type.has_token();
            let is_ok = has_code && has_both
                || !has_code && has_implicit
                || has_authorization_code && !has_id_token && !has_token
                || !has_code && !has_id_token && !has_token;

            if !is_ok {
                collected_errors.push(ClientMetadataVerificationError::IncoherentResponseType(
                    response_type.clone(),
                ));
            }
        }

        // Validate JWKS mutual exclusivity
        if self.jwks_uri.is_some() && self.jwks.is_some() {
            collected_errors.push(ClientMetadataVerificationError::JwksUriAndJwksMutuallyExclusive);
        }

        // Validate sector_identifier_uri scheme
        if let Some(url) = self
            .sector_identifier_uri
            .as_ref()
            .filter(|url| url.scheme() != "https")
        {
            collected_errors.push(ClientMetadataVerificationError::UrlNonHttpsScheme(
                "sector_identifier_uri",
                url.clone(),
            ));
        }

        // Validate token endpoint auth requirements
        if *self.token_endpoint_auth_method() == OAuthClientAuthenticationMethod::PrivateKeyJwt
            && self.jwks_uri.is_none()
            && self.jwks.is_none()
        {
            collected_errors.push(ClientMetadataVerificationError::MissingJwksForTokenMethod);
        }

        if let Some(alg) = &self.token_endpoint_auth_signing_alg {
            if *alg == JsonWebSignatureAlg::None {
                collected_errors.push(ClientMetadataVerificationError::UnauthorizedSigningAlgNone(
                    "token_endpoint",
                ));
            }
        } else if matches!(
            self.token_endpoint_auth_method(),
            OAuthClientAuthenticationMethod::PrivateKeyJwt
                | OAuthClientAuthenticationMethod::ClientSecretJwt
        ) {
            collected_errors.push(ClientMetadataVerificationError::MissingAuthSigningAlg(
                "token_endpoint",
            ));
        }

        // Validate ID token signing algorithm
        if *self.id_token_signed_response_alg() == JsonWebSignatureAlg::None
            && response_types.iter().any(ResponseType::has_id_token)
        {
            collected_errors.push(ClientMetadataVerificationError::IdTokenSigningAlgNone);
        }

        // Validate encryption alg/enc pairs
        if self.id_token_encrypted_response_enc.is_some()
            && self.id_token_encrypted_response_alg.is_none()
        {
            collected_errors.push(ClientMetadataVerificationError::MissingEncryptionAlg(
                "id_token",
            ));
        }

        if self.userinfo_encrypted_response_enc.is_some()
            && self.userinfo_encrypted_response_alg.is_none()
        {
            collected_errors.push(ClientMetadataVerificationError::MissingEncryptionAlg(
                "userinfo",
            ));
        }

        if self.request_object_encryption_enc.is_some()
            && self.request_object_encryption_alg.is_none()
        {
            collected_errors.push(ClientMetadataVerificationError::MissingEncryptionAlg(
                "request_object",
            ));
        }

        // Validate initiate_login_uri scheme
        if let Some(url) = self
            .initiate_login_uri
            .as_ref()
            .filter(|url| url.scheme() != "https")
        {
            collected_errors.push(ClientMetadataVerificationError::UrlNonHttpsScheme(
                "initiate_login_uri",
                url.clone(),
            ));
        }

        // Validate introspection encryption alg/enc pair
        if self.introspection_encrypted_response_enc.is_some()
            && self.introspection_encrypted_response_alg.is_none()
        {
            collected_errors.push(ClientMetadataVerificationError::MissingEncryptionAlg(
                "introspection",
            ));
        }

        // Return collected errors or the validated metadata
        match collected_errors.len() {
            0 => Ok(VerifiedClientMetadata::new(self)),
            1 => Err(collected_errors.into_iter().next().expect("validated")),
            _ => Err(ClientMetadataVerificationError::Multiple(collected_errors)),
        }
    }

    /// Sort the properties. This is inteded to ensure a stable serialization
    /// order when needed.
    #[must_use]
    pub fn sorted(mut self) -> Self {
        if let Some(redirect_uris) = &mut self.redirect_uris {
            redirect_uris.sort();
        }
        if let Some(response_types) = &mut self.response_types {
            response_types.sort();
        }
        if let Some(grant_types) = &mut self.grant_types {
            grant_types.sort();
        }
        if let Some(contacts) = &mut self.contacts {
            contacts.sort();
        }
        if let Some(client_name) = &mut self.client_name {
            client_name.sort();
        }
        if let Some(logo_uri) = &mut self.logo_uri {
            logo_uri.sort();
        }
        if let Some(client_uri) = &mut self.client_uri {
            client_uri.sort();
        }
        if let Some(policy_uri) = &mut self.policy_uri {
            policy_uri.sort();
        }
        if let Some(tos_uri) = &mut self.tos_uri {
            tos_uri.sort();
        }
        if let Some(default_acr_values) = &mut self.default_acr_values {
            default_acr_values.sort();
        }
        if let Some(request_uris) = &mut self.request_uris {
            request_uris.sort();
        }
        if let Some(post_logout_redirect_uris) = &mut self.post_logout_redirect_uris {
            post_logout_redirect_uris.sort();
        }

        self
    }

    /// Array of the [OAuth `response_type` values] that the client can use
    /// at the [authorization endpoint].
    ///
    /// All the types used by the client in an authorization request's
    /// `response_type` field must appear in this list.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_TYPES`].
    ///
    /// [OAuth `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
    #[must_use]
    pub fn response_types(&self) -> Vec<ResponseType> {
        self.response_types.clone().unwrap_or_else(|| {
            DEFAULT_RESPONSE_TYPES
                .into_iter()
                .map(ResponseType::from)
                .collect()
        })
    }

    /// Array of [OAuth `grant_type` values] that the client can use at the
    /// [token endpoint].
    ///
    /// Note that the possible grant types depend on the response types.
    ///
    /// All the types used by the client in a token request's `grant_type` field
    /// must appear in this list.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES`].
    ///
    /// [OAuth `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    #[must_use]
    pub fn grant_types(&self) -> &[GrantType] {
        self.grant_types.as_deref().unwrap_or(DEFAULT_GRANT_TYPES)
    }

    /// The kind of the application.
    ///
    /// Defaults to [`DEFAULT_APPLICATION_TYPE`].
    #[must_use]
    pub fn application_type(&self) -> ApplicationType {
        self.application_type
            .clone()
            .unwrap_or(DEFAULT_APPLICATION_TYPE)
    }

    /// Requested client authentication method for the [token endpoint].
    ///
    /// Defaults to [`DEFAULT_TOKEN_AUTH_METHOD`].
    ///
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    #[must_use]
    pub fn token_endpoint_auth_method(&self) -> &OAuthClientAuthenticationMethod {
        self.token_endpoint_auth_method
            .as_ref()
            .unwrap_or(DEFAULT_TOKEN_AUTH_METHOD)
    }

    /// [JWS] `alg` algorithm required for signing the ID Token issued to this
    /// client.
    ///
    /// If this field is present, it must not be
    /// [`JsonWebSignatureAlg::None`], unless the client uses only response
    /// types that return no ID Token from the authorization endpoint.
    ///
    /// Defaults to [`DEFAULT_SIGNING_ALGORITHM`].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    #[must_use]
    pub fn id_token_signed_response_alg(&self) -> &JsonWebSignatureAlg {
        self.id_token_signed_response_alg
            .as_ref()
            .unwrap_or(DEFAULT_SIGNING_ALGORITHM)
    }

    /// [JWE] `alg` and `enc` algorithms required for encrypting the ID Token
    /// issued to this client.
    ///
    /// Always returns `Some` if `id_token_encrypted_response_alg` is provided,
    /// using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for the `enc`
    /// value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    #[must_use]
    pub fn id_token_encrypted_response(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.id_token_encrypted_response_alg.as_ref().map(|alg| {
            (
                alg,
                self.id_token_encrypted_response_enc
                    .as_ref()
                    .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
            )
        })
    }

    /// [JWE] `alg` and `enc` algorithms required for encrypting user info
    /// responses.
    ///
    /// Always returns `Some` if `userinfo_encrypted_response_alg` is provided,
    /// using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for the `enc`
    /// value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    #[must_use]
    pub fn userinfo_encrypted_response(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.userinfo_encrypted_response_alg.as_ref().map(|alg| {
            (
                alg,
                self.userinfo_encrypted_response_enc
                    .as_ref()
                    .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
            )
        })
    }

    /// [JWE] `alg` and `enc` algorithms the client is declaring that it may use
    /// for encrypting Request Objects sent to the provider.
    ///
    /// Always returns `Some` if `request_object_encryption_alg` is provided,
    /// using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for the `enc`
    /// value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    #[must_use]
    pub fn request_object_encryption(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.request_object_encryption_alg.as_ref().map(|alg| {
            (
                alg,
                self.request_object_encryption_enc
                    .as_ref()
                    .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
            )
        })
    }

    /// Whether the `auth_time` Claim in the ID Token is required.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_auth_time(&self) -> bool {
        self.require_auth_time.unwrap_or_default()
    }

    /// Whether the client will only send authorization requests as [Request
    /// Objects].
    ///
    /// Defaults to `false`.
    ///
    /// [Request Object]: https://www.rfc-editor.org/rfc/rfc9101.html
    #[must_use]
    pub fn require_signed_request_object(&self) -> bool {
        self.require_signed_request_object.unwrap_or_default()
    }

    /// Whether the client will only send authorization requests via the [pushed
    /// authorization request endpoint].
    ///
    /// Defaults to `false`.
    ///
    /// [pushed authorization request endpoint]: https://www.rfc-editor.org/rfc/rfc9126.html
    #[must_use]
    pub fn require_pushed_authorization_requests(&self) -> bool {
        self.require_pushed_authorization_requests
            .unwrap_or_default()
    }

    /// [JWE] `alg` and `enc` algorithms for encrypting responses of the
    /// [introspection endpoint].
    ///
    /// Always returns `Some` if `introspection_encrypted_response_alg` is
    /// provided, using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for
    /// the `enc` value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    #[must_use]
    pub fn introspection_encrypted_response(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.introspection_encrypted_response_alg
            .as_ref()
            .map(|alg| {
                (
                    alg,
                    self.introspection_encrypted_response_enc
                        .as_ref()
                        .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
                )
            })
    }
}
