// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! Validation of [`ProviderMetadata`] and the [`VerifiedProviderMetadata`]
//! wrapper that guarantees the presence of the required fields.

use std::ops::Deref;

use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use url::Url;

use crate::oidc::{
    ClaimType, DEFAULT_AUTH_METHODS_SUPPORTED, DEFAULT_CLAIM_TYPES_SUPPORTED,
    DEFAULT_GRANT_TYPES_SUPPORTED, DEFAULT_RESPONSE_MODES_SUPPORTED, ProviderMetadata,
    ProviderMetadataVerificationError, SubjectType,
};
use crate::requests::{GrantType, ResponseMode};
use crate::response_type::ResponseType;

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
    /// - `issuer`: The issuer that was discovered to get this `ProviderMetadata`.
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
    /// - `issuer`: The issuer that was discovered to get this `ProviderMetadata`.
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

    /// JSON array containing a list of the OAuth `response_mode` values
    /// that this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_MODES_SUPPORTED`].
    #[must_use]
    pub fn response_modes_supported(&self) -> &[ResponseMode] {
        self.response_modes_supported
            .as_deref()
            .unwrap_or(DEFAULT_RESPONSE_MODES_SUPPORTED)
    }

    /// JSON array containing a list of the OAuth grant type values that
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

    /// JSON array containing a list of the OAuth `response_type` values
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
