// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! OpenID Connect Discovery 1.0 and RFC 8414 types.
//!
//! This module provides Rust types for working with OpenID Connect provider
//! metadata as defined in OpenID Connect Discovery 1.0 Section 3 and
//! OAuth Authorization Server Metadata (RFC 8414).

mod enums;
mod error;
mod logout;
mod provider_metadata;
mod verification;

pub use self::enums::{
    AccountManagementAction, ApplicationType, AuthenticationMethodOrAccessTokenType, ClaimType,
    DEFAULT_AUTH_METHODS_SUPPORTED, DEFAULT_CLAIM_TYPES_SUPPORTED, DEFAULT_GRANT_TYPES_SUPPORTED,
    DEFAULT_RESPONSE_MODES_SUPPORTED, SubjectType,
};
pub use self::error::ProviderMetadataVerificationError;
pub use self::logout::RpInitiatedLogoutRequest;
pub use self::provider_metadata::ProviderMetadata;
pub use self::verification::VerifiedProviderMetadata;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_iana::oauth::{
        OAuthAccessTokenType, OAuthAuthorizationEndpointResponseType,
        OAuthClientAuthenticationMethod,
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
