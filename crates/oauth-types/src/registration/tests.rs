use assert_matches::assert_matches;
use coauth_iana::jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg};
use coauth_iana::oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod};
use coauth_jose::jwk::PublicJsonWebKeySet;
use url::Url;

use super::{ClientMetadata, ClientMetadataVerificationError};
use crate::requests::GrantType;
use crate::response_type::ResponseType;

fn valid_client_metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: Some(vec![Url::parse("http://localhost/oidc").unwrap()]),
        ..Default::default()
    }
}

fn jwks() -> PublicJsonWebKeySet {
    serde_json::from_value(serde_json::json!({
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "n": "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ",
                "use": "sig",
                "kid": "d98f49bc6ca4581eae8dfadd494fce10ea23aab0",
                "e": "AQAB"
            }
        ]
    })).unwrap()
}

// -- Redirect URI validation ------------------------------------------------

#[test]
fn validate_required_metadata() {
    valid_client_metadata().validate().unwrap();
}

#[test]
fn validate_redirect_uris() {
    let mut metadata = ClientMetadata::default();

    assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::MissingRedirectUris)
    );

    let wrong_uri = Url::parse("http://localhost/#fragment").unwrap();
    metadata.redirect_uris = Some(vec![
        Url::parse("http://localhost/").unwrap(),
        wrong_uri.clone(),
    ]);
    let uri = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::RedirectUriWithFragment(uri)) => uri
    );
    assert_eq!(uri, wrong_uri);

    metadata.redirect_uris = Some(vec![
        Url::parse("http://localhost/").unwrap(),
        Url::parse("http://localhost/oidc").unwrap(),
        Url::parse("http://localhost/?oidc").unwrap(),
        Url::parse("http://localhost/my-client?oidc").unwrap(),
    ]);
    metadata.validate().unwrap();
}

// -- Response type / grant type coherence -----------------------------------

fn expect_incoherent(metadata: ClientMetadata) -> ResponseType {
    assert_matches!(
        metadata.validate(),
        Err(ClientMetadataVerificationError::IncoherentResponseType(rt)) => rt
    )
}

#[test]
fn validate_response_types_authorization_code_only() {
    let base = valid_client_metadata();

    // code is compatible with authorization_code
    let mut m = base.clone();
    m.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::Code.into()]);
    m.validate().unwrap();

    // hybrid types require implicit grant type too
    for rt in [
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
        OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
        OAuthAuthorizationEndpointResponseType::CodeToken,
        OAuthAuthorizationEndpointResponseType::IdToken,
        OAuthAuthorizationEndpointResponseType::IdTokenToken,
    ] {
        let mut m = base.clone();
        let expected: ResponseType = rt.into();
        m.response_types = Some(vec![expected.clone()]);
        assert_eq!(expect_incoherent(m), expected);
    }

    // none is always ok
    let mut m = base.clone();
    m.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::None.into()]);
    m.validate().unwrap();
}

#[test]
fn validate_response_types_implicit_only() {
    let mut base = valid_client_metadata();
    base.grant_types = Some(vec![GrantType::Implicit]);

    // code requires authorization_code grant
    let mut m = base.clone();
    let expected: ResponseType = OAuthAuthorizationEndpointResponseType::Code.into();
    m.response_types = Some(vec![expected.clone()]);
    assert_eq!(expect_incoherent(m), expected);

    // hybrid types that include code are incompatible
    for rt in [
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
        OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
        OAuthAuthorizationEndpointResponseType::CodeToken,
    ] {
        let mut m = base.clone();
        let expected: ResponseType = rt.into();
        m.response_types = Some(vec![expected.clone()]);
        assert_eq!(expect_incoherent(m), expected);
    }

    // implicit-only types are ok
    for rt in [
        OAuthAuthorizationEndpointResponseType::IdToken,
        OAuthAuthorizationEndpointResponseType::IdTokenToken,
        OAuthAuthorizationEndpointResponseType::Token,
        OAuthAuthorizationEndpointResponseType::None,
    ] {
        let mut m = base.clone();
        m.response_types = Some(vec![rt.into()]);
        m.validate().unwrap();
    }
}

#[test]
fn validate_response_types_both_grants() {
    let mut base = valid_client_metadata();
    base.grant_types = Some(vec![GrantType::AuthorizationCode, GrantType::Implicit]);

    // all standard response types should be accepted
    for rt in [
        OAuthAuthorizationEndpointResponseType::Code,
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
        OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
        OAuthAuthorizationEndpointResponseType::CodeToken,
        OAuthAuthorizationEndpointResponseType::IdToken,
        OAuthAuthorizationEndpointResponseType::IdTokenToken,
        OAuthAuthorizationEndpointResponseType::Token,
        OAuthAuthorizationEndpointResponseType::None,
    ] {
        let mut m = base.clone();
        m.response_types = Some(vec![rt.into()]);
        m.validate().unwrap();
    }
}

#[test]
fn validate_response_types_no_auth_grants() {
    let mut base = valid_client_metadata();
    base.grant_types = Some(vec![GrantType::RefreshToken, GrantType::ClientCredentials]);

    // code and hybrid types are incompatible without authorization_code/implicit
    for rt in [
        OAuthAuthorizationEndpointResponseType::Code,
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
        OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
        OAuthAuthorizationEndpointResponseType::CodeToken,
        OAuthAuthorizationEndpointResponseType::IdToken,
        OAuthAuthorizationEndpointResponseType::IdTokenToken,
        OAuthAuthorizationEndpointResponseType::Token,
    ] {
        let mut m = base.clone();
        let expected: ResponseType = rt.into();
        m.response_types = Some(vec![expected.clone()]);
        assert_eq!(expect_incoherent(m), expected);
    }

    // none is always ok
    let mut m = base.clone();
    m.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::None.into()]);
    m.validate().unwrap();
}

// -- JWKS -------------------------------------------------------------------

#[test]
fn validate_jwks() {
    let mut metadata = valid_client_metadata();

    metadata.jwks_uri = Some(Url::parse("http://localhost/jwks").unwrap());
    metadata.clone().validate().unwrap();

    metadata.jwks = Some(jwks());
    assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::JwksUriAndJwksMutuallyExclusive)
    );

    metadata.jwks_uri = None;
    metadata.validate().unwrap();
}

// -- URL scheme validation --------------------------------------------------

#[test]
fn validate_sector_identifier_uri() {
    let mut metadata = valid_client_metadata();

    let identifier_uri = Url::parse("http://localhost/").unwrap();
    metadata.sector_identifier_uri = Some(identifier_uri.clone());
    let (field, url) = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
    );
    assert_eq!(field, "sector_identifier_uri");
    assert_eq!(url, identifier_uri);

    metadata.sector_identifier_uri = Some(Url::parse("https://localhost/").unwrap());
    metadata.validate().unwrap();
}

#[test]
fn validate_initiate_login_uri() {
    let mut metadata = valid_client_metadata();

    let initiate_uri = Url::parse("http://localhost/").unwrap();
    metadata.initiate_login_uri = Some(initiate_uri.clone());
    let (field, url) = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
    );
    assert_eq!(field, "initiate_login_uri");
    assert_eq!(url, initiate_uri);

    metadata.initiate_login_uri = Some(Url::parse("https://localhost/").unwrap());
    metadata.validate().unwrap();
}

// -- Token endpoint auth method ---------------------------------------------

#[test]
fn validate_token_endpoint_auth_method() {
    let mut metadata = valid_client_metadata();

    metadata.token_endpoint_auth_signing_alg = Some(JsonWebSignatureAlg::None);
    let field = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::UnauthorizedSigningAlgNone(field)) => field
    );
    assert_eq!(field, "token_endpoint");

    // private_key_jwt requires JWKS
    metadata.token_endpoint_auth_method = Some(OAuthClientAuthenticationMethod::PrivateKeyJwt);
    metadata.token_endpoint_auth_signing_alg = Some(JsonWebSignatureAlg::Rs256);

    assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::MissingJwksForTokenMethod)
    );

    metadata.jwks_uri = Some(Url::parse("https://localhost/jwks").unwrap());
    metadata.clone().validate().unwrap();

    metadata.jwks_uri = None;
    metadata.jwks = Some(jwks());
    metadata.clone().validate().unwrap();

    // Missing signing alg for jwt methods
    metadata.token_endpoint_auth_signing_alg = None;
    let field = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::MissingAuthSigningAlg(field)) => field
    );
    assert_eq!(field, "token_endpoint");

    metadata.token_endpoint_auth_method = Some(OAuthClientAuthenticationMethod::ClientSecretJwt);
    metadata.jwks = None;

    let field = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::MissingAuthSigningAlg(field)) => field
    );
    assert_eq!(field, "token_endpoint");

    metadata.token_endpoint_auth_signing_alg = Some(JsonWebSignatureAlg::Rs256);
    metadata.validate().unwrap();
}

// -- Signing / encryption alg validation ------------------------------------

#[test]
fn validate_id_token_signed_response_alg() {
    let mut metadata = valid_client_metadata();
    metadata.id_token_signed_response_alg = Some(JsonWebSignatureAlg::None);
    metadata.grant_types = Some(vec![GrantType::AuthorizationCode, GrantType::Implicit]);

    for rt in [
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
        OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
        OAuthAuthorizationEndpointResponseType::IdToken,
        OAuthAuthorizationEndpointResponseType::IdTokenToken,
    ] {
        metadata.response_types = Some(vec![rt.into()]);
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::IdTokenSigningAlgNone)
        );
    }

    // Response types without id_token should be fine
    metadata.response_types = Some(vec![
        OAuthAuthorizationEndpointResponseType::Code.into(),
        OAuthAuthorizationEndpointResponseType::CodeToken.into(),
        OAuthAuthorizationEndpointResponseType::Token.into(),
        OAuthAuthorizationEndpointResponseType::None.into(),
    ]);
    metadata.validate().unwrap();
}

/// Helper: validate that a missing encryption alg is detected for the given
/// field when only the enc value is set.
fn assert_missing_encryption_alg(
    set_enc: impl Fn(&mut ClientMetadata),
    set_alg: impl Fn(&mut ClientMetadata),
    expected_field: &str,
) {
    let mut metadata = valid_client_metadata();
    set_enc(&mut metadata);

    let field = assert_matches!(
        metadata.clone().validate(),
        Err(ClientMetadataVerificationError::MissingEncryptionAlg(field)) => field
    );
    assert_eq!(field, expected_field);

    set_alg(&mut metadata);
    metadata.validate().unwrap();
}

#[test]
fn validate_id_token_encrypted_response() {
    assert_missing_encryption_alg(
        |m| m.id_token_encrypted_response_enc = Some(JsonWebEncryptionEnc::A128CbcHs256),
        |m| m.id_token_encrypted_response_alg = Some(JsonWebEncryptionAlg::RsaOaep),
        "id_token",
    );
}

#[test]
fn validate_userinfo_encrypted_response() {
    assert_missing_encryption_alg(
        |m| m.userinfo_encrypted_response_enc = Some(JsonWebEncryptionEnc::A128CbcHs256),
        |m| m.userinfo_encrypted_response_alg = Some(JsonWebEncryptionAlg::RsaOaep),
        "userinfo",
    );
}

#[test]
fn validate_request_object_encryption() {
    assert_missing_encryption_alg(
        |m| m.request_object_encryption_enc = Some(JsonWebEncryptionEnc::A128CbcHs256),
        |m| m.request_object_encryption_alg = Some(JsonWebEncryptionAlg::RsaOaep),
        "request_object",
    );
}

#[test]
fn validate_introspection_encrypted_response() {
    assert_missing_encryption_alg(
        |m| m.introspection_encrypted_response_enc = Some(JsonWebEncryptionEnc::A128CbcHs256),
        |m| m.introspection_encrypted_response_alg = Some(JsonWebEncryptionAlg::RsaOaep),
        "introspection",
    );
}
