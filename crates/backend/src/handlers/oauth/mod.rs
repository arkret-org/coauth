// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

//! OAuth and OpenID Connect protocol endpoint handlers.
//!
//! This module implements the server-side of the OAuth / OIDC strands:
//!
//! - [`authorization`] — Authorization endpoint (authorization code grant)
//! - [`token`] — Token endpoint (exchange codes / credentials for tokens)
//! - [`registration`] — Dynamic client registration (RFC 7591)
//! - [`discovery`] — OpenID Connect Discovery (`/.well-known/openid-configuration`)
//! - [`keys`] — JSON Web Key Set (`/.well-known/jwks.json`)
//! - [`userinfo`] — UserInfo endpoint (returns claims about the authenticated user)
//! - [`introspection`] — Token introspection (RFC 7662)
//! - [`revoke`] — Token revocation (RFC 7009)
//! - [`device`] — Device authorization grant (RFC 8628)
//! - [`webfinger`] — WebFinger discovery

use std::collections::HashMap;

use chrono::Duration;
use coauth_data::{
    AccessToken, Authentication, AuthorizationGrant, BrowserSession, Client, Clock, RefreshToken,
    RepositoryAccess, Session, TokenType, UrlBuilder,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::claims::{self, hash_token};
use coauth_jose::constraints::Constrainable;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;
use thiserror::Error;

use crate::handlers::cokret;

/// Authorization endpoint (user consent and code issuance).
pub mod authorization;
/// Device authorization grant (RFC 8628).
pub mod device;
/// OpenID Connect Discovery metadata.
pub mod discovery;
/// Token introspection (RFC 7662).
pub mod introspection;
/// JWK Set endpoint.
pub mod keys;
/// Dynamic client registration (RFC 7591).
pub mod registration;
/// Token revocation (RFC 7009).
pub mod revoke;
/// Token endpoint (code exchange, client credentials, refresh).
pub mod token;
/// UserInfo endpoint.
pub mod userinfo;
/// `WebFinger` discovery.
pub mod webfinger;

#[derive(Debug, Error)]
#[error(transparent)]
pub(crate) enum IdTokenSignatureError {
    #[error("The signing key is invalid")]
    InvalidSigningKey,
    Claim(#[from] coauth_jose::claims::ClaimError),
    JwtSignature(#[from] coauth_jose::jwt::JwtSignatureError),
    WrongAlgorithm(#[from] coauth_keystore::WrongAlgorithmError),
    TokenHash(#[from] coauth_jose::claims::TokenHashError),
}

/// Generate a signed OpenID Connect ID Token for the given session.
///
/// The token includes standard claims (`iss`, `sub`, `aud`, `iat`, `exp`)
/// and optional claims (`nonce`, `auth_time`, `at_hash`, `c_hash`) depending
/// on the grant context.
pub(crate) fn generate_id_token(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    clock: &impl Clock,
    url_builder: &UrlBuilder,
    subject_did: &str,
    principal_did: Option<&str>,
    key_store: &Keystore,
    client: &Client,
    grant: Option<&AuthorizationGrant>,
    session: Option<&Session>,
    _browser_session: &BrowserSession,
    access_token: Option<&AccessToken>,
    last_authentication: Option<&Authentication>,
) -> Result<String, IdTokenSignatureError> {
    let mut claims = HashMap::new();
    let now = clock.now();
    claims::ISS.insert(&mut claims, url_builder.oidc_issuer().to_string())?;
    claims::SUB.insert(&mut claims, subject_did.to_owned())?;
    if let Some(principal_did) = principal_did {
        claims.insert(
            cokret::CLAIM_PRINCIPAL_DID.to_owned(),
            serde_json::Value::String(principal_did.to_owned()),
        );
    }
    claims::AUD.insert(&mut claims, client.client_id.clone())?;
    claims::IAT.insert(&mut claims, now)?;
    claims::EXP.insert(&mut claims, now + Duration::try_hours(1).unwrap())?;

    if let Some(session) = session {
        claims.insert(
            cokret::CLAIM_SESSION_ID.to_owned(),
            serde_json::Value::String(session.id.to_string()),
        );

        if let Some(device_id) = cokret::primary_device_id(&session.scope) {
            claims.insert(
                cokret::CLAIM_DEVICE_ID.to_owned(),
                serde_json::Value::String(device_id),
            );
        }
    }

    if let Some(nonce) = grant.and_then(|grant| grant.nonce.as_ref()) {
        claims::NONCE.insert(&mut claims, nonce)?;
    }

    if let Some(last_authentication) = last_authentication {
        claims::AUTH_TIME.insert(&mut claims, last_authentication.created_at)?;
    }

    let alg = client
        .id_token_signed_response_alg
        .clone()
        .unwrap_or(JsonWebSignatureAlg::Rs256);
    let key = key_store
        .signing_key_for_algorithm(&alg)
        .ok_or(IdTokenSignatureError::InvalidSigningKey)?;

    if let Some(access_token) = access_token {
        claims::AT_HASH.insert(&mut claims, hash_token(&alg, &access_token.access_token)?)?;
    }

    if let Some(code) = grant.and_then(|grant| grant.code.as_ref()) {
        claims::C_HASH.insert(&mut claims, hash_token(&alg, &code.code)?)?;
    }

    let signer = key_store.signer_for_algorithm(&alg)?;
    let header = JsonWebSignatureHeader::new(alg)
        .with_kid(key.kid().ok_or(IdTokenSignatureError::InvalidSigningKey)?);
    let id_token = Jwt::sign_with_rng(rng, header, claims, &*signer)?;

    Ok(id_token.into_string())
}

/// Generate a new access-token / refresh-token pair for an OAuth session
/// and persist them in the repository.
pub(crate) async fn generate_token_pair<R: RepositoryAccess>(
    rng: &mut (impl rand_core::RngCore + Send),
    clock: &impl Clock,
    repo: &mut R,
    session: &Session,
    ttl: Duration,
) -> Result<(AccessToken, RefreshToken), R::Error> {
    let access_token_str = TokenType::AccessToken.generate(rng);
    let refresh_token_str = TokenType::RefreshToken.generate(rng);

    let access_token = repo
        .oauth_access_token()
        .add(rng, clock, session, access_token_str, Some(ttl))
        .await?;

    let refresh_token = repo
        .oauth_refresh_token()
        .add(rng, clock, session, &access_token, refresh_token_str)
        .await?;

    Ok((access_token, refresh_token))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Duration;
    use coauth_data::clock::MockClock;
    use coauth_data::{AccessTokenState, AuthenticationMethod};
    use coauth_jose::claims::hash_token;
    use coauth_jose::jwt::Jwt;
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use serde_json::Value;
    use ulid::Ulid;

    use super::*;

    fn keystore_for_alg(alg: &JsonWebSignatureAlg) -> (Keystore, &'static str) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let (private_key, kid) = match alg {
            JsonWebSignatureAlg::Es512 => (PrivateKey::generate_ec_p521(&mut rng), "test-es512"),
            JsonWebSignatureAlg::EdDsa => (PrivateKey::generate_ed25519(&mut rng), "test-eddsa"),
            other => panic!("unsupported test algorithm: {other:?}"),
        };

        let key = JsonWebKey::new(private_key).with_kid(kid);
        (Keystore::new(JsonWebKeySet::new(vec![key])), kid)
    }

    fn assert_generated_id_token_works(alg: JsonWebSignatureAlg) {
        let clock = MockClock::default();
        let now = clock.now();
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let principal_did =
            "did:webvh:zQmTestPrincipal:example.com:webvh:01964137000070008000000000000000";
        let mut fixture_rng = ChaChaRng::seed_from_u64(7);

        let mut client = Client::samples(now, &mut fixture_rng)
            .into_iter()
            .next()
            .unwrap();
        client.id_token_signed_response_alg = Some(alg.clone());

        let grant = AuthorizationGrant::sample(now, &mut fixture_rng);
        let browser_session = BrowserSession::samples(now, &mut fixture_rng)
            .into_iter()
            .next()
            .unwrap();
        let access_token = AccessToken {
            id: Ulid::new(),
            state: AccessTokenState::Valid,
            session_id: Ulid::new(),
            access_token: "access-token-value".to_owned(),
            created_at: now,
            expires_at: Some(now + Duration::try_minutes(5).unwrap()),
            first_used_at: None,
        };
        let authentication = Authentication {
            id: Ulid::new(),
            created_at: now - Duration::try_minutes(2).unwrap(),
            authentication_method: AuthenticationMethod::Unknown,
        };
        let (key_store, kid) = keystore_for_alg(&alg);
        let mut signing_rng = ChaChaRng::seed_from_u64(9);

        let encoded = generate_id_token(
            &mut signing_rng,
            &clock,
            &url_builder,
            principal_did,
            Some(principal_did),
            &key_store,
            &client,
            Some(&grant),
            None,
            &browser_session,
            Some(&access_token),
            Some(&authentication),
        )
        .unwrap();

        let jwt = Jwt::<HashMap<String, Value>>::try_from(encoded.as_str()).unwrap();

        assert_eq!(jwt.header().alg(), &alg);
        assert_eq!(jwt.header().kid(), Some(kid));
        jwt.verify_with_jwks(&key_store.public_jwks()).unwrap();

        let payload = jwt.payload();
        assert_eq!(
            payload.get("iss").and_then(Value::as_str),
            Some(url_builder.oidc_issuer().as_str())
        );
        assert_eq!(
            payload.get("sub").and_then(Value::as_str),
            Some(principal_did)
        );
        assert_eq!(
            payload
                .get(cokret::CLAIM_PRINCIPAL_DID)
                .and_then(Value::as_str),
            Some(principal_did)
        );
        assert_eq!(
            payload.get("aud").and_then(Value::as_str),
            Some(client.client_id.as_str())
        );
        assert_eq!(
            payload.get("nonce").and_then(Value::as_str),
            grant.nonce.as_deref()
        );
        assert_eq!(
            payload.get("auth_time").and_then(Value::as_i64),
            Some(authentication.created_at.timestamp())
        );

        let expected_at_hash = hash_token(&alg, &access_token.access_token).unwrap();
        assert_eq!(
            payload.get("at_hash").and_then(Value::as_str),
            Some(expected_at_hash.as_str())
        );

        let code = &grant.code.as_ref().unwrap().code;
        let expected_c_hash = hash_token(&alg, code).unwrap();
        assert_eq!(
            payload.get("c_hash").and_then(Value::as_str),
            Some(expected_c_hash.as_str())
        );
    }

    #[test]
    fn generate_id_token_omits_principal_did_claim_when_not_published() {
        let clock = MockClock::default();
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let subject = "did:web:example.com:users:01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let mut rng = ChaChaRng::seed_from_u64(11);
        let mut fixture_rng = ChaChaRng::seed_from_u64(12);
        let mut client = Client::samples(clock.now(), &mut fixture_rng)
            .into_iter()
            .next()
            .unwrap();
        client.id_token_signed_response_alg = Some(JsonWebSignatureAlg::EdDsa);
        let browser_session = BrowserSession::samples(clock.now(), &mut fixture_rng)
            .into_iter()
            .next()
            .unwrap();
        let (key_store, _) = keystore_for_alg(&JsonWebSignatureAlg::EdDsa);

        let encoded = generate_id_token(
            &mut rng,
            &clock,
            &url_builder,
            subject,
            None,
            &key_store,
            &client,
            None,
            None,
            &browser_session,
            None,
            None,
        )
        .unwrap();

        let jwt = Jwt::<HashMap<String, Value>>::try_from(encoded.as_str()).unwrap();
        assert_eq!(jwt.payload().get("sub").and_then(Value::as_str), Some(subject));
        assert!(
            !jwt.payload()
                .contains_key(cokret::CLAIM_PRINCIPAL_DID)
        );
    }

    #[test]
    fn generate_id_token_supports_es512() {
        assert_generated_id_token_works(JsonWebSignatureAlg::Es512);
    }

    #[test]
    fn generate_id_token_supports_eddsa() {
        assert_generated_id_token_works(JsonWebSignatureAlg::EdDsa);
    }
}

pub(crate) mod access;
pub(crate) mod introspection_service;
pub(crate) mod revocation_service;
pub(crate) mod token_service;
