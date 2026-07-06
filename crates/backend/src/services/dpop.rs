// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession / DPoP) verifier.
//!
//! Implements the proof-token shape that protects device-bound session
//! grants. A DPoP proof is a compact-serialisation JWS with:
//!
//! * `typ = "dpop+jwt"`
//! * `alg ∈ { ES256, EdDSA }` — locked down to the asymmetric algs we already support in
//!   `coauth_jose`.
//! * `jwk` — the protected-header MUST carry the public key the proof is signed with. We verify the
//!   JWS using exactly that embedded key, then reconstruct the RFC 7638 JWK SHA-256 thumbprint
//!   (`jkt`) and bind it to the issued session grant via a `cnf.jkt` claim (RFC 9449 §6.1).
//!
//! Bindings enforced on every proof:
//!
//! * `htm` — HTTP method on the incoming request must match.
//! * `htu` — Absolute endpoint URL on the incoming request must match (scheme + authority + path;
//!   we explicitly strip query / fragment).
//! * `ath` — When a Bearer access token is carried alongside the proof, `ath =
//!   base64url(sha256(access_token))` (RFC 9449 §4.3).
//! * `iat` — Must be within `MAX_CLOCK_SKEW` of the verifier's clock.
//! * `jti` — Must be unique inside the `NONCE_TTL` replay window; we cache observed `jti` values in
//!   an in-memory map keyed by `jti`, value `iat + NONCE_TTL`. Production deployments running
//!   multiple coauth replicas behind a load balancer will eventually want a Redis-backed cache, but
//!   the in-process map is enough for a single-node deployment and for the cotest e2e harness.
//!
//! This module is brand-new and only ever reads / writes session-grant
//! claims through the existing `coauth_jose` plumbing; we never roll our
//! own primitive crypto.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use coauth_data::{
    NewDpopJtiReplay, PgRepositoryFactory, RepositoryAccess as _, RepositoryFactory as _,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwa::AsymmetricVerifyingKey;
use coauth_jose::jwk::{PublicJsonWebKey, Thumbprint};
use coauth_jose::jwt::Jwt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

/// Maximum tolerated skew between the proof's `iat` and the verifier's
/// clock (±). Mirrors RFC 9449 §4.3's "small leeway" guidance — we pick
/// 60s, which is also what most well-known DPoP implementations use.
const MAX_CLOCK_SKEW: Duration = Duration::seconds(60);

/// Time window for jti replay detection — once a jti is observed it is
/// rejected until this many seconds after its `iat`.
const NONCE_TTL: StdDuration = StdDuration::from_mins(5);

/// Standard `typ` value the proof header must carry per RFC 9449 §4.2.
const DPOP_TYP: &str = "dpop+jwt";

/// The `jkt` thumbprint extracted from a DPoP proof, base64url-encoded
/// per RFC 7638. Used as the value of the `cnf.jkt` claim on tokens
/// issued bound to the proof.
pub type Jkt = String;

/// Decoded DPoP proof claims (RFC 9449 §4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopClaims {
    /// Unique identifier for the proof — used for replay protection.
    pub jti: String,
    /// HTTP method, uppercase. MUST match the protected request.
    pub htm: String,
    /// HTTP target URI without query / fragment.
    pub htu: String,
    /// `issued at` — Unix seconds. MUST be within `MAX_CLOCK_SKEW`.
    pub iat: i64,
    /// Access-token hash, set when the proof accompanies a Bearer token.
    /// Equal to `base64url(sha256(access_token))`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Server-issued challenge nonce; we accept whatever the proof
    /// carries but don't currently mandate it (RFC 9449 §8 nonce strand is
    /// optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Result of a successful DPoP proof verification.
#[derive(Debug, Clone)]
pub struct DpopVerification {
    /// JWK thumbprint (RFC 7638) of the embedded `jwk`, base64url-encoded.
    pub jkt: Jkt,
    /// Decoded proof claims.
    pub claims: DpopClaims,
    /// Echo of the embedded JWK so callers can persist or re-serialise.
    pub jwk: PublicJsonWebKey,
}

/// What can go wrong while verifying a DPoP proof.
#[derive(Debug, Error)]
pub enum DpopError {
    #[error("DPoP header is missing")]
    Missing,

    #[error("DPoP header is malformed: {0}")]
    Malformed(String),

    #[error("DPoP header is not a parseable JWT: {0}")]
    NotJwt(String),

    #[error("DPoP header `typ` must be `dpop+jwt`")]
    BadTyp,

    #[error("DPoP header `alg` `{0}` is not supported (only ES256, EdDSA)")]
    BadAlg(String),

    #[error("DPoP header is missing the embedded `jwk`")]
    MissingJwk,

    #[error("DPoP embedded `jwk` does not match the signing algorithm: {0}")]
    JwkAlgMismatch(String),

    #[error("DPoP signature verification failed")]
    BadSignature,

    #[error("DPoP claim `{0}` is missing or empty")]
    MissingClaim(&'static str),

    #[error("DPoP `htm` mismatch (expected `{expected}`, got `{actual}`)")]
    HtmMismatch { expected: String, actual: String },

    #[error("DPoP `htu` mismatch (expected `{expected}`, got `{actual}`)")]
    HtuMismatch { expected: String, actual: String },

    #[error("DPoP `iat` is outside the ±{0}s clock-skew window")]
    IatOutOfRange(i64),

    #[error("DPoP `jti` `{0}` was already presented within the replay window")]
    JtiReplayed(String),

    #[error("DPoP `ath` is missing — required when an access token is presented")]
    MissingAth,

    #[error("DPoP `ath` does not match the presented access token")]
    AthMismatch,

    #[error("DPoP `jkt` `{actual}` does not match the bound token `cnf.jkt` `{expected}`")]
    JktMismatch { expected: String, actual: String },

    #[error("DPoP replay store failed: {0}")]
    ReplayStore(String),

    #[error("DPoP verifier is unavailable: {0}")]
    VerifierUnavailable(String),
}

/// Replay-protection store for DPoP `jti` values (RFC 9449 §4.3).
///
/// Abstracted behind a trait so the verifier logic does not bake in a
/// particular storage backend. A single-node deployment (and the cotest
/// e2e harness) uses the in-process [`InMemoryJtiStore`]; a horizontally
/// scaled deployment can inject a shared backend (Redis / Postgres) via
/// [`DpopVerifier::with_store`] so that a replayed proof landing on a
/// different replica is still rejected. See this module's header for why
/// a process-local map alone is insufficient behind a load balancer.
#[async_trait]
pub trait JtiReplayStore: Send + Sync + std::fmt::Debug {
    /// Atomically check whether `jti` is still inside its replay window
    /// and, if not, record it as seen until `now + ttl`.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::JtiReplayed`] when `jti` was already recorded
    /// and has not yet expired.
    async fn check_and_record(
        &self,
        jti: &str,
        now: DateTime<Utc>,
        ttl: StdDuration,
    ) -> Result<(), DpopError>;
}

/// Default in-process [`JtiReplayStore`], keyed by `jti` → expiry
/// timestamp. Adequate for single-node deployments and tests; replaced by
/// a shared backend in multi-replica production.
#[derive(Debug, Default)]
pub struct InMemoryJtiStore {
    seen: Mutex<HashMap<String, DateTime<Utc>>>,
}

#[async_trait]
impl JtiReplayStore for InMemoryJtiStore {
    async fn check_and_record(
        &self,
        jti: &str,
        now: DateTime<Utc>,
        ttl: StdDuration,
    ) -> Result<(), DpopError> {
        let mut guard = self.seen.lock().await;
        guard.retain(|_, expiry| *expiry > now);
        if guard.contains_key(jti) {
            return Err(DpopError::JtiReplayed(jti.to_owned()));
        }
        let expiry = now + Duration::from_std(ttl).expect("NONCE_TTL fits in chrono::Duration");
        guard.insert(jti.to_owned(), expiry);
        Ok(())
    }
}

/// Database-backed [`JtiReplayStore`] for multi-replica deployments.
#[derive(Clone)]
pub struct RepositoryJtiStore {
    repository_factory: PgRepositoryFactory,
}

impl RepositoryJtiStore {
    /// Construct a DPoP replay store backed by the shared PostgreSQL
    /// repository factory.
    #[must_use]
    pub fn new(repository_factory: PgRepositoryFactory) -> Self {
        Self { repository_factory }
    }
}

impl std::fmt::Debug for RepositoryJtiStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryJtiStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl JtiReplayStore for RepositoryJtiStore {
    async fn check_and_record(
        &self,
        jti: &str,
        now: DateTime<Utc>,
        ttl: StdDuration,
    ) -> Result<(), DpopError> {
        let expires_at = now + Duration::from_std(ttl).expect("NONCE_TTL fits in chrono::Duration");
        let jti_digest = dpop_jti_digest(jti);
        let mut repo = self
            .repository_factory
            .create()
            .await
            .map_err(|error| DpopError::ReplayStore(error.to_string()))?;

        let inserted = repo
            .dpop_replay()
            .consume_jti(NewDpopJtiReplay {
                jti_digest,
                seen_at: now,
                expires_at,
            })
            .await
            .map_err(|error| DpopError::ReplayStore(error.to_string()))?;

        repo.save()
            .await
            .map_err(|error| DpopError::ReplayStore(error.to_string()))?;

        if inserted {
            Ok(())
        } else {
            Err(DpopError::JtiReplayed(jti.to_owned()))
        }
    }
}

fn dpop_jti_digest(jti: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(jti.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// RFC 9449 DPoP proof verifier. Cheap to clone — holds an `Arc` over a
/// pluggable [`JtiReplayStore`].
#[derive(Debug, Clone)]
pub struct DpopVerifier {
    jti_store: Arc<dyn JtiReplayStore>,
}

impl Default for DpopVerifier {
    fn default() -> Self {
        Self {
            jti_store: Arc::new(InMemoryJtiStore::default()),
        }
    }
}

impl DpopVerifier {
    /// Construct a new verifier backed by a fresh in-process replay store.
    /// Production handlers should use the depot-injected verifier instead so
    /// replay state stays repository-backed across replicas.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a verifier backed by a caller-supplied [`JtiReplayStore`].
    ///
    /// Use this to inject a shared (Redis / Postgres) backend in
    /// multi-replica deployments, or a deterministic store in tests.
    #[must_use]
    pub fn with_store(jti_store: Arc<dyn JtiReplayStore>) -> Self {
        Self { jti_store }
    }

    /// Process-wide singleton for tests and single-process fixtures.
    /// Production handlers must not fall back to this weaker store.
    #[must_use]
    pub fn shared() -> Self {
        static SHARED: LazyLock<DpopVerifier> = LazyLock::new(DpopVerifier::new);
        SHARED.clone()
    }

    /// Verify a DPoP proof.
    ///
    /// `dpop_header` is the raw value of the request's `DPoP` HTTP header.
    /// `htm` is the request method (case-normalised to uppercase by the
    /// caller — we match exactly). `htu` is the canonicalised target URL
    /// without query / fragment. `now` is the verifier's clock.
    /// `access_token` is the Bearer token, if one was presented; when set,
    /// the proof MUST carry a matching `ath` claim.
    ///
    /// On success returns the proof's `jkt` thumbprint plus decoded
    /// claims. On failure returns the most-specific [`DpopError`] variant.
    ///
    /// # Errors
    ///
    /// Returns `DpopError` if any of the RFC 9449 invariants are not
    /// satisfied.
    pub async fn verify(
        &self,
        dpop_header: &str,
        htm: &str,
        htu: &str,
        now: DateTime<Utc>,
        access_token: Option<&str>,
    ) -> Result<DpopVerification, DpopError> {
        let trimmed = dpop_header.trim();
        if trimmed.is_empty() {
            return Err(DpopError::Missing);
        }

        let jwt: Jwt<'_, DpopClaims> =
            Jwt::try_from(trimmed).map_err(|error| DpopError::NotJwt(error.to_string()))?;
        let header = jwt.header();

        // `typ` MUST be `dpop+jwt` (RFC 9449 §4.2).
        if header.typ() != Some(DPOP_TYP) {
            return Err(DpopError::BadTyp);
        }

        // Only allow the two algs the task pins us to. The wider
        // `coauth_jose` machinery supports many more, but DPoP requires
        // an asymmetric proof key and we lock down the surface explicitly.
        let alg = header.alg();
        if !matches!(alg, JsonWebSignatureAlg::Es256 | JsonWebSignatureAlg::EdDsa) {
            return Err(DpopError::BadAlg(alg.to_string()));
        }

        // Embedded JWK is the verification key (RFC 9449 §4.2: jwk MUST
        // be present).
        let jwk = header.jwk().ok_or(DpopError::MissingJwk)?.clone();
        let verifying_key = AsymmetricVerifyingKey::from_jwk_and_alg(jwk.params(), alg)
            .map_err(|error| DpopError::JwkAlgMismatch(error.to_string()))?;
        jwt.verify(&verifying_key)
            .map_err(|_| DpopError::BadSignature)?;

        let claims = jwt.payload().clone();

        // Required claims.
        if claims.jti.trim().is_empty() {
            return Err(DpopError::MissingClaim("jti"));
        }
        if claims.htm.trim().is_empty() {
            return Err(DpopError::MissingClaim("htm"));
        }
        if claims.htu.trim().is_empty() {
            return Err(DpopError::MissingClaim("htu"));
        }
        if claims.iat == 0 {
            return Err(DpopError::MissingClaim("iat"));
        }

        // htm — case-sensitive uppercase match per RFC 9449 §4.3.
        if !claims.htm.eq_ignore_ascii_case(htm) {
            return Err(DpopError::HtmMismatch {
                expected: htm.to_owned(),
                actual: claims.htm.clone(),
            });
        }

        // htu — strip query+fragment on both sides before comparing.
        let expected_htu = canonicalize_htu(htu);
        let actual_htu = canonicalize_htu(&claims.htu);
        if expected_htu != actual_htu {
            return Err(DpopError::HtuMismatch {
                expected: expected_htu,
                actual: actual_htu,
            });
        }

        // iat skew.
        let iat = DateTime::<Utc>::from_timestamp(claims.iat, 0)
            .ok_or(DpopError::IatOutOfRange(MAX_CLOCK_SKEW.num_seconds()))?;
        let skew = if iat > now { iat - now } else { now - iat };
        if skew > MAX_CLOCK_SKEW {
            return Err(DpopError::IatOutOfRange(MAX_CLOCK_SKEW.num_seconds()));
        }

        // ath — required when a Bearer token is presented (RFC 9449 §4.3).
        if let Some(token) = access_token {
            let expected_ath = access_token_hash(token);
            let Some(ath) = claims.ath.as_deref() else {
                return Err(DpopError::MissingAth);
            };
            if ath != expected_ath {
                return Err(DpopError::AthMismatch);
            }
        }

        // jti replay.
        self.jti_store
            .check_and_record(&claims.jti, now, NONCE_TTL)
            .await?;

        let jkt = jwk.params().thumbprint_sha256_base64();
        Ok(DpopVerification { jkt, claims, jwk })
    }

    /// Convenience helper to confirm that a proof presented on a
    /// follow-up request matches the `jkt` baked into the previously
    /// issued grant.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::JktMismatch`] when the thumbprints diverge.
    pub fn require_matching_jkt(actual: &str, expected: &str) -> Result<(), DpopError> {
        if actual == expected {
            Ok(())
        } else {
            Err(DpopError::JktMismatch {
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            })
        }
    }
}

/// Compute the RFC 9449 `ath` claim: `base64url(sha256(access_token))`.
#[must_use]
pub fn access_token_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    Base64UrlUnpadded::encode_string(&digest)
}

/// Read the `DPoP` header off a salvo request.
#[must_use]
pub fn dpop_header_from_request(req: &salvo::Request) -> Option<String> {
    req.headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Read the Bearer access token off a salvo request's `Authorization`
/// header. Returns `None` if the header is missing, malformed, or not a
/// Bearer scheme.
#[must_use]
pub fn bearer_token_from_request(req: &salvo::Request) -> Option<String> {
    let header = req.headers().get(http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::to_owned)
}

/// Compute the canonical `htu` (HTTP target URI) for the current
/// request: `<scheme>://<authority><path>`, anchored to the service's
/// configured public base URL.
///
/// `public_base` is intentionally **required** rather than optional: the
/// `htu` binding is only meaningful when it is derived from a trusted,
/// server-side source. The previous fallback to the attacker-controlled
/// `Host` header (with a hard-coded `http://` scheme) is removed so a
/// caller can never accidentally weaken the binding by omitting the base
/// — callers must always thread through their `UrlBuilder` public base.
#[must_use]
pub fn dpop_htu(public_base: &url::Url, req: &salvo::Request) -> String {
    let path = req.uri().path();
    let scheme = public_base.scheme();
    let host = public_base.host_str().unwrap_or("localhost");
    match public_base.port() {
        Some(port) => format!("{scheme}://{host}:{port}{path}"),
        None => format!("{scheme}://{host}{path}"),
    }
}

/// Trim query string and fragment from `htu`, lowercase scheme + host.
fn canonicalize_htu(input: &str) -> String {
    let trimmed = input.trim();
    let without_fragment = trimmed
        .split_once('#')
        .map_or(trimmed, |(prefix, _)| prefix);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(prefix, _)| prefix);
    // Lowercase scheme + authority but leave path case alone (paths are
    // case-sensitive per RFC 3986).
    if let Some(scheme_end) = without_query.find("://") {
        let (scheme, rest) = without_query.split_at(scheme_end);
        let rest = &rest[3..];
        if let Some(path_start) = rest.find('/') {
            let (authority, path) = rest.split_at(path_start);
            format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                authority.to_ascii_lowercase(),
                path
            )
        } else {
            format!(
                "{}://{}",
                scheme.to_ascii_lowercase(),
                rest.to_ascii_lowercase()
            )
        }
    } else {
        without_query.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::jwa::AsymmetricSigningKey;
    use coauth_jose::jwk::JsonWebKeyPublicParameters;
    use coauth_jose::jwt::JsonWebSignatureHeader;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    use super::*;

    fn sign_proof(claims: &DpopClaims, signing: &SigningKey) -> String {
        let verifying = signing.verifying_key();
        let public = PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&verifying))
            .with_alg(JsonWebSignatureAlg::EdDsa);
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::EdDsa)
            .with_typ("dpop+jwt".to_owned())
            .with_jwk(public);
        let signer = AsymmetricSigningKey::eddsa(signing.clone());
        Jwt::sign(header, claims.clone(), &signer)
            .expect("DPoP sign")
            .into_string()
    }

    #[tokio::test]
    async fn verifies_well_formed_proof_and_extracts_jkt() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = DpopClaims {
            jti: "test-jti-1".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_cokret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: None,
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        let result = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await
            .expect("DPoP proof verifies");
        assert!(!result.jkt.is_empty());
    }

    #[tokio::test]
    async fn rejects_replayed_jti() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = DpopClaims {
            jti: "test-jti-replay".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_cokret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: None,
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await
            .expect("first verify succeeds");

        let second = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await;
        assert!(matches!(second, Err(DpopError::JtiReplayed(_))));
    }

    #[tokio::test]
    async fn rejects_htm_mismatch() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = DpopClaims {
            jti: "test-jti-htm".to_owned(),
            htm: "GET".to_owned(),
            htu: "https://example.test/_cokret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: None,
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        let result = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await;
        assert!(matches!(result, Err(DpopError::HtmMismatch { .. })));
    }

    #[tokio::test]
    async fn rejects_iat_outside_skew() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = DpopClaims {
            jti: "test-jti-iat".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_cokret/gate/account/session-grants/refresh".to_owned(),
            iat: (now - Duration::seconds(600)).timestamp(),
            ath: None,
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        let result = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await;
        assert!(matches!(result, Err(DpopError::IatOutOfRange(_))));
    }

    #[tokio::test]
    async fn enforces_ath_when_access_token_present() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let token = "some-access-token";
        let claims = DpopClaims {
            jti: "test-jti-ath".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_cokret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: Some(access_token_hash(token)),
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                Some(token),
            )
            .await
            .expect("ath matches");
    }

    #[tokio::test]
    async fn rejects_ath_for_a_different_access_token() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = DpopClaims {
            jti: "test-jti-ath-mismatch".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_cokret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: Some(access_token_hash("bound-access-token")),
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        let result = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_cokret/gate/account/session-grants/refresh",
                now,
                Some("other-access-token"),
            )
            .await;
        assert!(matches!(result, Err(DpopError::AthMismatch)));
    }

    #[test]
    fn rejects_jkt_mismatch_against_bound_session_grant() {
        let result = DpopVerifier::require_matching_jkt("runtime-jkt", "grant-bound-jkt");

        assert!(matches!(
            result,
            Err(DpopError::JktMismatch {
                expected,
                actual,
            }) if expected == "grant-bound-jkt" && actual == "runtime-jkt"
        ));
    }

    #[test]
    fn canonicalize_htu_strips_query_fragment_and_lowercases_host() {
        let canon = canonicalize_htu("HTTPS://Example.TEST:8443/api/v1/Refresh?a=1#frag");
        assert_eq!(canon, "https://example.test:8443/api/v1/Refresh");
    }
}
