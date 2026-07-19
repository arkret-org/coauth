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

use arkret_signatures::dpop::{DpopVerificationError, DpopVerificationRequest, verify_dpop_proof};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::{NewDpopJtiReplay, RepositoryAccess as _, RepositoryFactory as _};
use coauth_jose::jwk::PublicJsonWebKey;
use coauth_storage_postgres::PgRepositoryFactory;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

/// Accepted proof freshness and future-clock leeway.
const MAX_PROOF_AGE: Duration = Duration::seconds(300);
const MAX_FUTURE_SKEW: Duration = Duration::seconds(30);

/// Time window for jti replay detection — once a jti is observed it is
/// rejected until this many seconds after its `iat`.
const NONCE_TTL: StdDuration = StdDuration::from_mins(5);
const MAX_IN_MEMORY_JTIS: usize = 100_000;

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
    /// `issued at` — Unix seconds. MUST be inside the accepted freshness window.
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

    #[error("DPoP header `alg` `{0}` is not supported (only EdDSA)")]
    BadAlg(String),

    #[error("DPoP header is missing the embedded `jwk`")]
    MissingJwk,

    #[error("DPoP signature verification failed")]
    BadSignature,

    #[error("DPoP claim `{0}` is missing or empty")]
    MissingClaim(&'static str),

    #[error("DPoP `htm` does not match the request method")]
    HtmMismatch,

    #[error("DPoP `htu` does not match the request URI")]
    HtuMismatch,

    #[error("DPoP `iat` is outside the accepted freshness window")]
    IatOutOfRange,

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
#[derive(Debug)]
pub struct InMemoryJtiStore {
    seen: Mutex<HashMap<String, DateTime<Utc>>>,
    max_entries: usize,
}

impl Default for InMemoryJtiStore {
    fn default() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            max_entries: MAX_IN_MEMORY_JTIS,
        }
    }
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
        if guard.len() >= self.max_entries {
            return Err(DpopError::ReplayStore(
                "in-memory DPoP replay store capacity exhausted".to_owned(),
            ));
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

        let verified = verify_dpop_proof(&DpopVerificationRequest {
            proof_jwt: trimmed,
            method: htm,
            htu,
            access_token,
            now,
            max_age: MAX_PROOF_AGE,
            max_future_skew: MAX_FUTURE_SKEW,
        })
        .map_err(map_verification_error)?;
        let claims = DpopClaims {
            jti: verified.claims.jti,
            htm: verified.claims.htm,
            htu: verified.claims.htu,
            iat: verified.claims.iat,
            ath: verified.claims.ath,
            nonce: verified.claims.nonce,
        };
        let jkt = verified.jkt;
        let jwk = serde_json::from_value(
            serde_json::to_value(verified.public_jwk)
                .map_err(|error| DpopError::Malformed(error.to_string()))?,
        )
        .map_err(|error| DpopError::Malformed(error.to_string()))?;

        self.jti_store
            .check_and_record(&claims.jti, now, NONCE_TTL)
            .await?;

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

fn map_verification_error(error: DpopVerificationError) -> DpopError {
    match error {
        DpopVerificationError::Malformed | DpopVerificationError::InvalidJson => {
            DpopError::NotJwt(error.to_string())
        }
        DpopVerificationError::InvalidType => DpopError::BadTyp,
        DpopVerificationError::InvalidAlgorithm => DpopError::BadAlg("not EdDSA".to_owned()),
        DpopVerificationError::InvalidJwk => DpopError::MissingJwk,
        DpopVerificationError::InvalidSignature => DpopError::BadSignature,
        DpopVerificationError::MissingClaim(claim) => DpopError::MissingClaim(claim),
        DpopVerificationError::MethodMismatch => DpopError::HtmMismatch,
        DpopVerificationError::InvalidTargetUri | DpopVerificationError::TargetUriMismatch => {
            DpopError::HtuMismatch
        }
        DpopVerificationError::IssuedAtOutOfRange => DpopError::IatOutOfRange,
        DpopVerificationError::MissingAccessTokenHash => DpopError::MissingAth,
        DpopVerificationError::AccessTokenHashMismatch => DpopError::AthMismatch,
    }
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
#[cfg(test)]
mod tests {
    use arkret_signatures::dpop_access_token_hash;
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::jwa::AsymmetricSigningKey;
    use coauth_jose::jwk::JsonWebKeyPublicParameters;
    use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
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
            htu: "https://example.test/_arkret/gate/account/session-grants/refresh".to_owned(),
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
                "https://example.test/_arkret/gate/account/session-grants/refresh",
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
            htu: "https://example.test/_arkret/gate/account/session-grants/refresh".to_owned(),
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
                "https://example.test/_arkret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await
            .expect("first verify succeeds");

        let second = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_arkret/gate/account/session-grants/refresh",
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
            htu: "https://example.test/_arkret/gate/account/session-grants/refresh".to_owned(),
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
                "https://example.test/_arkret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await;
        assert!(matches!(result, Err(DpopError::HtmMismatch)));
    }

    #[tokio::test]
    async fn rejects_iat_outside_skew() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = DpopClaims {
            jti: "test-jti-iat".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_arkret/gate/account/session-grants/refresh".to_owned(),
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
                "https://example.test/_arkret/gate/account/session-grants/refresh",
                now,
                None,
            )
            .await;
        assert!(matches!(result, Err(DpopError::IatOutOfRange)));
    }

    #[tokio::test]
    async fn enforces_ath_when_access_token_present() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let token = "some-access-token";
        let claims = DpopClaims {
            jti: "test-jti-ath".to_owned(),
            htm: "POST".to_owned(),
            htu: "https://example.test/_arkret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: Some(dpop_access_token_hash(token)),
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_arkret/gate/account/session-grants/refresh",
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
            htu: "https://example.test/_arkret/gate/account/session-grants/refresh".to_owned(),
            iat: now.timestamp(),
            ath: Some(dpop_access_token_hash("bound-access-token")),
            nonce: None,
        };
        let proof = sign_proof(&claims, &signing);

        let verifier = DpopVerifier::new();
        let result = verifier
            .verify(
                &proof,
                "POST",
                "https://example.test/_arkret/gate/account/session-grants/refresh",
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
}
