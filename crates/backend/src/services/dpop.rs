// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession / DPoP) verifier.
//!
//! Implements the proof-token shape that protects device-bound session
//! grants. A DPoP proof is a compact-serialisation JWS with:
//!
//! * `typ = "dpop+jwt"`
//! * `alg = "Ed25519"` — locked by the SDK verifier (`arkret_signatures::dpop::DPOP_PROOF_ALG`).
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
use std::sync::Arc;
use std::time::Duration as StdDuration;

use arkret_signatures::dpop::{DpopVerificationRequest, VerifiedDpopProof, verify_dpop_proof};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::{NewDpopJtiReplay, RepositoryAccess as _, RepositoryFactory as _};
use coauth_jose::jwk::PublicJsonWebKey;
use coauth_storage_postgres::PgRepositoryFactory;
use thiserror::Error;
use tokio::sync::Mutex;

/// Accepted proof freshness and future-clock leeway.
const MAX_PROOF_AGE: Duration = Duration::seconds(300);
const MAX_FUTURE_SKEW: Duration = Duration::seconds(30);

/// Time window for jti replay detection — once a jti is observed it is
/// rejected until this many seconds after its `iat`.
const NONCE_TTL: StdDuration = StdDuration::from_mins(5);
const MAX_IN_MEMORY_JTIS: usize = 100_000;

/// What can go wrong while verifying a DPoP proof. Cryptographic, target
/// and freshness failures surface verbatim from the SDK verifier; this
/// type adds the replay-window and `jkt`-binding failures enforced on top.
#[derive(Debug, Error)]
pub enum DpopError {
    #[error("DPoP header is missing")]
    Missing,

    #[error(transparent)]
    Verification(#[from] arkret_signatures::dpop::DpopVerificationError),

    #[error("DPoP `jti` `{0}` was already presented within the replay window")]
    JtiReplayed(String),

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

pub(crate) fn dpop_jti_digest(jti: &str) -> String {
    arkret_canonical::sha256_digest(jti.as_bytes())
}

/// Adapt the SDK JWK of a verified proof into the coauth JOSE public-key
/// type used by session-grant issuance.
pub(crate) fn session_public_jwk(
    jwk: &arkret_signatures::jwk::JsonWebKey,
) -> serde_json::Result<PublicJsonWebKey> {
    serde_json::from_value(serde_json::to_value(jwk)?)
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

    pub(crate) async fn check_and_record_replay_key(
        &self,
        key: &str,
        now: DateTime<Utc>,
        ttl: StdDuration,
    ) -> Result<(), DpopError> {
        self.jti_store.check_and_record(key, now, ttl).await
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
    /// On success returns the SDK-verified proof: its `jkt` thumbprint,
    /// decoded claims, and the embedded public JWK. On failure returns the
    /// most-specific [`DpopError`] variant.
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
    ) -> Result<VerifiedDpopProof, DpopError> {
        let verification = Self::verify_without_replay(dpop_header, htm, htu, now, access_token)?;
        self.jti_store
            .check_and_record(&verification.claims.jti, now, NONCE_TTL)
            .await?;

        Ok(verification)
    }

    /// Verify every cryptographic, target and freshness property without
    /// consuming the proof JTI. Transactional protocols use this form so the
    /// durable outcome and JTI replay row can be committed atomically.
    pub fn verify_without_replay(
        dpop_header: &str,
        htm: &str,
        htu: &str,
        now: DateTime<Utc>,
        access_token: Option<&str>,
    ) -> Result<VerifiedDpopProof, DpopError> {
        let trimmed = dpop_header.trim();
        if trimmed.is_empty() {
            return Err(DpopError::Missing);
        }

        Ok(verify_dpop_proof(&DpopVerificationRequest {
            proof_jwt: trimmed,
            method: htm,
            htu,
            access_token,
            now,
            max_age: MAX_PROOF_AGE,
            max_future_skew: MAX_FUTURE_SKEW,
            expected_nonce: None,
        })?)
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

pub(crate) fn dpop_replay_record(jti: &str, now: DateTime<Utc>) -> NewDpopJtiReplay {
    NewDpopJtiReplay {
        jti_digest: dpop_jti_digest(jti),
        seen_at: now,
        expires_at: now
            + Duration::from_std(NONCE_TTL).expect("NONCE_TTL fits in chrono::Duration"),
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

/// Read a DPoP-bound credential from the request's `Authorization` header.
/// The current-v1 profile has one presentation form only:
/// `Authorization: DPoP <credential>`. Bearer and whitespace-bearing token
/// values fail closed instead of selecting a compatibility parser.
#[must_use]
pub fn dpop_authorization_token(req: &salvo::Request) -> Option<&str> {
    let header = req.headers().get(http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("DPoP")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return None;
    }
    Some(token)
}

/// Compute the canonical `htu` (HTTP target URI) for the current
/// request: `<scheme>://<authority><path>`, anchored to the service's
/// configured public base URL.
///
/// `public_base_url` is intentionally **required** rather than optional: the
/// `htu` binding is only meaningful when it is derived from a trusted,
/// server-side source. The previous fallback to the attacker-controlled
/// `Host` header (with a hard-coded `http://` scheme) is removed so a
/// caller can never accidentally weaken the binding by omitting the base
/// — callers must always thread through their `UrlBuilder` public base.
#[must_use]
pub fn dpop_htu(public_base_url: &url::Url, req: &salvo::Request) -> String {
    let path = req.uri().path();
    let scheme = public_base_url.scheme();
    let host = public_base_url.host_str().unwrap_or("localhost");
    match public_base_url.port() {
        Some(port) => format!("{scheme}://{host}:{port}{path}"),
        None => format!("{scheme}://{host}{path}"),
    }
}

#[cfg(test)]
mod tests {
    use arkret_signatures::dpop::{DpopVerificationError, VerifiedDpopClaims};
    use arkret_signatures::dpop_access_token_hash;
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::jwa::AsymmetricSigningKey;
    use coauth_jose::jwk::JsonWebKeyPublicParameters;
    use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    use super::*;

    fn sign_proof(claims: &VerifiedDpopClaims, signing: &SigningKey) -> String {
        let verifying = signing.verifying_key();
        let public = PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&verifying))
            .with_alg(JsonWebSignatureAlg::Ed25519);
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Ed25519)
            .with_typ("dpop+jwt".to_owned())
            .with_jwk(public);
        let signer = AsymmetricSigningKey::ed25519(signing.clone());
        Jwt::sign(header, claims.clone(), &signer)
            .expect("DPoP sign")
            .into_string()
    }

    #[tokio::test]
    async fn verifies_well_formed_proof_and_extracts_jkt() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = VerifiedDpopClaims {
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
        let claims = VerifiedDpopClaims {
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
        let claims = VerifiedDpopClaims {
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
        assert!(matches!(
            result,
            Err(DpopError::Verification(
                DpopVerificationError::MethodMismatch
            ))
        ));
    }

    #[tokio::test]
    async fn rejects_iat_outside_skew() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let claims = VerifiedDpopClaims {
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
        assert!(matches!(
            result,
            Err(DpopError::Verification(
                DpopVerificationError::IssuedAtOutOfRange
            ))
        ));
    }

    #[tokio::test]
    async fn enforces_ath_when_access_token_present() {
        let signing = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let token = "some-access-token";
        let claims = VerifiedDpopClaims {
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
        let claims = VerifiedDpopClaims {
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
        assert!(matches!(
            result,
            Err(DpopError::Verification(
                DpopVerificationError::AccessTokenHashMismatch
            ))
        ));
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
