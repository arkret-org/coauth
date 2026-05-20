//! Validate DID-binding `control_proof` payloads against the resolved DID
//! document.
//!
//! Shape: a detached JWS signed by one of the DID's verification-method
//! keys, over a canonical "binding statement" of the form:
//!
//! ```json
//! {
//!   "type": "cx.did_binding.control_proof.v1",
//!   "account_did": "<account DID>",
//!   "cx_account_id": "<local account ULID>",
//!   "nonce": "<opaque nonce>",
//!   "iat": "<RFC3339 timestamp>"
//! }
//! ```
//!
//! Verification flow:
//!   1. Resolve the DID via the configured resolver chain (`DidResolverService`).
//!   2. Reject if the resolver returns no `verificationMethod` keys.
//!   3. Reject if the JWS doesn't verify against any of those keys.
//!   4. Reject if the embedded binding statement doesn't match the request
//!      (`account_did` + `cx_account_id` + nonce all match exactly).
//!
//! SDK note: `contrix::identity::binding::verify_binding_proof` is the
//! available pure SDK verifier today, but it accepts a raw Ed25519 proof
//! tuple, not coauth's compact JWS + DID-document JWKS envelope. Until
//! the SDK grows a JWS/JWKS binding-proof adapter, this module keeps the
//! envelope verification in `coauth_jose` and pins the statement checks
//! below with targeted unit tests.
//!
//! ## Verification-service proof
//!
//! [`verify_verification_service_proof`] is the sister verifier for the
//! 3PID invite chain (see `third_party_invite::verify_invite`). It
//! validates a signed JWT issued by a trusted 3PID verification service
//! whose claims attest that a 3PID (e.g. email) was verified for the
//! presented invite. Required claims: `iss` (must equal the configured
//! `expected_verification_service_did`), `aud` (must equal the local
//! coauth service DID), `sub` (SHA-256 hex of the normalized 3PID),
//! `exp` (must be in the future), `nbf` (must be ≤ now), `jti`, and
//! `nonce`. The signature is verified against the verification
//! service's resolved DID document JWKS.

use chrono::{DateTime, Utc};
use coauth_config::ContrixConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_jose::{jwk::PublicJsonWebKeySet, jwt::Jwt};
use coauth_keystore::Keystore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::services::did_resolver::{DidResolveError, DidResolverService};

/// Canonical binding statement claims embedded in a proof JWS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingStatementClaims {
    /// Discriminator. Must equal `cx.did_binding.control_proof.v1`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The DID being bound.
    pub account_did: String,
    /// The local coauth account ULID (string-encoded).
    pub cx_account_id: String,
    /// Nonce supplied in the binding request.
    pub nonce: String,
    /// Issuance time.
    pub iat: DateTime<Utc>,
}

/// Validation errors. All variants are deterministic from the inputs and
/// resolver response.
#[derive(Debug, Error)]
pub enum DidBindingProofError {
    #[error("control_proof must be a non-empty JWS string")]
    EmptyProof,

    #[error("control_proof JWS could not be parsed: {0}")]
    InvalidJws(String),

    #[error("DID resolver failed: {0}")]
    Resolve(#[from] DidResolveError),

    #[error("DID document has no verificationMethod entries")]
    NoVerificationKey,

    #[error("control_proof JWS signature did not verify against any DID key")]
    SignatureMismatch,

    #[error("binding statement type discriminator mismatch")]
    StatementKindMismatch,

    #[error("binding statement account_did does not match request")]
    AccountDidMismatch,

    #[error("binding statement cx_account_id does not match request")]
    CxAccountIdMismatch,

    #[error("binding statement nonce does not match request")]
    NonceMismatch,

    #[error("binding statement iat is in the future or expired")]
    IatOutOfRange,
}

/// Maximum `iat` skew accepted, in seconds. Past or future drift beyond
/// this window rejects the proof.
const MAX_IAT_SKEW_SECS: i64 = 5 * 60;

/// Validate a `control_proof` JWS against the resolved DID document and
/// the requested binding statement.
///
/// `account_did` / `cx_account_id` / `nonce` form the canonical statement
/// that must be embedded inside the JWS payload. `now` is used to bound
/// the `iat` claim (proofs more than 5 minutes from `now` in either
/// direction are rejected).
#[allow(clippy::too_many_arguments)]
pub async fn validate_control_proof(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    proof_jws: &str,
    account_did: &str,
    cx_account_id: Ulid,
    nonce: &str,
    now: DateTime<Utc>,
) -> Result<BindingStatementClaims, DidBindingProofError> {
    if proof_jws.trim().is_empty() {
        return Err(DidBindingProofError::EmptyProof);
    }

    // Round 4 (spec a77b995) — DID regex tightened to
    // `^did:[a-z0-9]+:[^\s]+$`. Reject any value the SDK validator
    // refuses BEFORE invoking the resolver chain, so wire-broken DIDs
    // never trigger network I/O. Delegating to the SDK's validator
    // keeps coauth in lockstep with the canonical regex.
    if contrix_core::Did::new(account_did.to_owned()).is_err() {
        return Err(DidBindingProofError::InvalidJws(format!(
            "account_did {account_did:?} fails round-4 DID regex"
        )));
    }

    // Parse JWS
    let jwt: Jwt<'_, BindingStatementClaims> =
        Jwt::try_from(proof_jws).map_err(|e| DidBindingProofError::InvalidJws(e.to_string()))?;

    // Resolve DID document
    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            contrix_config,
            key_store,
            repo,
            account_did,
        )
        .await?;

    let keys: Vec<_> = resolution
        .document
        .verification_method
        .iter()
        .map(|vm| vm.public_key_jwk.clone())
        .collect();
    if keys.is_empty() {
        return Err(DidBindingProofError::NoVerificationKey);
    }

    let jwks = PublicJsonWebKeySet::new(keys);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return Err(DidBindingProofError::SignatureMismatch);
    }

    let claims = jwt.payload();
    validate_binding_statement_claims(claims, account_did, cx_account_id, nonce, now)?;

    Ok(claims.clone())
}

fn validate_binding_statement_claims(
    claims: &BindingStatementClaims,
    account_did: &str,
    cx_account_id: Ulid,
    nonce: &str,
    now: DateTime<Utc>,
) -> Result<(), DidBindingProofError> {
    if claims.kind != "cx.did_binding.control_proof.v1" {
        return Err(DidBindingProofError::StatementKindMismatch);
    }
    if claims.account_did != account_did {
        return Err(DidBindingProofError::AccountDidMismatch);
    }
    if claims.cx_account_id != cx_account_id.to_string() {
        return Err(DidBindingProofError::CxAccountIdMismatch);
    }
    if claims.nonce != nonce {
        return Err(DidBindingProofError::NonceMismatch);
    }
    let skew_secs = (claims.iat - now).num_seconds().abs();
    if skew_secs > MAX_IAT_SKEW_SECS {
        return Err(DidBindingProofError::IatOutOfRange);
    }

    Ok(())
}

// ─────────────── Verification-service proof (3PID invite chain) ───────────────

/// JWT claims issued by the trusted 3PID verification service.
///
/// All fields are MANDATORY. Unknown / missing claims are rejected
/// up-front via the JSON deserialiser; semantic checks
/// (`iss` / `aud` / `sub` / `exp` / `nbf`) live in
/// [`verify_verification_service_proof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationServiceProofClaims {
    /// Issuer DID — MUST equal the configured trusted verification
    /// service DID.
    pub iss: String,
    /// Audience — MUST equal the local coauth service DID.
    pub aud: String,
    /// Subject — SHA-256 (hex) of the normalized 3PID (e.g. lowercased
    /// trimmed email address).
    pub sub: String,
    /// Expiry, Unix-epoch seconds. MUST be in the future.
    pub exp: i64,
    /// Not-before, Unix-epoch seconds. MUST be ≤ now.
    pub nbf: i64,
    /// JWT ID. Used for replay defence in the calling layer.
    pub jti: String,
    /// Single-use nonce; the upper layer (`third_party_invite`)
    /// records it for cross-proof linkage.
    pub nonce: String,
}

/// Errors returned by [`verify_verification_service_proof`].
///
/// The caller MAPS these onto the public
/// `InviteVerificationError::VerificationProofInvalid` /
/// `ProofExpired` variants in `third_party_invite.rs`. We keep this
/// enum private to coauth's service layer (i.e. not exposed on the
/// wire) so we can grow it without breaking the HTTP surface.
#[derive(Debug, Error)]
pub enum VerificationProofError {
    #[error("JWS could not be parsed: {0}")]
    InvalidJws(String),
    #[error("DID resolver failed: {0}")]
    Resolve(#[from] DidResolveError),
    #[error("DID document has no verificationMethod entries")]
    NoVerificationKey,
    #[error("JWS signature did not verify against any verification-service key")]
    SignatureMismatch,
    #[error("iss claim {actual:?} does not match expected {expected:?}")]
    IssuerMismatch { expected: String, actual: String },
    #[error("aud claim {actual:?} does not match expected audience {expected:?}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("nbf claim {nbf} is in the future (now={now})")]
    NotYetValid { nbf: i64, now: i64 },
    #[error("proof has expired: {0}")]
    Expired(String),
    #[error("sub claim is empty or malformed")]
    SubjectMalformed,
}

/// Verify a verification-service proof JWS.
///
/// Steps:
/// 1. Parse the compact JWS into a typed JWT.
/// 2. Reject empty / malformed claims (`sub`).
/// 3. Match `iss` / `aud` against the expected values.
/// 4. Reject `nbf > now` and `exp <= now`.
/// 5. Resolve the issuer DID document, verify the signature against
///    its JWKS.
///
/// Replay defence (`jti` deduplication) is NOT done here — the caller
/// owns the nonce store so a successful verify against a replayed
/// `jti` doesn't poison the store with garbage entries before the
/// signature is checked.
#[allow(clippy::too_many_arguments)]
pub async fn verify_verification_service_proof(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    proof_jws: &str,
    expected_issuer_did: &str,
    expected_audience: &str,
    now: DateTime<Utc>,
) -> Result<VerificationServiceProofClaims, VerificationProofError> {
    if proof_jws.trim().is_empty() {
        return Err(VerificationProofError::InvalidJws("empty JWS".into()));
    }

    let jwt: Jwt<'_, VerificationServiceProofClaims> = Jwt::try_from(proof_jws)
        .map_err(|e| VerificationProofError::InvalidJws(e.to_string()))?;

    let claims = jwt.payload();
    if claims.sub.trim().is_empty() {
        return Err(VerificationProofError::SubjectMalformed);
    }
    if claims.iss != expected_issuer_did {
        return Err(VerificationProofError::IssuerMismatch {
            expected: expected_issuer_did.to_owned(),
            actual: claims.iss.clone(),
        });
    }
    if claims.aud != expected_audience {
        return Err(VerificationProofError::AudienceMismatch {
            expected: expected_audience.to_owned(),
            actual: claims.aud.clone(),
        });
    }
    let now_ts = now.timestamp();
    if claims.nbf > now_ts {
        return Err(VerificationProofError::NotYetValid {
            nbf: claims.nbf,
            now: now_ts,
        });
    }
    if claims.exp <= now_ts {
        return Err(VerificationProofError::Expired(format!(
            "exp {} <= now {}",
            claims.exp, now_ts
        )));
    }

    // Resolve the issuer DID and check the signature against its keys.
    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            contrix_config,
            key_store,
            repo,
            &claims.iss,
        )
        .await?;

    let keys: Vec<_> = resolution
        .document
        .verification_method
        .iter()
        .map(|vm| vm.public_key_jwk.clone())
        .collect();
    if keys.is_empty() {
        return Err(VerificationProofError::NoVerificationKey);
    }
    let jwks = PublicJsonWebKeySet::new(keys);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return Err(VerificationProofError::SignatureMismatch);
    }

    Ok(claims.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_claims_default() -> BindingStatementClaims {
        BindingStatementClaims {
            kind: "cx.did_binding.control_proof.v1".to_owned(),
            account_did: "did:web:alice.example".to_owned(),
            cx_account_id: Ulid::nil().to_string(),
            nonce: "nonce-123".to_owned(),
            iat: chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn binding_statement_claims_round_trip() {
        let original = statement_claims_default();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: BindingStatementClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, original.kind);
        assert_eq!(decoded.account_did, original.account_did);
        assert_eq!(decoded.cx_account_id, original.cx_account_id);
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.iat, original.iat);
    }

    #[test]
    fn binding_statement_kind_must_be_explicit() {
        // Sanity check: type discriminator literal is what the validator expects.
        assert_eq!(
            statement_claims_default().kind,
            "cx.did_binding.control_proof.v1"
        );
    }

    #[test]
    fn binding_statement_validation_accepts_exact_request_context() {
        let claims = statement_claims_default();

        validate_binding_statement_claims(
            &claims,
            "did:web:alice.example",
            Ulid::nil(),
            "nonce-123",
            claims.iat,
        )
        .expect("matching statement should validate");
    }

    #[test]
    fn binding_statement_validation_rejects_nonce_replay() {
        let claims = statement_claims_default();

        let err = validate_binding_statement_claims(
            &claims,
            "did:web:alice.example",
            Ulid::nil(),
            "different-nonce",
            claims.iat,
        )
        .expect_err("nonce replay must reject");

        assert!(matches!(err, DidBindingProofError::NonceMismatch));
    }

    #[test]
    fn binding_statement_validation_rejects_expired_iat() {
        let claims = statement_claims_default();
        let now = claims.iat + chrono::Duration::seconds(MAX_IAT_SKEW_SECS + 1);

        let err = validate_binding_statement_claims(
            &claims,
            "did:web:alice.example",
            Ulid::nil(),
            "nonce-123",
            now,
        )
        .expect_err("expired statement must reject");

        assert!(matches!(err, DidBindingProofError::IatOutOfRange));
    }
}
