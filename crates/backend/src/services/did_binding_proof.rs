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
//!      (account_did + cx_account_id + nonce all match exactly).

use chrono::{DateTime, Utc};
use coauth_config::ContrixConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_jose::{
    jwk::PublicJsonWebKeySet,
    jwt::Jwt,
};
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

    // Parse JWS
    let jwt: Jwt<'_, BindingStatementClaims> = Jwt::try_from(proof_jws)
        .map_err(|e| DidBindingProofError::InvalidJws(e.to_string()))?;

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

    // Statement equality
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
}
