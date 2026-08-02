//! Shared proof-of-possession signature verification.
//!
//! Protocol-owned signing-input types produce canonical bytes; this module
//! only verifies those bytes so handlers cannot drift through shadow DTOs.

use arkret_canonical::canonical_sha256;
use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Serialize;
use serde_json::Value;

use super::AgentAuthRejection;
use crate::AppError;

/// Verify an Ed25519 proof signature over canonical bytes produced by the
/// protocol owner. Session-grant proofs use the SDK-owned signing-input type
/// directly so the issuer and verifier cannot drift through shadow DTOs.
pub(super) fn verify_proof_signature_bytes(
    verification_public_key: &str,
    message: &[u8],
    signature_b64: &str,
) -> Result<(), AgentAuthRejection> {
    let public_key = PublicKeyMaterial::Ed25519Multibase {
        value: verification_public_key.to_owned(),
    };
    if verify_detached_ed25519_signature(&public_key, message, signature_b64) {
        Ok(())
    } else {
        Err(AgentAuthRejection::ProofInvalid)
    }
}

/// Convert the spec `PublicKey` object accepted at pairing into the Ed25519
/// material the detached-signature verifier consumes. This is intentionally
/// not a legacy wire parser: only `{kty:"OKP", alg:"Ed25519"|"EdDSA",
/// kid:<verification_method>, key:<base64url raw Ed25519>}` is accepted.
pub(super) fn runtime_public_key_material_from_spec(
    public_key: &Value,
    verification_method: &str,
) -> Result<String, AgentAuthRejection> {
    let key: arkret_models_collaboration::governance::agent_artifacts::PublicKey =
        serde_json::from_value(public_key.clone()).map_err(|_| AgentAuthRejection::ProofInvalid)?;
    if key.kty.as_str() != "OKP"
        || key.kid.as_str() != verification_method
        || (key.alg.as_str() != "Ed25519" && key.alg.as_str() != "EdDSA")
    {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    let raw = Base64UrlUnpadded::decode_vec(key.key.as_str())
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    Ok(arkret_canonical::ed25519_pubkey_to_did_key_multibase(&raw))
}

/// Compute the canonical SHA-256 digest of `value`, mapping the canonical
/// serialization failure into an [`AppError`].
///
/// Kept as a shared helper rather than inlined: there are multiple call sites
/// across the agents module (`key_pair.rs`, `accountability.rs`) and inlining
/// would duplicate the identical error-mapping boilerplate at each one.
pub(super) fn canonical_digest(value: &impl Serialize) -> Result<String, AppError> {
    canonical_sha256(value).map_err(|error| {
        AppError::internal_box(Box::new(std::io::Error::other(format!(
            "canonical digest failed: {error}"
        ))))
    })
}
