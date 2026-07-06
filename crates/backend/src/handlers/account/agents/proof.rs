//! Shared proof-of-possession signing-fields view and signature verification.
//!
//! Both the pairing PoP (CKP-0008 §4.5) and the `agent_key_proof` session
//! branch (§4.6) sign over the same canonical signed-fields shape, so the
//! verification routine lives here and is shared by both handlers.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use cokret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AgentAuthRejection;
use crate::AppError;

/// Canonical signed-fields view of a proof-of-possession: every field except
/// the signature, serialized via the SDK canonical JSON helper. Both pairing
/// PoP and the agent-key-proof session branch sign over this same shape so the
/// two proof surfaces share one verification routine.
#[derive(Debug, Serialize)]
pub(super) struct ProofSignedFields<'a> {
    pub(super) audience: &'a str,
    pub(super) challenge: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) nonce: Option<&'a str>,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) request_canonical_digest: &'a str,
    pub(super) verification_method: &'a str,
}

/// Verify an Ed25519 PoP signature (base64url, unpadded or padded) over the
/// canonical signed-fields bytes against a multibase Ed25519 public key.
pub(super) fn verify_proof_signature(
    verification_public_key: &str,
    signed_fields: &ProofSignedFields<'_>,
    signature_b64: &str,
) -> Result<(), AgentAuthRejection> {
    let message =
        canonical_json_bytes(signed_fields).map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let public_key = PublicKeyMaterial::Ed25519Multibase {
        value: verification_public_key.to_owned(),
    };
    if verify_detached_ed25519_signature(&public_key, &message, signature_b64) {
        Ok(())
    } else {
        Err(AgentAuthRejection::ProofInvalid)
    }
}

#[derive(Debug, Deserialize)]
struct AgentRuntimePublicKey {
    kty: String,
    kid: String,
    alg: String,
    key: String,
}

/// Convert the spec `PublicKey` object accepted at pairing into the Ed25519
/// material the detached-signature verifier consumes. This is intentionally
/// not a legacy wire parser: only `{kty:"OKP", alg:"Ed25519"|"EdDSA",
/// kid:<verification_method>, key:<base64url raw Ed25519>}` is accepted.
pub(super) fn runtime_public_key_material_from_spec(
    public_key: &Value,
    verification_method: &str,
) -> Result<String, AgentAuthRejection> {
    let key: AgentRuntimePublicKey =
        serde_json::from_value(public_key.clone()).map_err(|_| AgentAuthRejection::ProofInvalid)?;
    if key.kty != "OKP"
        || key.kid != verification_method
        || (key.alg != "Ed25519" && key.alg != "EdDSA")
    {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    let raw =
        Base64UrlUnpadded::decode_vec(&key.key).map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    Ok(cokret_core::ed25519_pubkey_to_did_key_multibase(&raw))
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
