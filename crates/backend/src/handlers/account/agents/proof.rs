//! Shared proof-of-possession signing-fields view and signature verification.
//!
//! Both the pairing PoP (CKP-0008 §4.5) and the `agent_key_proof` session
//! branch (§4.6) sign over the same canonical signed-fields shape, so the
//! verification routine lives here and is shared by both handlers.

use chrono::{DateTime, Utc};
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Serialize;

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
    pub(super) expires_at: DateTime<Utc>,
    pub(super) request_canonical_digest: &'a str,
    pub(super) verification_method: &'a str,
}

/// Verify an Ed25519 PoP signature (base64url, unpadded or padded) over the
/// canonical signed-fields bytes against a multibase Ed25519 public key.
pub(super) fn verify_proof_signature(
    public_key_multibase: &str,
    signed_fields: &ProofSignedFields<'_>,
    signature_b64: &str,
) -> Result<(), AgentAuthRejection> {
    let key_bytes = cokret::identity::binding::decode_multicodec_ed25519(public_key_multibase)
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let verifying =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| AgentAuthRejection::ProofInvalid)?;

    let message =
        canonical_json_bytes(signed_fields).map_err(|_| AgentAuthRejection::ProofInvalid)?;

    let signature_bytes =
        base64_decode_flexible(signature_b64).ok_or(AgentAuthRejection::ProofInvalid)?;
    if signature_bytes.len() != 64 {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying
        .verify(&message, &signature)
        .map_err(|_| AgentAuthRejection::ProofInvalid)
}

/// Decode base64url (preferred) or standard base64, padded or unpadded.
pub(super) fn base64_decode_flexible(value: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(value)
        .or_else(|_| Base64Url::decode_vec(value))
        .or_else(|_| Base64Unpadded::decode_vec(value))
        .or_else(|_| Base64::decode_vec(value))
        .ok()
}

pub(super) fn canonical_digest(value: &impl Serialize) -> Result<String, AppError> {
    canonical_sha256(value).map_err(|error| {
        AppError::internal_box(Box::new(std::io::Error::other(format!(
            "canonical digest failed: {error}"
        ))))
    })
}
