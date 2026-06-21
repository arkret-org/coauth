//! Shared proof-of-possession signing-fields view and signature verification.
//!
//! Both the pairing PoP (CKP-0008 §4.5) and the `agent_key_proof` session
//! branch (§4.6) sign over the same canonical signed-fields shape, so the
//! verification routine lives here and is shared by both handlers.

use chrono::{DateTime, Utc};
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use cokret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
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
    let message =
        canonical_json_bytes(signed_fields).map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let public_key = PublicKeyMaterial::Ed25519Multibase {
        value: public_key_multibase.to_owned(),
    };
    if verify_detached_ed25519_signature(&public_key, &message, signature_b64) {
        Ok(())
    } else {
        Err(AgentAuthRejection::ProofInvalid)
    }
}

pub(super) fn canonical_digest(value: &impl Serialize) -> Result<String, AppError> {
    canonical_sha256(value).map_err(|error| {
        AppError::internal_box(Box::new(std::io::Error::other(format!(
            "canonical digest failed: {error}"
        ))))
    })
}
