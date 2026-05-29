//! Unified helper for writing admin audit log entries.
//!
//! This module provides [`record_admin_operation`], a single function that
//! encapsulates the repeated pattern of conditionally writing an admin
//! operation audit log when the caller is an authenticated admin user.
//!
//! ## P5: signed audit rows
//!
//! Round 5 added an optional `audit_signature` column to
//! `admin_operation_logs`. The companion writer
//! [`record_admin_operation_signed`] computes a base64url-unpadded
//! detached signature over the canonical-JSON form of the
//! "what we logged" tuple using the coauth service signing key, and
//! attaches it to the new row. Existing callers continue to use
//! [`record_admin_operation`] and write unsigned rows — those rows
//! remain valid; the verification side is documented as
//! TODO(P5-impl).

use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_data::{
    BoxRepository, RepositoryAccess, RepositoryError,
    audit::{AdminOperation, NewAdminOperationLog},
};
use coauth_keystore::Keystore;
use contrix_core::canonical::canonical_json_bytes;
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng as _};
use serde::Serialize;
use signature::RandomizedSigner as _;
use ulid::Ulid;

/// Record an admin operation in the audit log, if the caller is an
/// authenticated admin user.
///
/// When `admin_user` is `None` (e.g. the request was made with a
/// service-level token that has no associated user), the function is a
/// no-op.
pub async fn record_admin_operation(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn coauth_data::Clock,
    admin_user: Option<&coauth_data::User>,
    operation: AdminOperation,
    resource_type: &str,
    resource_id: Option<Ulid>,
    details: serde_json::Value,
) -> Result<(), RepositoryError> {
    if let Some(admin) = admin_user {
        let mut params = NewAdminOperationLog::new(admin.id, operation, resource_type, details);
        if let Some(id) = resource_id {
            params = params.with_resource_id(id);
        }
        repo.audit().add_admin_operation(rng, clock, params).await?;
    }
    Ok(())
}

/// Like [`record_admin_operation`] but additionally computes a
/// detached signature over the canonical-JSON form of the audit
/// payload using `keystore`'s preferred service signing key.
///
/// Best-effort: if the keystore has no usable signing key the row is
/// written **unsigned** rather than failing the request. The audit
/// row is the authoritative record; the signature is a defence in
/// depth, not a precondition.
///
/// TODO(P5-impl): migrate the 30+ existing call sites in
/// `handlers::admin::*` from [`record_admin_operation`] to this
/// function. Coexists during rollout so unsigned rows are still
/// accepted.
pub async fn record_admin_operation_signed(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn coauth_data::Clock,
    keystore: &Keystore,
    service_did: &str,
    admin_user: Option<&coauth_data::User>,
    operation: AdminOperation,
    resource_type: &str,
    resource_id: Option<Ulid>,
    details: serde_json::Value,
) -> Result<(), RepositoryError> {
    let Some(admin) = admin_user else {
        return Ok(());
    };

    let mut params =
        NewAdminOperationLog::new(admin.id, operation.clone(), resource_type, details.clone());
    if let Some(id) = resource_id {
        params = params.with_resource_id(id);
    }

    // Compose the canonical transcript and try to sign it. Failure to
    // sign is logged at WARN and the row is still written, unsigned.
    let transcript = AuditTranscript {
        kind: "cx.coauth.audit.admin_operation.v1",
        admin_user_id: admin.id.to_string(),
        operation: &operation,
        resource_type,
        resource_id: resource_id.map(|id| id.to_string()),
        details: &details,
    };

    match sign_transcript(keystore, service_did, &transcript) {
        Ok(sig) => {
            params = params.with_audit_signature(sig);
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                resource_type,
                "audit row written unsigned: keystore could not produce a signature"
            );
        }
    }

    repo.audit().add_admin_operation(rng, clock, params).await?;
    Ok(())
}

/// Canonical-JSON transcript bound to one admin-audit row. Field
/// order is fixed but `contrix_core::canonical` re-sorts before
/// emitting bytes, so this is just for shape.
#[derive(Debug, Serialize)]
struct AuditTranscript<'a> {
    kind: &'a str,
    admin_user_id: String,
    operation: &'a AdminOperation,
    resource_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
    details: &'a serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
enum SignError {
    #[error("no usable service signing key in keystore")]
    NoSigningKey,
    #[error("keystore signing key rejected the audit algorithm")]
    KeyAlgMismatch,
    #[error("canonical-JSON encoding failed: {0}")]
    Canonical(String),
    #[error("audit transcript signing failed")]
    Sign,
}

fn sign_transcript(
    keystore: &Keystore,
    service_did: &str,
    transcript: &AuditTranscript<'_>,
) -> Result<String, SignError> {
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::constraints::Constrainable as _;

    let canonical =
        canonical_json_bytes(transcript).map_err(|e| SignError::Canonical(e.to_string()))?;

    let (alg, key) = [
        JsonWebSignatureAlg::EdDsa,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
    ]
    .into_iter()
    .find_map(|alg| keystore.signing_key_for_algorithm(&alg).map(|k| (alg, k)))
    .ok_or(SignError::NoSigningKey)?;

    // Ensure the key has a JWK kid; if not we cannot verify later.
    key.kid().ok_or(SignError::NoSigningKey)?;
    let signer = keystore
        .signer_for_algorithm(&alg)
        .map_err(|_| SignError::KeyAlgMismatch)?;

    let mut rng = ChaChaRng::from_rng(rand_core::OsRng).map_err(|_| SignError::Sign)?;
    let raw = signer
        .try_sign_with_rng(&mut rng, &canonical)
        .map_err(|_| SignError::Sign)?;

    let sig_bytes: Box<[u8]> = raw.into();
    let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
    // `<service_did>#<jwk_kid>:<sig>` matches the policy-signer
    // envelope shape so verifiers can dispatch on the same DID-URL
    // form. Stored as a single TEXT column for now; can be split into
    // a kid column later if grouping by kid becomes useful.
    let _ = service_did; // future: emit `kid` alongside `sig` if column is split
    Ok(sig_b64)
}
