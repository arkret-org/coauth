//! Shared approval-proof verification for destructive admin revocations.
//!
//! Device revocation (cascading every session grant) and account-DID
//! binding removal are high-risk identity operations. `key-management.md`
//! §7 ("SHOULD use proposal / approval constraints for high-risk actions") and the account
//! risk-action workflow already require detached-JWS approval evidence for
//! `disable` / `erase`. To keep the module's high-risk governance posture
//! consistent, the optional `approval_proof` supplied to a revocation MUST
//! be a real detached JWS bound to the authenticated admin's primary DID
//! over a canonical revocation transcript — it is no longer recorded as a
//! mere `approval_proof_present` boolean.
//!
//! Semantics: when no proof is supplied the revocation proceeds (admin
//! token + audit trail remain the baseline gate, matching spec's SHOULD).
//! When a proof *is* supplied it MUST verify, otherwise the request is
//! rejected — closing the previous gap where a forged/garbage proof was
//! silently accepted and only its presence logged.

use arkret_canonical::canonical_json_bytes;
use arkret_identifiers::Did;
use serde::Serialize;

use crate::AppError;
use crate::handlers::common::DepotExt;
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;

/// Canonical transcript that an admin revocation approval JWS must cover.
///
/// The detached-JWS payload is the canonical-JSON encoding of this struct,
/// binding the signature to the exact operation (kind), target resource and
/// reason so a captured signature cannot be replayed against a different
/// device / DID / account.
#[derive(Debug, Serialize)]
struct RevocationApprovalTranscript<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    /// Stable operation discriminator, e.g. `device.revoke` or
    /// `account_did_binding.revoke`.
    operation: &'static str,
    /// Targeted resource identifier (device id or DID).
    target: &'a str,
    /// Optional account scope (account ULID), when the revocation is
    /// account-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<&'a str>,
    /// Operator-supplied reason, bound into the signed transcript.
    reason: &'a str,
    /// Authenticated admin DID the proof is anchored to.
    approved_by: &'a Did,
}

/// Verify an optional admin revocation `approval_proof` against the
/// authenticated admin user's primary DID.
///
/// Returns:
/// - `Ok(None)` when no proof was supplied (revocation proceeds on the admin-token + audit
///   baseline).
/// - `Ok(Some(verification_method))` when a proof was supplied and verified against the
///   authenticated admin's primary DID document; the resolved verification method is returned for
///   audit binding.
/// - `Err(_)` when a proof was supplied but is empty / malformed / not anchored to the admin DID /
///   signature-invalid.
///
/// The caller's open `repo` is reused so the resolve happens inside the same
/// transaction as the revocation + audit write.
#[allow(clippy::too_many_arguments)]
pub(super) async fn verify_revocation_approval_proof(
    depot: &salvo::Depot,
    repo: &mut coauth_data::BoxRepository,
    admin_user: &coauth_data::User,
    operation: &'static str,
    target: &str,
    account_id: Option<&str>,
    reason: &str,
    approval_proof: Option<&str>,
) -> Result<Option<String>, AppError> {
    let proof = match approval_proof
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(proof) => proof,
        None => return Ok(None),
    };

    let arkret_config = depot.arkret_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let keyring = depot.keyring()?;
    let url_builder = depot.url_builder()?;
    let http_client = depot.http_client().map_err(AppError::internal)?;

    let approved_by = did_resolver
        .primary_did_for_user(repo, &arkret_config, admin_user)
        .await
        .map_err(|error| AppError::bad_request(format!("principal_id_policy: {error}")))?;

    let transcript = RevocationApprovalTranscript {
        kind: "org.arkret.coauth.admin_revocation.approval.v1",
        operation,
        target,
        account_id,
        reason,
        approved_by: &approved_by,
    };
    let payload = canonical_json_bytes(&transcript)
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    // §4 row 7 — an admin revocation approval is a high-risk write, so the
    // approver's own DID must satisfy `fresh_within(HIGH_RISK_MAX_AGE)` under
    // the closed `AdminAction` purpose. An acceptance made for the same DID as
    // a `Principal` (ordinary session subject) never authorizes this path.
    let resolution = crate::services::did_binding::authority_document(
        &http_client,
        &url_builder,
        &arkret_config,
        &keyring,
        repo,
        did_resolver.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        approved_by.as_str(),
        arkret_identity::DidBindingPurpose::AdminAction,
        crate::services::did_binding::high_risk_freshness(),
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|error| AppError::bad_request(format!("admin_did_resolve_failed: {error}")))?;
    if resolution.document.verification_method.is_empty() {
        return Err(AppError::bad_request(
            "approved_by DID document has no verificationMethod entries",
        ));
    }

    let verification_method =
        verify_detached_jws_with_sdk(proof, &payload, &resolution.document.verification_method)
            .map_err(|error| AppError::bad_request(format!("approval_proof_invalid: {error}")))?;

    Ok(Some(verification_method))
}
