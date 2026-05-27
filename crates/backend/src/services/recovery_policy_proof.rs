// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! REC-1 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) — recovery-policy
//! `proof_kind` enum guard.
//!
//! coauth's first-class recovery flow today is the password-reset / email-OOB
//! ticket loop in [`crate::handlers::account::recovery`] — it does NOT
//! participate in the CXP recovery-policy / recovery-receipt binding
//! described in `spec/v1/artifacts/schemas/recovery-policy.schema.json`.
//!
//! When (and only when) coauth is configured to issue OIDC-backed recovery
//! evidence as part of a `cx.schema.recovery_policy.v1` body (e.g. a
//! `trusted_recovery_service` provider in a sovereign deployment), this
//! module provides the wire-level guard that rejects any `proof_kind`
//! outside the registered enum:
//!
//! - `device_quorum`
//! - `recovery_unlock`
//! - `trusted_recovery_service`
//! - `principal_signing`
//!
//! The SDK source-of-truth is [`contrix_core::RecoveryProofKind`]; this
//! module is a thin coauth-side adapter so handlers and reducer-feeding
//! code paths can call into a single function regardless of whether the
//! deployment actually enables the OIDC-backed binding.
//
// TODO(R3.1): wire this into the (future) OIDC-recovery binding handler
// alongside the recovery-session id binding and the recovery-receipt
// emitter. Internal proof verification (cross-signing reset proof
// equivalents, threshold device quorum, OIDC trusted recovery service,
// principal-signing) is also a R3.1 deliverable — this round only
// pins the enum surface.

use contrix_core::RecoveryProofKind;
use thiserror::Error;

/// Outcome of the wire-level `proof_kind` validator.
#[derive(Debug, Error)]
pub enum RecoveryProofKindError {
    /// The `proof_kind` string is not one of the four enum variants
    /// registered in `recovery-policy.schema.json` v2026-05-27.
    #[error("recovery_policy proof_kind {0:?} is not a registered enum variant")]
    UnknownProofKind(String),
}

/// REC-1: validate that `proof_kind` parses to one of the four
/// registered `RecoveryProofKind` variants. Returns the typed enum on
/// success so callers can switch on the variant without re-parsing the
/// string.
///
/// This is the **wire-level** guard — it does NOT verify proof internals
/// (those land in R3.1 alongside the verifier implementation). Use
/// before persisting a `recovery-policy.body.proof_kinds[]` entry or
/// before accepting a `recovery-receipt` proof_summary.
pub fn validate_proof_kind(raw: &str) -> Result<RecoveryProofKind, RecoveryProofKindError> {
    for variant in RecoveryProofKind::ALL.iter().copied() {
        if variant.as_wire_str() == raw {
            return Ok(variant);
        }
    }
    Err(RecoveryProofKindError::UnknownProofKind(raw.to_owned()))
}

/// REC-1: validate a list of `proof_kind` strings (the schema shape on
/// `recovery-policy.body.proof_kinds[]`). Returns the typed enum
/// collection on success.
pub fn validate_proof_kinds(
    raw: &[String],
) -> Result<Vec<RecoveryProofKind>, RecoveryProofKindError> {
    raw.iter().map(|s| validate_proof_kind(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_four_registered_variants() {
        for variant in RecoveryProofKind::ALL.iter().copied() {
            let parsed = validate_proof_kind(variant.as_wire_str())
                .expect("registered variant must validate");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn rejects_unknown_variant() {
        let err = validate_proof_kind("password_reset")
            .expect_err("password_reset is not a registered enum variant");
        assert!(matches!(err, RecoveryProofKindError::UnknownProofKind(_)));
    }

    #[test]
    fn validates_a_list_of_variants() {
        let variants = ["device_quorum".to_owned(), "principal_signing".to_owned()];
        let parsed = validate_proof_kinds(&variants).expect("must accept registered variants");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], RecoveryProofKind::DeviceQuorum);
        assert_eq!(parsed[1], RecoveryProofKind::PrincipalSigning);
    }

    #[test]
    fn rejects_list_with_one_unknown_entry() {
        let variants = ["device_quorum".to_owned(), "magic_link".to_owned()];
        let result = validate_proof_kinds(&variants);
        assert!(result.is_err());
    }
}
