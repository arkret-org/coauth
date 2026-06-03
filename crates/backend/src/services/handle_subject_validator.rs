//! R3.2 (cokret-spec @ b56cab1) handle-claim issuer guards.
//!
//! Two normative tightenings land here, shared by every coauth code path
//! that mints a `cx.handle.claim` artefact:
//!
//!   1. **`claim_kind` deny check** — the draft-era `service_handle`
//!      `claim_kind` was removed from `ck.schema.handle_claim.v1`
//!      (`HandleClass::ServiceHandle` no longer exists in the SDK). v1 only
//!      allows `handle_binding` / `organization_handle`. coauth never emits
//!      `service_handle` today, but to fail closed against future drift we keep
//!      an explicit allow-list + deny check rather than relying on the absence
//!      of a code path. (Handle Claim's closed protocol taxonomy uses
//!      `claim_kind`, per `common-fields.md` §`kind`/`type` naming rules.)
//!
//!   2. **`subject` validator** — a handle claim subject MUST be a holder /
//!      principal DID. It is NOT a Realm `actor_id` (`ck:actor:`), a
//!      server-local `account_id` (`ck:account:`), a service DID, or a generic
//!      resource id. We delegate to the SDK's
//!      [`cokret_core::validate_handle_claim_subject`] so the wire code
//!      (`handle_claim_subject_not_principal_did`) stays in lockstep with
//!      soland / cotest / the spec.

use cokret_core::Did;
use thiserror::Error;

/// Wire-level reason code returned when an issuance request asks for a
/// `claim_kind` coauth no longer supports (notably the removed
/// `service_handle`). Mirrors the audit reason soland emits (HC-SOL-1).
pub const CLAIM_KIND_UNSUPPORTED_CODE: &str = "claim_kind_unsupported";

/// Wire-level reason code returned when the handle-claim subject is not a
/// holder / principal DID. Kept in sync with the SDK validator's
/// [`cokret_core::validate_handle_claim_subject`] error-message prefix.
pub const HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE: &str =
    "handle_claim_subject_not_principal_did";

/// The only `claim_kind` values coauth's handle-claim issuer accepts.
///
/// Matches the post-R3.2 `ck.schema.handle_claim.v1` `claim_kind` enum
/// (`HandleClass::{UserHandle, OrganizationHandle}` in the SDK). The SDK
/// serialises those variants as the snake-case strings below.
pub const ALLOWED_CLAIM_KINDS: &[&str] = &["handle_binding", "organization_handle"];

#[derive(Debug, Error)]
pub enum HandleClaimSubjectError {
    /// The requested `claim_kind` is not in [`ALLOWED_CLAIM_KINDS`]
    /// (typically the removed `service_handle`).
    #[error("{CLAIM_KIND_UNSUPPORTED_CODE}: claim_kind {0:?} is not supported by this issuer")]
    ClaimKindUnsupported(String),

    /// The subject is not a holder / principal DID.
    #[error("{HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE}: {0}")]
    SubjectNotPrincipalDid(String),
}

/// HC-COAUTH-1 — reject any `claim_kind` outside [`ALLOWED_CLAIM_KINDS`].
///
/// `service_handle` was removed from the schema in R3.2; this fails closed
/// against any caller (or future internal path) that tries to mint one.
pub fn ensure_claim_kind_supported(claim_kind: &str) -> Result<(), HandleClaimSubjectError> {
    if ALLOWED_CLAIM_KINDS.contains(&claim_kind) {
        Ok(())
    } else {
        Err(HandleClaimSubjectError::ClaimKindUnsupported(
            claim_kind.to_owned(),
        ))
    }
}

/// HC-COAUTH-2 — reject `ck:actor:` / `ck:account:` / non-DID subjects.
///
/// Delegates to the SDK's [`cokret_core::validate_handle_claim_subject`]
/// so the rejection logic (and thus the wire code) matches the spec and
/// the other Cokret services. The input is parsed through
/// [`cokret_core::Did::new`] first; a value that is not even a structural
/// DID is rejected with the same `handle_claim_subject_not_principal_did`
/// code (a `ck:actor:`/`ck:account:` typed id is not a `did:` and would be
/// rejected by `Did::new` anyway, but we keep the message explicit).
pub fn ensure_subject_is_principal_did(subject: &str) -> Result<(), HandleClaimSubjectError> {
    // The SDK validator wants an already-parsed `Did`. A `ck:actor:` /
    // `ck:account:` typed id will fail `Did::new`, so we surface the
    // principal-DID reason directly rather than the generic DID parse
    // error to keep the wire code stable.
    let did = Did::new(subject.to_owned()).map_err(|error| {
        HandleClaimSubjectError::SubjectNotPrincipalDid(format!(
            "subject must be a holder/principal DID ({subject}): {error}"
        ))
    })?;
    cokret_core::validate_handle_claim_subject(&did)
        .map_err(|error| HandleClaimSubjectError::SubjectNotPrincipalDid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_v1_claim_kinds() {
        ensure_claim_kind_supported("handle_binding").unwrap();
        ensure_claim_kind_supported("organization_handle").unwrap();
    }

    #[test]
    fn rejects_service_handle_claim_kind() {
        let err = ensure_claim_kind_supported("service_handle").unwrap_err();
        assert!(matches!(
            err,
            HandleClaimSubjectError::ClaimKindUnsupported(_)
        ));
        assert!(err.to_string().starts_with(CLAIM_KIND_UNSUPPORTED_CODE));
    }

    #[test]
    fn rejects_unknown_claim_kind() {
        assert!(ensure_claim_kind_supported("user_handle").is_err());
    }

    #[test]
    fn accepts_principal_did_subject() {
        ensure_subject_is_principal_did("did:web:auth.example.com:users:01ABC").unwrap();
        ensure_subject_is_principal_did("did:key:z6Mk...").unwrap();
    }

    #[test]
    fn rejects_actor_and_account_typed_ids() {
        let actor = ensure_subject_is_principal_did("ck:actor:01ABCDEF").unwrap_err();
        assert!(
            actor
                .to_string()
                .starts_with(HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE)
        );
        let account = ensure_subject_is_principal_did("ck:account:01ABCDEF").unwrap_err();
        assert!(
            account
                .to_string()
                .starts_with(HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE)
        );
    }

    #[test]
    fn rejects_non_did_subject() {
        assert!(ensure_subject_is_principal_did("not-a-did").is_err());
    }
}
