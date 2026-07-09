//! R3.2 (arkret-spec @ b56cab1) handle-claim issuer guards.
//!
//! The normative subject validator is shared by every coauth code path
//! that mints a `ck.handle.claim` artefact. A handle claim subject MUST be a holder / principal
//! DID. It is      NOT a Realm `actor_id` (`ck:actor:`), a server-local `account_id`
//! (`ck:account:`), a      service DID, or a generic resource id. We delegate to the SDK's
//!      [`arkret_core::validate_handle_claim_subject`] so the wire code
//!      (`handle_claim_subject_not_principal_did`) stays in lockstep with soland / cotest / the
//!      spec.

use arkret_core::Did;
use thiserror::Error;

/// Wire-level reason code returned when the handle-claim subject is not a
/// holder / principal DID. Kept in sync with the SDK validator's
/// [`arkret_core::validate_handle_claim_subject`] error-message prefix.
pub const HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE: &str =
    "handle_claim_subject_not_principal_did";

#[derive(Debug, Error)]
pub enum HandleClaimSubjectError {
    /// The subject is not a holder / principal DID.
    #[error("{HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE}: {0}")]
    SubjectNotPrincipalDid(String),
}

/// HC-COAUTH-2 — reject `ck:actor:` / `ck:account:` / non-DID subjects.
///
/// Delegates to the SDK's [`arkret_core::validate_handle_claim_subject`]
/// so the rejection logic (and thus the wire code) matches the spec and
/// the other Arkret services. The input is parsed through
/// [`arkret_core::Did::new`] first; a value that is not even a structural
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
    arkret_core::validate_handle_claim_subject(&did)
        .map_err(|error| HandleClaimSubjectError::SubjectNotPrincipalDid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_principal_did_subject() {
        ensure_subject_is_principal_did("did:web:auth.example.com:users:01ABC").unwrap();
        ensure_subject_is_principal_did("did:key:z6Mk...").unwrap();
    }

    #[test]
    fn rejects_actor_and_account_typed_ids() {
        let actor = ensure_subject_is_principal_did("ak:actor:01ABCDEF").unwrap_err();
        assert!(
            actor
                .to_string()
                .starts_with(HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE)
        );
        let account = ensure_subject_is_principal_did("ak:account:01ABCDEF").unwrap_err();
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
