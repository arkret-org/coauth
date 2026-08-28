//! Handle-claim subject guards shared by every Coauth issuer path.

use arkret_identifiers::DidCoreId;
use thiserror::Error;

/// Wire-level reason code returned when the handle-claim subject is not a
/// holder / principal DID. Kept in sync with the SDK validator's
/// [`arkret_models_identity::validate_handle_claim_subject`] error-message prefix.
pub const HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE: &str =
    "handle_claim_subject_not_principal_id";

#[derive(Debug, Error)]
pub enum HandleClaimSubjectError {
    /// The subject is not a holder / principal DID.
    #[error("{HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE}: {0}")]
    SubjectNotPrincipalDid(String),
}

/// Validate the stable holder identity used by a handle claim.
pub fn ensure_subject_is_principal_core_id(
    subject: &str,
) -> Result<DidCoreId, HandleClaimSubjectError> {
    let principal_id = DidCoreId::new(subject.to_owned()).map_err(|error| {
        HandleClaimSubjectError::SubjectNotPrincipalDid(format!(
            "subject must be a holder/principal did_core_id ({subject}): {error}"
        ))
    })?;
    arkret_models_identity::validate_handle_claim_subject(&principal_id)
        .map_err(|error| HandleClaimSubjectError::SubjectNotPrincipalDid(error.to_string()))?;
    Ok(principal_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_principal_core_id_subject() {
        ensure_subject_is_principal_core_id("ak:did_core:web:auth.example.com:users:01ABC")
            .unwrap();
        ensure_subject_is_principal_core_id("ak:did_core:key:z6MkFixture").unwrap();
    }

    #[test]
    fn rejects_non_core_ids() {
        let account = ensure_subject_is_principal_core_id("ak:account:01ABCDEF").unwrap_err();
        assert!(
            account
                .to_string()
                .starts_with(HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID_CODE)
        );
    }

    #[test]
    fn rejects_non_did_subject() {
        assert!(ensure_subject_is_principal_core_id("not-a-did").is_err());
    }
}
