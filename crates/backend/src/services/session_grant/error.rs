use anyhow::Error as AnyhowError;
use coauth_jose::jwt::JwtSignatureError;
use coauth_keyring::WrongAlgorithmError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionGrantError {
    #[error("no signing key is configured for Arkret session grants")]
    NoSigningKey,

    #[error(transparent)]
    JwtSignature(#[from] JwtSignatureError),

    #[error(transparent)]
    WrongAlgorithm(#[from] WrongAlgorithmError),

    #[error(transparent)]
    Serialize(#[from] serde_json::Error),

    /// Canonical JSON or digest failure surfaced by the canonical owner crate.
    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    /// Wire construction or validation failure surfaced by the wire owner crate.
    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    /// R3.2 (HC-COAUTH-1/2) — the handle-claim issuance request failed the
    /// `claim_kind` allow-list or subject (holder/principal DID)
    /// validation. Carries the SDK / shared wire reason code.
    #[error(transparent)]
    HandleClaimSubject(#[from] crate::services::handle_subject_validator::HandleClaimSubjectError),

    #[error("principal_unknown")]
    PrincipalUnknown,

    /// Typed identifier parse failure surfaced by the identifiers owner crate.
    #[error(transparent)]
    Identifier(#[from] arkret_identifiers::IdentifierError),

    #[error(transparent)]
    Other(#[from] AnyhowError),
}
