use coauth_data::oauth::NewSessionGrant;
#[cfg(test)]
use coauth_data::{BrowserSession, SessionGrant};
use coauth_data::{Clock, RepositoryAccess};
use coauth_oauth_types::scope::{Scope, ScopeToken};
#[cfg(test)]
use rand_core::RngCore;
use ulid::Ulid;

use super::SessionGrantMaterial;

#[cfg(test)]
pub(crate) async fn persist_session_grant_with_browser_session_id<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session_id: Option<Ulid>,
    material: &mut SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess<Error = coauth_data::RepositoryError> + ?Sized,
{
    // Fixture templates carry no allocator authority. The mutable parameter
    // makes every caller use the actual reserved ID/U/window in later HTTP.
    let request_identity = format!("internal-test-issue:{}", material.grant_id);
    let canonical_intent = arkret_canonical::canonical_json_bytes(&material.metadata)
        .expect("validated fixture metadata must canonicalize");
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            rng,
            clock,
            coauth_data::NewSessionGrantOperation {
                issuer_id: material.issuer_id.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: material.metadata.proof_kind,
                request_identity: &request_identity,
                canonical_intent_digest: arkret_canonical::sha256_bytes(&canonical_intent),
                canonical_intent: &canonical_intent,
                target_session_grant_id: None,
                grant_not_before: Some(material.not_before_timestamp),
                grant_expires_at: Some(material.expires_at_timestamp),
                retained_until: material.expires_at_timestamp + chrono::Duration::days(7),
            },
        )
        .await?;
    let operation = match reserved {
        coauth_data::SessionGrantReserveOutcome::Reserved(operation)
        | coauth_data::SessionGrantReserveOutcome::Pending(operation) => operation,
        _ => {
            return Err(coauth_data::RepositoryError::from_error(
                std::io::Error::other(
                    "fixture issuance must have its original uncommitted reservation",
                ),
            ));
        }
    };
    let seed = super::SessionGrantIssuanceSeed::from_operation(&operation)
        .map_err(coauth_data::RepositoryError::from_error)?;
    material.grant_id = seed.grant_id.clone();
    material.session_grant = seed.session_grant;
    material.session_id = seed.session_id.clone();
    material.not_before_timestamp = seed.not_before;
    material.expires_at_timestamp = seed.expires_at;
    material.expires_at = arkret_canonical::format_timestamp_canonical(seed.expires_at);
    material.metadata.id = seed.grant_id;
    material.metadata.session_id = seed.session_id;
    material.metadata.not_before = seed.not_before;
    material.metadata.expires_at = seed.expires_at;
    material
        .metadata
        .validate()
        .map_err(coauth_data::RepositoryError::from_error)?;
    let canonical_outcome = arkret_canonical::canonical_json_bytes(material)
        .expect("reserved fixture material must canonicalize");
    let checkpoint =
        serde_json::json!({"kind":"internal_test_session_issue","grant_id":material.grant_id});
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            rng,
            clock,
            operation.id,
            coauth_data::SessionGrantProofAuthorization {
                authorization_ref: &request_identity,
                checkpoint: &checkpoint,
                proof_expires_at: material.expires_at_timestamp,
            },
            coauth_data::SessionGrantExactOutcome {
                canonical_response: &canonical_outcome,
                response_digest: arkret_canonical::sha256_bytes(&canonical_outcome),
            },
            new_session_grant_record(browser_session_id, material),
        )
        .await?;
    match committed {
        coauth_data::SessionGrantCommitOutcome::Committed(grant) => Ok(*grant),
        coauth_data::SessionGrantCommitOutcome::AuthorizationExpired(_) => Err(
            coauth_data::RepositoryError::from_error(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "issuer authorization expired while waiting for accepting locks",
            )),
        ),
        coauth_data::SessionGrantCommitOutcome::Replay(_)
        | coauth_data::SessionGrantCommitOutcome::Indeterminate(_) => {
            Err(coauth_data::RepositoryError::from_error(
                std::io::Error::other("fixture issuance did not commit its original reservation"),
            ))
        }
    }
}

pub(crate) fn new_session_grant_record(
    browser_session_id: Option<Ulid>,
    material: &SessionGrantMaterial,
) -> NewSessionGrant<'_> {
    let scope: Scope = material
        .scopes
        .iter()
        .map(|scope| scope.parse::<ScopeToken>())
        .collect::<Result<Scope, _>>()
        .expect("validated session grant scopes must be valid OAuth scope tokens");

    NewSessionGrant {
        grant_id: material.grant_id.clone(),
        browser_session_id,
        issuer_id: &material.issuer_id,
        subject_id: &material.subject_id,
        local_account_id: &material.local_account_id,
        device_id: material.device_id.as_deref(),
        audience_id: &material.audience_id,
        scope,
        session_grant: &material.session_grant,
        session_id: &material.session_id,
        metadata: &material.metadata,
        session_public_key: &material.session_public_key,
        credential_class: &material.credential_class,
        not_before: material.not_before_timestamp,
        expires_at: material.expires_at_timestamp,
    }
}

/// One ledger mutation; the controller retains ownership of save/cancel and
/// atomic proof consumption in this same repository transaction.
pub(crate) struct IssuanceCommit<'a> {
    pub operation_id: Ulid,
    pub proof: coauth_data::SessionGrantProofAuthorization<'a>,
    pub canonical_outcome: &'a [u8],
    pub browser_session_id: Option<Ulid>,
    pub material: &'a SessionGrantMaterial,
}

pub(crate) async fn commit_session_grant_issuance<R>(
    repo: &mut R,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn Clock,
    input: IssuanceCommit<'_>,
) -> Result<coauth_data::SessionGrantCommitOutcome, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    let IssuanceCommit {
        operation_id,
        proof,
        canonical_outcome,
        browser_session_id,
        material,
    } = input;
    use sha2::Digest as _;

    let response_digest: [u8; 32] = sha2::Sha256::digest(canonical_outcome).into();
    repo.oauth_session_grant()
        .commit_issuance(
            rng,
            clock,
            operation_id,
            proof,
            coauth_data::SessionGrantExactOutcome {
                canonical_response: canonical_outcome,
                response_digest,
            },
            new_session_grant_record(browser_session_id, material),
        )
        .await
}

#[cfg(test)]
pub(crate) async fn persist_session_grant<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session: &BrowserSession,
    material: &mut SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess<Error = coauth_data::RepositoryError> + ?Sized,
{
    persist_session_grant_with_browser_session_id(
        repo,
        rng,
        clock,
        Some(browser_session.id),
        material,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn persist_unbound_session_grant<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    material: &mut SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess<Error = coauth_data::RepositoryError> + ?Sized,
{
    persist_session_grant_with_browser_session_id(repo, rng, clock, None, material).await
}
