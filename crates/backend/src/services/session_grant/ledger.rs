use arkret_models_identity::SessionGrantIssuancePreimage;
use coauth_data::oauth::NewSessionGrant;
use coauth_data::{BrowserSession, Clock, RepositoryAccess, SessionGrant};
use coauth_oauth_types::scope::{Scope, ScopeToken};
use rand_core::RngCore;
use ulid::Ulid;

use super::SessionGrantMaterial;

pub(crate) async fn persist_session_grant_with_browser_session_id<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session_id: Option<Ulid>,
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    // The repository has no single-call insert: a grant only becomes durable as
    // the committed outcome of a reserved operation. Internal browser-session
    // entry points (password, passkey, debug seeds) therefore reserve and commit
    // here rather than carrying a second persistence path that bypasses the
    // ledger.
    //
    // The signed preimage fixes this internal operation's identity. Internal
    // callers sign fresh material once per login; they do not expose a replay
    // API. Reusing it after a committed outcome is a caller invariant failure.
    let request_identity = format!("internal-issue:{}", material.grant_id);
    let issuance_preimage: SessionGrantIssuancePreimage =
        serde_json::from_slice(&material.issuance_preimage)
            .expect("signed session grant material carries a validated issuance preimage");
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            rng,
            clock,
            coauth_data::NewSessionGrantOperation {
                issuer_id: material.issuer_id.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: issuance_preimage.proof_kind,
                request_identity: &request_identity,
                canonical_intent_digest: material.issuance_digest,
                canonical_intent: &material.issuance_preimage,
                target_session_grant_id: None,
                issuance_nonce: Some(&material.issuance_nonce),
                session_id: Some(&material.session_id),
                grant_not_before: Some(material.not_before_timestamp),
                grant_expires_at: Some(material.expires_at_timestamp),
                signing_key_id: Some(&material.signing_key_id),
                retained_until: material.expires_at_timestamp + chrono::Duration::days(7),
            },
        )
        .await?;

    let operation_id = match reserved {
        coauth_data::SessionGrantReserveOutcome::Reserved(operation)
        | coauth_data::SessionGrantReserveOutcome::Pending(operation) => operation.id,
        coauth_data::SessionGrantReserveOutcome::Replay(operation)
        | coauth_data::SessionGrantReserveOutcome::Conflict(operation)
        | coauth_data::SessionGrantReserveOutcome::Indeterminate(operation) => operation.id,
    };

    let checkpoint = serde_json::json!({
        "kind": "internal_browser_session_issue",
        "grant_id": material.grant_id,
    });
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            rng,
            clock,
            operation_id,
            coauth_data::SessionGrantProofAuthorization {
                authorization_ref: &request_identity,
                checkpoint: &checkpoint,
                proof_expires_at: material.expires_at_timestamp,
            },
            coauth_data::SessionGrantExactOutcome {
                canonical_response: &material.issuance_preimage,
                response_digest: material.issuance_digest,
            },
            new_session_grant_record(browser_session_id, material),
        )
        .await?;

    match committed {
        coauth_data::SessionGrantCommitOutcome::Committed(grant) => Ok(grant),
        coauth_data::SessionGrantCommitOutcome::Replay(operation)
        | coauth_data::SessionGrantCommitOutcome::Indeterminate(operation) => {
            // Each internal login signs fresh material, so its `grant_id` — and
            // therefore its request identity — is unique to this attempt. A
            // replay or tombstone here means the caller reused signed material
            // across two logical issuances, which would hand out one grant under
            // two identities.
            panic!(
                "internal browser-session issuance reused signed material: operation {} already \
                 holds an outcome for grant {}",
                operation.id, material.grant_id
            )
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
        .expect("signed session grant scopes must be valid OAuth scope tokens");

    NewSessionGrant {
        grant_id: material.grant_id.clone(),
        browser_session_id,
        issuer_id: &material.issuer_id,
        subject_id: &material.subject_id,
        local_account_id: &material.local_account_id,
        device_id: material.device_id.as_deref(),
        audience_id: &material.audience_id,
        scope,
        grant_jwt: &material.grant_jwt,
        session_id: &material.session_id,
        issuance_nonce: &material.issuance_nonce,
        issuance_preimage: &material.issuance_preimage,
        issuance_digest: material.issuance_digest,
        signing_key_id: &material.signing_key_id,
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

pub(crate) async fn persist_session_grant<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session: &BrowserSession,
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
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
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    persist_session_grant_with_browser_session_id(repo, rng, clock, None, material).await
}
