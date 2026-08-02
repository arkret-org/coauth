//! Fail-closed scheduling boundary for account-status publication.

use arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody;
use arkret_wire::Hash;
use coauth_data::queue::{AccountStatusPublicationJob, QueueJobRepositoryExt as _};
use coauth_data::{BoxRepository, Clock, RepositoryAccess as _, RepositoryError};
use rand_core::RngCore;
use thiserror::Error;

/// Errors that prevent a publication from entering the durable outbox.
#[derive(Debug, Error)]
pub enum AccountStatusPublicationError {
    #[error("account-status publication idempotency key is empty")]
    EmptyIdempotencyKey,
    #[error("account-status publication body is invalid: {0}")]
    InvalidBody(String),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Validate and atomically enqueue one immutable destination-scoped body.
///
/// Callers must author the complete signed Event and authority evidence before
/// entering this boundary. The queue worker retries these exact bytes; it never
/// rebuilds a body from mutable account state.
pub async fn enqueue_exact_publication(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    destination_name: &str,
    idempotency_key: &str,
    body: AccountStatusPublicationRequestBody,
) -> Result<Hash, AccountStatusPublicationError> {
    if destination_name.trim().is_empty() {
        return Err(AccountStatusPublicationError::InvalidBody(
            "destination Principal Server name is empty".to_owned(),
        ));
    }
    if idempotency_key.trim().is_empty() {
        return Err(AccountStatusPublicationError::EmptyIdempotencyKey);
    }
    body.validate_shape()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let body_digest = Hash::new(
        arkret_canonical::canonical_sha256(&body)
            .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?,
    )
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let job = AccountStatusPublicationJob::new(
        destination_name.to_owned(),
        idempotency_key.to_owned(),
        body_digest.clone(),
        body,
    );
    repo.queue_job().schedule_job(rng, clock, job).await?;
    Ok(body_digest)
}
