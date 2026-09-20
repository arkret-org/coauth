//! Atomic Account Authority issuer-ledger and durable publication boundary.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusInitialPublication, AccountStatusPublication, AccountStatusPublicationRequestBody,
};
use arkret_models_collaboration::account_status::{
    AccountStatusRecord, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{DidCoreId, Hash, SchemaId};
use coauth_data::queue::{AccountStatusPublicationJob, QueueJobRepositoryExt as _};
use coauth_data::{
    AccountStatusAppendOutcome, BoxRepository, Clock, LocalAccountId, PrincipalDidBinding,
    RepositoryAccess as _, RepositoryError, User,
};
use rand_core::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AccountStatusPublicationError {
    #[error("account-status publication idempotency key is empty")]
    EmptyIdempotencyKey,
    #[error("account-status publication body is invalid: {0}")]
    InvalidBody(String),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub struct AccountStatusPublicationPlan {
    pub audience_id: DidCoreId,
    pub destination_name: String,
    pub local_account_id: LocalAccountId,
    pub idempotency_key: String,
    pub body: AccountStatusPublicationRequestBody,
}

/// Author, append and enqueue one authoritative account-status transition.
///
/// Keeping issuer-ledger append and publication scheduling behind one boundary
/// prevents a caller from committing a signed successor without the exact
/// immutable bytes also entering the durable outbox. The caller may perform
/// the local account-row mutation and audit write before committing the shared
/// repository transaction.
#[allow(clippy::too_many_arguments)]
pub async fn author_and_enqueue_transition(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    station: &dyn coauth_principal::ConnectorAdmin,
    keyring: &coauth_keyring::Keyring,
    service_id: &str,
    user: &User,
    binding: &PrincipalDidBinding,
    target_status: AccountStatus,
    reason_code: Option<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AccountStatusPublicationPlan, AccountStatusPublicationError> {
    let (destination_name, audience) = station
        .account_status_destination()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    if audience != binding.audience_id {
        return Err(AccountStatusPublicationError::InvalidBody(
            "configured destination does not match the durable binding audience".to_owned(),
        ));
    }
    let account_authority_id = DidCoreId::new(service_id.to_owned())
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    if account_authority_id != binding.binding_receipt.account_authority_id {
        return Err(AccountStatusPublicationError::InvalidBody(
            "owning Station identity does not match the accepted account authority".to_owned(),
        ));
    }
    let local_account_id = LocalAccountId::new(user.id.to_string())
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let current = repo
        .account_status_ledger()
        .current(account_authority_id.as_str(), local_account_id.as_str())
        .await?;
    if let Some(head) = &current {
        if head.status != user.status {
            return Err(AccountStatusPublicationError::InvalidBody(
                "local account status diverges from the issuer-ledger head".to_owned(),
            ));
        }
        if !user.status.can_transition_to(target_status) {
            return Err(AccountStatusPublicationError::InvalidBody(
                "account_status_transition_invalid".to_owned(),
            ));
        }
    } else if target_status != AccountStatus::Active {
        return Err(AccountStatusPublicationError::InvalidBody(
            "the issuer ledger must begin with an active genesis record".to_owned(),
        ));
    }

    let unsigned = UnsignedAccountStatusRecord {
        schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
        account_authority_id: account_authority_id.clone(),
        account_id: arkret_wire::AccountId {
            principal_id: binding.account_id.principal_id.clone(),
            station_id: binding.account_id.station_id.clone(),
        },
        principal_control_realm_id: binding.principal_control_realm_id.clone(),
        binding_version: binding.binding_version,
        status_seq: current.as_ref().map_or(1, |head| head.status_seq + 1),
        previous_account_status_record_id: current
            .as_ref()
            .map(|head| head.account_status_record_id.clone()),
        status: target_status,
        reason_code,
        reason: None,
        issued_at: now,
        effective_at: now,
        expires_at: None,
    };
    let signing_seed = keyring
        .account_authority_seed()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let record = arkret_signatures::account_status::sign_account_status_record(
        unsigned,
        binding.binding_receipt.proof.verification_method.clone(),
        &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&signing_seed),
    )
    .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;

    match repo
        .account_status_ledger()
        .append(&local_account_id, &record)
        .await?
    {
        AccountStatusAppendOutcome::Appended => {}
        AccountStatusAppendOutcome::Duplicate => {
            return Err(AccountStatusPublicationError::InvalidBody(
                "new transition unexpectedly replayed an existing issuer record".to_owned(),
            ));
        }
        AccountStatusAppendOutcome::Conflict { .. } => {
            return Err(AccountStatusPublicationError::InvalidBody(
                "issuer-ledger current-head compare-and-swap failed".to_owned(),
            ));
        }
    }

    let idempotency_key = format!("account-status:{}", record.account_status_record_id);
    let body = AccountStatusPublicationRequestBody {
        publication: AccountStatusPublication::Initial(AccountStatusInitialPublication { record }),
    };
    body.validate_shape()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let plan = AccountStatusPublicationPlan {
        audience_id: audience,
        destination_name,
        local_account_id,
        idempotency_key,
        body,
    };
    enqueue_exact_publication(
        repo,
        rng,
        clock,
        &plan.destination_name,
        plan.local_account_id.clone(),
        &plan.idempotency_key,
        plan.body.clone(),
    )
    .await?;
    Ok(plan)
}

pub fn validate_transition_plan(
    user: &User,
    binding: &PrincipalDidBinding,
    target_status: AccountStatus,
    plan: &AccountStatusPublicationPlan,
) -> Result<(), AccountStatusPublicationError> {
    plan.body
        .validate_shape()
        .map_err(|error| AccountStatusPublicationError::InvalidBody(error.to_string()))?;
    let record: &AccountStatusRecord = plan.body.publication.record();
    if binding.user_id != user.id
        || binding.audience_id != plan.audience_id
        || binding.principal_id != record.account_id.principal_id
        || binding.account_id.station_id != record.account_id.station_id
        || binding.principal_control_realm_id != record.principal_control_realm_id
        || binding.binding_version != record.binding_version
        || binding.binding_receipt.account_authority_id != record.account_authority_id
        || plan.local_account_id.as_str() != user.id.to_string()
        || record.status != target_status
    {
        return Err(AccountStatusPublicationError::InvalidBody(
            "publication does not match the durable account authority binding".to_owned(),
        ));
    }
    Ok(())
}

async fn enqueue_exact_publication(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    destination_name: &str,
    local_account_id: LocalAccountId,
    idempotency_key: &str,
    body: AccountStatusPublicationRequestBody,
) -> Result<Hash, AccountStatusPublicationError> {
    if destination_name.trim().is_empty() {
        return Err(AccountStatusPublicationError::InvalidBody(
            "destination Station name is empty".to_owned(),
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
    repo.queue_job()
        .schedule_job(
            rng,
            clock,
            AccountStatusPublicationJob::new(
                destination_name.to_owned(),
                local_account_id,
                idempotency_key.to_owned(),
                body_digest.clone(),
                body,
            ),
        )
        .await?;
    Ok(body_digest)
}
