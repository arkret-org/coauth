//! PostgreSQL account-handoff state machine.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::account_handoff::{
    AccountHandoffCreation, AccountHandoffCreationAttempt, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffCreationAttemptState, AccountHandoffGrant,
    AccountHandoffGrantInput, DeviceBootstrapAcceptanceCommit, DeviceBootstrapCancelCommit,
    DeviceBootstrapCancelInput, DeviceBootstrapCancelOperation, DeviceBootstrapCancelReserve,
    DeviceBootstrapCancelReserveInput, DeviceBootstrapEnrollmentCommit,
    DeviceBootstrapEnrollmentInput, DeviceBootstrapEnrollmentReservationInput,
    DeviceBootstrapEnrollmentReserve, DeviceBootstrapTransaction, DeviceBootstrapTransactionCreate,
    DeviceBootstrapTransactionState, FirstDeviceEnrollmentCommit, FirstDeviceEnrollmentInput,
    IdentityBindingChallengeInput, IdentityBindingChallengeIssue, IdentityBindingChallengeRecord,
    IdentityCreationBindingCommit, IdentityCreationLeaseRecord, IdentityCreationRegisterLedger,
    IdentityCreationRegisterReplay, IdentityCreationRegistrationContext, IdentityCreationSagaState,
    NewAccountHandoffCreationAttempt, NewDeviceBootstrapTransaction,
};
use coauth_data::{AccountHandoffRepository, Ulid};
use diesel::OptionalExtension as _;
use diesel::prelude::*;
use diesel::sql_types::{
    Array, BigInt, Bytea, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::Digest as _;
use uuid::Uuid;

use crate::DatabaseError;

const ALLOWED_OPERATIONS: [&str; 3] = [
    "ak.gate.account.command.issue_identity_binding_challenge",
    "ak.gate.account.command.register",
    "ak.gate.account.command.issue_session_grant",
];

fn canonical_json_digest_matches(bytes: &[u8], expected: &arkret_identifiers::Hash) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Ok(canonical) = arkret_canonical::canonical_json_bytes(&value) else {
        return false;
    };
    canonical == bytes
        && expected.as_str() == format!("sha256:{:x}", sha2::Sha256::digest(bytes)).as_str()
}

fn canonical_device_enroll_outcome_matches(
    bytes: &[u8],
    expected: &arkret_identifiers::Hash,
) -> bool {
    let Ok(outcome) =
        serde_json::from_slice::<arkret_models_identity::AccountDeviceEnrollOutcome>(bytes)
    else {
        return false;
    };
    let Ok(canonical) = arkret_canonical::canonical_json_bytes(&outcome) else {
        return false;
    };
    canonical == bytes
        && outcome.outcome_digest == *expected
        && outcome.recompute_outcome_digest().ok().as_ref() == Some(expected)
}

fn canonical_device_enroll_request_matches(
    bytes: &[u8],
    expected: &arkret_identifiers::Hash,
) -> bool {
    let Ok(request) =
        serde_json::from_slice::<arkret_models_identity::AccountDeviceEnrollRequestBody>(bytes)
    else {
        return false;
    };
    let Ok(canonical) = arkret_canonical::canonical_json_bytes(&request) else {
        return false;
    };
    canonical == bytes && request.canonical_request_digest().ok().as_ref() == Some(expected)
}

fn device_bootstrap_request_matches_transaction(
    bytes: &[u8],
    input: &NewDeviceBootstrapTransaction,
) -> bool {
    let Ok(request) =
        serde_json::from_slice::<arkret_models_identity::AccountDeviceEnrollRequestBody>(bytes)
    else {
        return false;
    };
    let Ok(payload) = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
    >(serde_json::Value::Object(
        request
            .authorize_event_preimage
            .payload
            .clone()
            .into_iter()
            .collect(),
    )) else {
        return false;
    };
    let key_text = payload.device_public_key.as_str();
    let raw_key = arkret_canonical::decode_ed25519_multibase(key_text)
        .ok()
        .or_else(|| {
            arkret_canonical::base64url_decode(key_text)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        });
    request.device_id == input.device_id
        && request.authorize_event_preimage.actor_id == input.principal_id
        && payload.principal_id == input.principal_id
        && payload.device_id == input.device_id
        && request.authorize_event_preimage.prev_refs.as_slice()
            == [input.founding_event_ids[0].clone()]
        && request.authorize_event_preimage.event_id == input.founding_event_ids[1]
        && raw_key
            .and_then(|key| arkret_models_identity::device_bootstrap_device_key_digest(key).ok())
            .as_ref()
            == Some(&input.device_key_digest)
}

fn validate_device_bootstrap_decision_evidence(
    transaction: &DeviceBootstrapTransaction,
    evidence: &coauth_data::DeviceBootstrapDecisionEvidence,
    expected_decision: arkret_models_collaboration::contact_operations::DeviceBootstrapDecision,
) -> Result<(), DatabaseError> {
    validate_device_bootstrap_decision_request(transaction, &evidence.request)?;
    evidence
        .outcome
        .validate_against(&evidence.request)
        .map_err(|_| DatabaseError::invalid_operation())?;
    let canonical_receipt = arkret_canonical::canonical_json_bytes(&evidence.outcome.receipt)
        .map_err(|_| DatabaseError::invalid_operation())?;
    let receipt = &evidence.outcome.receipt;
    let decision_time_valid = receipt.decided_at >= transaction.created_at
        && match expected_decision {
            arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted => {
                receipt.decided_at <= transaction.expires_at
            }
            arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Cancelled => {
                receipt.decided_at < transaction.expires_at
            }
            arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Expired => {
                receipt.decided_at >= transaction.expires_at
            }
        };
    if evidence.outcome.decision != expected_decision
        || !decision_time_valid
        || canonical_receipt != evidence.canonical_receipt
        || receipt.principal_server_id.as_str().trim().is_empty()
        || receipt.principal_server_id != transaction.principal_server_id
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

fn validate_device_bootstrap_decision_request(
    transaction: &DeviceBootstrapTransaction,
    request: &arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
) -> Result<(), DatabaseError> {
    request
        .validate()
        .map_err(|_| DatabaseError::invalid_operation())?;
    let event_ids: [arkret_identifiers::EventId; 2] = transaction
        .founding_event_ids
        .clone()
        .try_into()
        .map_err(|_| DatabaseError::invalid_operation())?;
    if request.account_authority_id != transaction.account_authority_id
        || request.transaction_id != transaction.transaction_id
        || request.principal_id != transaction.principal_id
        || request.device_id != transaction.device_id
        || request.grant_id != transaction.bootstrap_grant_id
        || request.canonical_request_digest != transaction.canonical_request_digest
        || request.founding_event_ids != event_ids
        || request.founding_batch_digest != transaction.founding_batch_digest
        || request.bootstrap_transaction_expires_at != transaction.expires_at
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

/// PostgreSQL-backed account-handoff state machine.
pub struct PgAccountHandoffRepository<'c> {
    conn: &'c mut AsyncPgConnection,
}

impl<'c> PgAccountHandoffRepository<'c> {
    /// Create a repository over the caller's transaction connection.
    #[must_use]
    pub fn new(conn: &'c mut AsyncPgConnection) -> Self {
        Self { conn }
    }

    async fn creation_attempt(
        &mut self,
        request_id: Uuid,
        for_update: bool,
    ) -> Result<Option<AccountHandoffCreationAttempt>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, request_digest, canonical_intent_digest, canonical_intent, \
             holder_jkt, issuer, client_id, authorization_code_digest, dpop_jti_digest, state, \
             authorization_checkpoint, canonical_outcome, outcome_digest, retained_until, \
             created_at, authorized_at, committed_at FROM account_handoff_creation_attempts \
             WHERE request_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<SqlUuid, _>(request_id)
            .get_result::<HandoffCreationAttemptRow>(self.conn)
            .await
            .optional()?
            .map(creation_attempt_from_row)
            .transpose()
    }

    async fn device_bootstrap_transaction(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        for_update: bool,
    ) -> Result<Option<DeviceBootstrapTransaction>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT transaction_id, mode, account_authority_id, principal_server_id, principal_id, device_id, device_key_digest, holder_jkt, \
             canonical_request_digest, canonical_request, founding_batch_digest, founding_event_ids, \
             bootstrap_grant_id, state, enrollment_request_digest, canonical_enrollment_outcome, \
             enrollment_outcome_digest, authorized_event_id, authorized_event_digest, \
             standard_grant_id, expires_at, created_at, enrolled_at, accepted_at, cancelled_at, \
             expired_at, decision_principal_server_id, canonical_decision_receipt, \
             decision_receipt_digest FROM device_bootstrap_transactions \
             WHERE transaction_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<Text, _>(transaction_id.as_str())
            .get_result::<DeviceBootstrapTransactionRow>(self.conn)
            .await
            .optional()?
            .map(device_bootstrap_transaction_from_row)
            .transpose()
    }

    async fn device_bootstrap_cancel_operation(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        idempotency_key: &arkret_wire::IdempotencyKey,
        for_update: bool,
    ) -> Result<Option<DeviceBootstrapCancelOperation>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT transaction_id, idempotency_key, canonical_request_digest, canonical_request, \
             authority_request_digest, canonical_authority_request, requested_decision, \
             canonical_outcome, outcome_digest, created_at \
             FROM device_bootstrap_cancel_operations \
             WHERE transaction_id = $1 AND idempotency_key = $2{suffix}"
        );
        diesel::sql_query(query)
            .bind::<Text, _>(transaction_id.as_str())
            .bind::<Text, _>(idempotency_key.as_str())
            .get_result::<DeviceBootstrapCancelOperationRow>(self.conn)
            .await
            .optional()?
            .map(device_bootstrap_cancel_operation_from_row)
            .transpose()
    }

    async fn handoff_by_request_uuid(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<AccountHandoffGrant>, DatabaseError> {
        let row = diesel::sql_query(
            "SELECT id, request_id, request_digest, service_account_id, browser_session_id, \
             audience, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
             revoked_at, consumed_at FROM account_handoff_grants WHERE request_id = $1",
        )
        .bind::<SqlUuid, _>(request_id)
        .get_result::<HandoffRow>(self.conn)
        .await
        .optional()?;
        row.map(handoff_from_row).transpose()
    }

    async fn lease_for_account(
        &mut self,
        service_account_id: Uuid,
        audience: &str,
        for_update: bool,
    ) -> Result<Option<IdentityCreationLeaseRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT service_account_id, audience, lease_id, holder_jkt, fence, expires_at, \
             reserved_principal_id, reserved_operation_digest, did_operation, state, \
             registry_receipt, head_event_digest, binding_receipt, register_handoff_grant_id, \
             register_challenge_id, register_request_digest, register_outcome, created_at, updated_at \
             FROM identity_creation_leases WHERE service_account_id = $1 AND audience = $2{suffix}"
        );
        let row = diesel::sql_query(query)
            .bind::<SqlUuid, _>(service_account_id)
            .bind::<Text, _>(audience)
            .get_result::<LeaseRow>(self.conn)
            .await
            .optional()?;
        row.map(lease_from_row).transpose()
    }

    async fn bound_principal(
        &mut self,
        service_account_id: Uuid,
        audience: &str,
    ) -> Result<Option<arkret_identifiers::Did>, DatabaseError> {
        let row = diesel::sql_query(
            "SELECT owners.principal_id \
             FROM principal_did_bindings bindings \
             JOIN principal_did_owners owners ON owners.id = bindings.principal_did_owner_id \
             WHERE bindings.user_id = $1 AND bindings.audience = $2",
        )
        .bind::<SqlUuid, _>(service_account_id)
        .bind::<Text, _>(audience)
        .get_result::<PrincipalRow>(self.conn)
        .await
        .optional()?;
        row.map(|row| arkret_identifiers::Did::new(row.principal_id))
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())
    }

    async fn challenge_by_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<IdentityBindingChallengeRecord>, DatabaseError> {
        let row = diesel::sql_query(
            "SELECT request_id, request_digest, service_account_id, challenge_id, challenge, \
             purpose, principal_id, operation_digest, lease_id, lease_fence, dpop_jkt, audience, \
             origin, trust_domain, issued_at, expires_at, consumed_at, replaced_at \
             FROM identity_binding_challenges WHERE request_id = $1",
        )
        .bind::<SqlUuid, _>(request_id)
        .get_result::<ChallengeRow>(self.conn)
        .await
        .optional()?;
        row.map(challenge_from_row).transpose()
    }

    async fn challenge_by_id(
        &mut self,
        challenge_id: &str,
        for_update: bool,
    ) -> Result<Option<IdentityBindingChallengeRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, request_digest, service_account_id, challenge_id, challenge, \
             purpose, principal_id, operation_digest, lease_id, lease_fence, dpop_jkt, audience, \
             origin, trust_domain, issued_at, expires_at, consumed_at, replaced_at \
             FROM identity_binding_challenges WHERE challenge_id = $1{suffix}"
        );
        let row = diesel::sql_query(query)
            .bind::<Text, _>(challenge_id)
            .get_result::<ChallengeRow>(self.conn)
            .await
            .optional()?;
        row.map(challenge_from_row).transpose()
    }
}

#[derive(QueryableByName)]
struct PrincipalRow {
    #[diesel(sql_type = Text)]
    principal_id: String,
}

#[derive(QueryableByName)]
struct FirstDeviceEnrollmentRow {
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct HandoffRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = SqlUuid)]
    service_account_id: Uuid,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    browser_session_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Text)]
    cnf_jkt: String,
    #[diesel(sql_type = Array<Text>)]
    allowed_operations: Vec<String>,
    #[diesel(sql_type = Text)]
    account_handoff_grant: String,
    #[diesel(sql_type = Timestamptz)]
    issued_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct HandoffCreationAttemptRow {
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    canonical_intent_digest: String,
    #[diesel(sql_type = Bytea)]
    canonical_intent: Vec<u8>,
    #[diesel(sql_type = Text)]
    holder_jkt: String,
    #[diesel(sql_type = Text)]
    issuer: String,
    #[diesel(sql_type = Text)]
    client_id: String,
    #[diesel(sql_type = Text)]
    authorization_code_digest: String,
    #[diesel(sql_type = Text)]
    dpop_jti_digest: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    authorization_checkpoint: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Bytea>)]
    canonical_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    outcome_digest: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    retained_until: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    authorized_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    committed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, QueryableByName)]
struct DeviceBootstrapTransactionRow {
    #[diesel(sql_type = Text)]
    transaction_id: String,
    #[diesel(sql_type = Text)]
    mode: String,
    #[diesel(sql_type = Text)]
    account_authority_id: String,
    #[diesel(sql_type = Text)]
    principal_server_id: String,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    device_key_digest: String,
    #[diesel(sql_type = Text)]
    holder_jkt: String,
    #[diesel(sql_type = Text)]
    canonical_request_digest: String,
    #[diesel(sql_type = Bytea)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Text)]
    founding_batch_digest: String,
    #[diesel(sql_type = Array<Text>)]
    founding_event_ids: Vec<String>,
    #[diesel(sql_type = Text)]
    bootstrap_grant_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Text>)]
    enrollment_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Bytea>)]
    canonical_enrollment_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    enrollment_outcome_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    authorized_event_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    authorized_event_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    standard_grant_id: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    enrolled_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    accepted_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    cancelled_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expired_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    decision_principal_server_id: Option<String>,
    #[diesel(sql_type = Nullable<Bytea>)]
    canonical_decision_receipt: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    decision_receipt_digest: Option<String>,
}

#[derive(QueryableByName)]
struct DeviceBootstrapCancelOperationRow {
    #[diesel(sql_type = Text)]
    transaction_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    canonical_request_digest: String,
    #[diesel(sql_type = Bytea)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Text)]
    authority_request_digest: String,
    #[diesel(sql_type = Bytea)]
    canonical_authority_request: Vec<u8>,
    #[diesel(sql_type = Text)]
    requested_decision: String,
    #[diesel(sql_type = Nullable<Bytea>)]
    canonical_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    outcome_digest: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
}

fn device_bootstrap_cancel_operation_from_row(
    row: DeviceBootstrapCancelOperationRow,
) -> Result<DeviceBootstrapCancelOperation, DatabaseError> {
    let request = serde_json::from_slice::<
        arkret_models_collaboration::contact_operations::CancelDeviceBootstrapRequestBody,
    >(&row.canonical_request)
    .map_err(|_| DatabaseError::invalid_operation())?;
    if request
        .canonical_request_digest()
        .map_err(|_| DatabaseError::invalid_operation())?
        .as_str()
        != row.canonical_request_digest
        || arkret_canonical::canonical_json_bytes(&request)
            .map_err(|_| DatabaseError::invalid_operation())?
            != row.canonical_request
    {
        return Err(DatabaseError::invalid_operation());
    }
    let authority_request = serde_json::from_slice::<
        arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
    >(&row.canonical_authority_request)
    .map_err(|_| DatabaseError::invalid_operation())?;
    if authority_request.validate().is_err()
        || authority_request.decision_request_digest.as_str() != row.authority_request_digest
        || arkret_canonical::canonical_json_bytes(&authority_request)
            .map_err(|_| DatabaseError::invalid_operation())?
            != row.canonical_authority_request
        || match authority_request.requested_decision {
            arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Cancelled => "cancelled",
            arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Expired => "expired",
        } != row.requested_decision
    {
        return Err(DatabaseError::invalid_operation());
    }
    let outcome_digest = row
        .outcome_digest
        .as_deref()
        .map(arkret_identifiers::Hash::new)
        .transpose()
        .map_err(|_| DatabaseError::invalid_operation())?;
    match (row.canonical_outcome.as_deref(), outcome_digest.as_ref()) {
        (None, None) => {}
        (Some(bytes), Some(stored_digest)) => {
            if let Ok(outcome) = serde_json::from_slice::<
                arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome,
            >(bytes)
            {
                outcome
                    .validate_against(&request)
                    .map_err(|_| DatabaseError::invalid_operation())?;
                let embedded_digest = match &outcome {
                    arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Cancelled {
                        outcome_digest,
                        ..
                    }
                    | arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Expired {
                        outcome_digest,
                        ..
                    }
                    | arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Pending {
                        outcome_digest,
                        ..
                    } => outcome_digest,
                };
                if arkret_canonical::canonical_json_bytes(&outcome)
                    .map_err(|_| DatabaseError::invalid_operation())?
                    != bytes
                    || embedded_digest != stored_digest
                {
                    return Err(DatabaseError::invalid_operation());
                }
            } else {
                let envelope = serde_json::from_slice::<arkret_wire::ErrorEnvelope>(bytes)
                    .map_err(|_| DatabaseError::invalid_operation())?;
                let expected_plain_digest = format!("sha256:{:x}", sha2::Sha256::digest(bytes));
                if arkret_canonical::canonical_json_bytes(&envelope)
                    .map_err(|_| DatabaseError::invalid_operation())?
                    != bytes
                    || stored_digest.as_str() != expected_plain_digest
                    || envelope.code() != arkret_wire::ErrorCode::FAILED_PRECONDITION
                    || envelope.details().get("transaction_id")
                        != Some(&serde_json::Value::String(
                            request.transaction_id.as_str().to_owned(),
                        ))
                    || envelope.details().get("state")
                        != Some(&serde_json::Value::String("accepted".to_owned()))
                {
                    return Err(DatabaseError::invalid_operation());
                }
            }
        }
        _ => return Err(DatabaseError::invalid_operation()),
    }
    Ok(DeviceBootstrapCancelOperation {
        transaction_id: arkret_wire::ProtocolOpaqueId::new(row.transaction_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        idempotency_key: arkret_wire::IdempotencyKey::new(row.idempotency_key)
            .map_err(|_| DatabaseError::invalid_operation())?,
        canonical_request_digest: arkret_identifiers::Hash::new(row.canonical_request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        canonical_request: row.canonical_request,
        authority_request,
        canonical_authority_request: row.canonical_authority_request,
        canonical_outcome: row.canonical_outcome,
        outcome_digest,
        created_at: row.created_at,
    })
}

fn device_bootstrap_transaction_from_row(
    row: DeviceBootstrapTransactionRow,
) -> Result<DeviceBootstrapTransaction, DatabaseError> {
    let founding_event_ids = row
        .founding_event_ids
        .into_iter()
        .map(arkret_identifiers::EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DatabaseError::invalid_operation())?;
    let founding_batch_digest = arkret_identifiers::Hash::new(row.founding_batch_digest)
        .map_err(|_| DatabaseError::invalid_operation())?;
    let canonical_request_digest = arkret_identifiers::Hash::new(row.canonical_request_digest)
        .map_err(|_| DatabaseError::invalid_operation())?;
    let state = DeviceBootstrapTransactionState::try_from(row.state.as_str())
        .map_err(|_| DatabaseError::invalid_operation())?;
    let decision_principal_server_id = row
        .decision_principal_server_id
        .map(arkret_identifiers::Did::new)
        .transpose()
        .map_err(|_| DatabaseError::invalid_operation())?;
    let decision_receipt_digest = row
        .decision_receipt_digest
        .map(arkret_identifiers::Hash::new)
        .transpose()
        .map_err(|_| DatabaseError::invalid_operation())?;
    match (
        state,
        decision_principal_server_id.as_ref(),
        row.canonical_decision_receipt.as_ref(),
        decision_receipt_digest.as_ref(),
    ) {
        (DeviceBootstrapTransactionState::Pending, None, None, None) => {}
        (terminal, Some(principal_server_id), Some(bytes), Some(digest)) => {
            let receipt = serde_json::from_slice::<
                arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionReceipt,
            >(bytes)
            .map_err(|_| DatabaseError::invalid_operation())?;
            let expected_decision = match terminal {
                DeviceBootstrapTransactionState::Accepted => arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted,
                DeviceBootstrapTransactionState::Cancelled => arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Cancelled,
                DeviceBootstrapTransactionState::Expired => arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Expired,
                DeviceBootstrapTransactionState::Pending => return Err(DatabaseError::invalid_operation()),
            };
            let decision_time_valid = receipt.decided_at >= row.created_at
                && match expected_decision {
                    arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted => receipt.decided_at <= row.expires_at,
                    arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Cancelled => receipt.decided_at < row.expires_at,
                    arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Expired => receipt.decided_at >= row.expires_at,
                };
            let lifecycle_time_valid = match terminal {
                DeviceBootstrapTransactionState::Accepted => {
                    row.accepted_at == Some(receipt.decided_at)
                        && row.cancelled_at.is_none()
                        && row.expired_at.is_none()
                }
                DeviceBootstrapTransactionState::Cancelled => {
                    row.cancelled_at == Some(receipt.decided_at)
                        && row.accepted_at.is_none()
                        && row.expired_at.is_none()
                }
                DeviceBootstrapTransactionState::Expired => {
                    row.expired_at == Some(row.expires_at)
                        && row.accepted_at.is_none()
                        && row.cancelled_at.is_none()
                }
                DeviceBootstrapTransactionState::Pending => false,
            };
            if arkret_canonical::canonical_json_bytes(&receipt)
                .map_err(|_| DatabaseError::invalid_operation())?
                != *bytes
                || !decision_time_valid
                || !lifecycle_time_valid
                || receipt.validate().is_err()
                || receipt.decision != expected_decision
                || receipt.principal_server_id != *principal_server_id
                || receipt.receipt_digest != *digest
                || receipt.transaction_id.as_str() != row.transaction_id
                || receipt.account_authority_id.as_str() != row.account_authority_id
                || receipt.principal_id.as_str() != row.principal_id
                || receipt.device_id.as_str() != row.device_id
                || receipt.grant_id.as_str() != row.bootstrap_grant_id
                || receipt.canonical_request_digest != canonical_request_digest
                || receipt.founding_event_ids.as_slice() != founding_event_ids.as_slice()
                || receipt.founding_batch_digest != founding_batch_digest
                || receipt.bootstrap_transaction_expires_at != row.expires_at
            {
                return Err(DatabaseError::invalid_operation());
            }
        }
        _ => return Err(DatabaseError::invalid_operation()),
    }
    if arkret_models_identity::founding_batch_digest(&founding_event_ids)
        .map_err(|_| DatabaseError::invalid_operation())?
        != founding_batch_digest
        || !canonical_device_enroll_request_matches(
            &row.canonical_request,
            &canonical_request_digest,
        )
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(DeviceBootstrapTransaction {
        transaction_id: arkret_wire::ProtocolOpaqueId::new(row.transaction_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        mode: match row.mode.as_str() {
            "founding" => arkret_models_collaboration::contact_operations::BootstrapMode::Founding,
            "sibling_pairing" => {
                arkret_models_collaboration::contact_operations::BootstrapMode::SiblingPairing
            }
            _ => return Err(DatabaseError::invalid_operation()),
        },
        account_authority_id: arkret_identifiers::Did::new(row.account_authority_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        principal_server_id: arkret_identifiers::Did::new(row.principal_server_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        principal_id: arkret_identifiers::Did::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        device_id: arkret_identifiers::DeviceId::new(row.device_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        device_key_digest: arkret_identifiers::Hash::new(row.device_key_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        holder_jkt: row.holder_jkt,
        canonical_request_digest,
        canonical_request: row.canonical_request,
        founding_batch_digest,
        founding_event_ids,
        bootstrap_grant_id: arkret_identifiers::SessionGrantId::new(row.bootstrap_grant_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        state,
        enrollment_request_digest: row
            .enrollment_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        canonical_enrollment_outcome: row.canonical_enrollment_outcome,
        enrollment_outcome_digest: row
            .enrollment_outcome_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        authorized_event_id: row
            .authorized_event_id
            .map(arkret_identifiers::EventId::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        authorized_event_digest: row
            .authorized_event_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        standard_grant_id: row
            .standard_grant_id
            .map(arkret_identifiers::SessionGrantId::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        expires_at: row.expires_at,
        created_at: row.created_at,
        enrolled_at: row.enrolled_at,
        accepted_at: row.accepted_at,
        cancelled_at: row.cancelled_at,
        expired_at: row.expired_at,
        decision_principal_server_id,
        canonical_decision_receipt: row.canonical_decision_receipt,
        decision_receipt_digest,
    })
}

fn creation_attempt_from_row(
    row: HandoffCreationAttemptRow,
) -> Result<AccountHandoffCreationAttempt, DatabaseError> {
    Ok(AccountHandoffCreationAttempt {
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))
            .map_err(|_| DatabaseError::invalid_operation())?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        canonical_intent_digest: arkret_identifiers::Hash::new(row.canonical_intent_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        canonical_intent: row.canonical_intent,
        holder_jkt: row.holder_jkt,
        issuer: row.issuer,
        client_id: row.client_id,
        authorization_code_digest: arkret_identifiers::Hash::new(row.authorization_code_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        dpop_jti_digest: arkret_identifiers::Hash::new(row.dpop_jti_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        state: AccountHandoffCreationAttemptState::try_from(row.state.as_str())
            .map_err(|_| DatabaseError::invalid_operation())?,
        authorization_checkpoint: row.authorization_checkpoint,
        canonical_outcome: row.canonical_outcome,
        outcome_digest: row
            .outcome_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        retained_until: row.retained_until,
        created_at: row.created_at,
        authorized_at: row.authorized_at,
        committed_at: row.committed_at,
    })
}

fn handoff_from_row(row: HandoffRow) -> Result<AccountHandoffGrant, DatabaseError> {
    if row
        .allowed_operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != ALLOWED_OPERATIONS
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(AccountHandoffGrant {
        id: Ulid::from(row.id),
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))
            .map_err(|_| DatabaseError::invalid_operation())?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        service_account_id: Ulid::from(row.service_account_id),
        browser_session_id: row.browser_session_id.map(Ulid::from),
        audience: row.audience,
        cnf_jkt: row.cnf_jkt,
        allowed_operations: arkret_models_identity::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
        account_handoff_grant: row.account_handoff_grant,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
        consumed_at: row.consumed_at,
    })
}

#[derive(QueryableByName)]
struct LeaseRow {
    #[diesel(sql_type = SqlUuid)]
    service_account_id: Uuid,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Text)]
    lease_id: String,
    #[diesel(sql_type = Text)]
    holder_jkt: String,
    #[diesel(sql_type = BigInt)]
    fence: i64,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    reserved_principal_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    reserved_operation_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    did_operation: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    registry_receipt: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    head_event_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    binding_receipt: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    register_handoff_grant_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    register_challenge_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    register_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    register_outcome: Option<serde_json::Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

fn lease_from_row(row: LeaseRow) -> Result<IdentityCreationLeaseRecord, DatabaseError> {
    let reserved_identity = match (
        row.reserved_principal_id,
        row.reserved_operation_digest,
        row.did_operation,
    ) {
        (None, None, None) => None,
        (Some(principal_id), Some(operation_digest), Some(did_operation)) => {
            Some(arkret_models_identity::ReservedIdentityCreation {
                principal_id: arkret_identifiers::Did::new(principal_id)
                    .map_err(|_| DatabaseError::invalid_operation())?,
                operation_digest: arkret_identifiers::Hash::new(operation_digest)
                    .map_err(|_| DatabaseError::invalid_operation())?,
                did_operation: serde_json::from_value(did_operation)
                    .map_err(|_| DatabaseError::invalid_operation())?,
            })
        }
        _ => return Err(DatabaseError::invalid_operation()),
    };
    let register_ledger = match (
        row.register_handoff_grant_id,
        row.register_challenge_id,
        row.register_request_digest,
        row.register_outcome,
    ) {
        (None, None, None, None) => None,
        (Some(handoff_grant_id), Some(challenge_id), Some(request_digest), Some(outcome)) => {
            Some(IdentityCreationRegisterLedger {
                handoff_grant_id: Ulid::from(handoff_grant_id),
                challenge_id,
                request_digest: arkret_identifiers::Hash::new(request_digest)
                    .map_err(|_| DatabaseError::invalid_operation())?,
                outcome: serde_json::from_value(outcome)
                    .map_err(|_| DatabaseError::invalid_operation())?,
            })
        }
        _ => return Err(DatabaseError::invalid_operation()),
    };
    Ok(IdentityCreationLeaseRecord {
        service_account_id: Ulid::from(row.service_account_id),
        audience: row.audience,
        lease_id: row.lease_id,
        holder_jkt: row.holder_jkt,
        fence: u64::try_from(row.fence).map_err(|_| DatabaseError::invalid_operation())?,
        expires_at: row.expires_at,
        reserved_identity,
        state: IdentityCreationSagaState::try_from(row.state.as_str())
            .map_err(|_| DatabaseError::invalid_operation())?,
        registry_receipt: row.registry_receipt,
        head_event_digest: row
            .head_event_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        binding_receipt: row
            .binding_receipt
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        register_ledger,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

#[derive(QueryableByName)]
struct ChallengeRow {
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = SqlUuid)]
    service_account_id: Uuid,
    #[diesel(sql_type = Text)]
    challenge_id: String,
    #[diesel(sql_type = Text)]
    challenge: String,
    #[diesel(sql_type = Text)]
    purpose: String,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    operation_digest: String,
    #[diesel(sql_type = Text)]
    lease_id: String,
    #[diesel(sql_type = BigInt)]
    lease_fence: i64,
    #[diesel(sql_type = Text)]
    dpop_jkt: String,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Text)]
    origin: String,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = Timestamptz)]
    issued_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    replaced_at: Option<DateTime<Utc>>,
}

fn challenge_from_row(row: ChallengeRow) -> Result<IdentityBindingChallengeRecord, DatabaseError> {
    if row.purpose != "account_binding" {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(IdentityBindingChallengeRecord {
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))
            .map_err(|_| DatabaseError::invalid_operation())?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        service_account_id: Ulid::from(row.service_account_id),
        challenge_id: row.challenge_id,
        challenge: row.challenge,
        purpose: arkret_models_identity::IdentityBindingPurpose::AccountBinding,
        principal_id: arkret_identifiers::Did::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        operation_digest: arkret_identifiers::Hash::new(row.operation_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        lease_id: row.lease_id,
        lease_fence: u64::try_from(row.lease_fence)
            .map_err(|_| DatabaseError::invalid_operation())?,
        dpop_jkt: row.dpop_jkt,
        audience: arkret_identifiers::Did::new(row.audience)
            .map_err(|_| DatabaseError::invalid_operation())?,
        origin: row.origin,
        trust_domain: arkret_identifiers::TypedTrustDomainId::new(row.trust_domain)
            .map_err(|_| DatabaseError::invalid_operation())?,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        consumed_at: row.consumed_at,
        replaced_at: row.replaced_at,
    })
}

fn challenge_matches_context(
    challenge: &IdentityBindingChallengeRecord,
    context: &IdentityCreationRegistrationContext,
) -> bool {
    let expected = &context.challenge;
    challenge.request_id == expected.request_id
        && challenge.request_digest == expected.request_digest
        && challenge.service_account_id == context.grant.service_account_id
        && challenge.challenge_id == expected.challenge_id
        && challenge.challenge == expected.challenge
        && challenge.purpose == expected.purpose
        && challenge.principal_id == expected.principal_id
        && challenge.operation_digest == expected.operation_digest
        && challenge.lease_id == context.lease.lease_id
        && challenge.lease_fence == context.lease.fence
        && challenge.dpop_jkt == context.grant.cnf_jkt
        && challenge.audience.as_str() == context.grant.audience
        && challenge.origin == expected.origin
        && challenge.trust_domain == expected.trust_domain
        && challenge.issued_at == expected.issued_at
        && challenge.expires_at == expected.expires_at
}

fn retry_after_ms(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    u64::try_from((expires_at - now).num_milliseconds().max(1)).unwrap_or(u64::MAX)
}

#[async_trait]
impl AccountHandoffRepository for PgAccountHandoffRepository<'_> {
    type Error = DatabaseError;

    async fn reserve_creation_attempt(
        &mut self,
        input: NewAccountHandoffCreationAttempt,
    ) -> Result<AccountHandoffCreationAttemptReserve, Self::Error> {
        if !canonical_json_digest_matches(&input.canonical_intent, &input.canonical_intent_digest)
            || input.retained_until <= input.now
        {
            return Err(DatabaseError::invalid_operation());
        }
        let inserted = diesel::sql_query(
            "INSERT INTO account_handoff_creation_attempts \
             (request_id, request_digest, canonical_intent_digest, canonical_intent, holder_jkt, \
              issuer, client_id, authorization_code_digest, dpop_jti_digest, state, \
              retained_until, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'reserved', $10, $11) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<Text, _>(input.canonical_intent_digest.as_str())
        .bind::<Bytea, _>(&input.canonical_intent)
        .bind::<Text, _>(&input.holder_jkt)
        .bind::<Text, _>(&input.issuer)
        .bind::<Text, _>(&input.client_id)
        .bind::<Text, _>(input.authorization_code_digest.as_str())
        .bind::<Text, _>(input.dpop_jti_digest.as_str())
        .bind::<Timestamptz, _>(input.retained_until)
        .bind::<Timestamptz, _>(input.now)
        .execute(self.conn)
        .await?
            == 1;
        let attempt = self
            .creation_attempt(input.request_id.uuid(), true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if attempt.canonical_intent_digest != input.canonical_intent_digest {
            return Ok(AccountHandoffCreationAttemptReserve::Conflict(attempt));
        }
        if attempt.retained_until <= input.now {
            return Ok(AccountHandoffCreationAttemptReserve::Indeterminate(attempt));
        }
        if inserted {
            return Ok(AccountHandoffCreationAttemptReserve::Reserved(attempt));
        }
        Ok(match attempt.state {
            AccountHandoffCreationAttemptState::Committed => {
                AccountHandoffCreationAttemptReserve::Replay(attempt)
            }
            AccountHandoffCreationAttemptState::Reserved
            | AccountHandoffCreationAttemptState::Authorized => {
                AccountHandoffCreationAttemptReserve::Pending(attempt)
            }
        })
    }

    async fn checkpoint_creation_authorization(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        checkpoint: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreationAttemptCommit, Self::Error> {
        let attempt = self
            .creation_attempt(request_id.uuid(), true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if attempt.canonical_intent_digest != *canonical_intent_digest {
            return Ok(AccountHandoffCreationAttemptCommit::Conflict(attempt));
        }
        if attempt.retained_until <= now {
            return Ok(AccountHandoffCreationAttemptCommit::Indeterminate(attempt));
        }
        match attempt.state {
            AccountHandoffCreationAttemptState::Committed => {
                return Ok(AccountHandoffCreationAttemptCommit::Replay(attempt));
            }
            AccountHandoffCreationAttemptState::Authorized => {
                return if attempt.authorization_checkpoint.as_ref() == Some(checkpoint) {
                    Ok(AccountHandoffCreationAttemptCommit::Committed(attempt))
                } else {
                    Ok(AccountHandoffCreationAttemptCommit::Conflict(attempt))
                };
            }
            AccountHandoffCreationAttemptState::Reserved => {}
        }
        diesel::sql_query(
            "UPDATE account_handoff_creation_attempts SET state = 'authorized', \
             authorization_checkpoint = $3, authorized_at = $4 \
             WHERE request_id = $1 AND canonical_intent_digest = $2 AND state = 'reserved'",
        )
        .bind::<SqlUuid, _>(request_id.uuid())
        .bind::<Text, _>(canonical_intent_digest.as_str())
        .bind::<Jsonb, _>(checkpoint)
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        let attempt = self
            .creation_attempt(request_id.uuid(), false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(AccountHandoffCreationAttemptCommit::Committed(attempt))
    }

    async fn commit_creation_attempt(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        canonical_outcome: &[u8],
        outcome_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreationAttemptCommit, Self::Error> {
        if !canonical_json_digest_matches(canonical_outcome, outcome_digest) {
            return Err(DatabaseError::invalid_operation());
        }
        let attempt = self
            .creation_attempt(request_id.uuid(), true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if attempt.canonical_intent_digest != *canonical_intent_digest {
            return Ok(AccountHandoffCreationAttemptCommit::Conflict(attempt));
        }
        if attempt.retained_until <= now {
            return Ok(AccountHandoffCreationAttemptCommit::Indeterminate(attempt));
        }
        match attempt.state {
            AccountHandoffCreationAttemptState::Committed => {
                return if attempt.canonical_outcome.as_deref() == Some(canonical_outcome)
                    && attempt.outcome_digest.as_ref() == Some(outcome_digest)
                {
                    Ok(AccountHandoffCreationAttemptCommit::Replay(attempt))
                } else {
                    Ok(AccountHandoffCreationAttemptCommit::Conflict(attempt))
                };
            }
            AccountHandoffCreationAttemptState::Reserved => {
                return Ok(AccountHandoffCreationAttemptCommit::Indeterminate(attempt));
            }
            AccountHandoffCreationAttemptState::Authorized => {}
        }
        diesel::sql_query(
            "UPDATE account_handoff_creation_attempts SET state = 'committed', \
             canonical_outcome = $3, outcome_digest = $4, committed_at = $5 \
             WHERE request_id = $1 AND canonical_intent_digest = $2 AND state = 'authorized'",
        )
        .bind::<SqlUuid, _>(request_id.uuid())
        .bind::<Text, _>(canonical_intent_digest.as_str())
        .bind::<Bytea, _>(canonical_outcome)
        .bind::<Text, _>(outcome_digest.as_str())
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        let attempt = self
            .creation_attempt(request_id.uuid(), false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(AccountHandoffCreationAttemptCommit::Committed(attempt))
    }

    async fn create_device_bootstrap_transaction(
        &mut self,
        input: NewDeviceBootstrapTransaction,
    ) -> Result<DeviceBootstrapTransactionCreate, Self::Error> {
        if input.mode != arkret_models_collaboration::contact_operations::BootstrapMode::Founding
            || input.expires_at <= input.now
            || arkret_models_identity::founding_batch_digest(&input.founding_event_ids)
                .map_err(|_| DatabaseError::invalid_operation())?
                != input.founding_batch_digest
            || !canonical_device_enroll_request_matches(
                &input.canonical_request,
                &input.canonical_request_digest,
            )
            || !device_bootstrap_request_matches_transaction(&input.canonical_request, &input)
        {
            return Err(DatabaseError::invalid_operation());
        }

        let inserted = diesel::sql_query(
            "INSERT INTO device_bootstrap_transactions \
             (transaction_id, mode, account_authority_id, principal_server_id, principal_id, device_id, device_key_digest, holder_jkt, \
              canonical_request_digest, canonical_request, founding_batch_digest, founding_event_ids, \
              bootstrap_grant_id, state, expires_at, created_at) \
             VALUES ($1, 'founding', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', $13, $14) \
             ON CONFLICT (transaction_id) DO NOTHING",
        )
        .bind::<Text, _>(input.transaction_id.as_str())
        .bind::<Text, _>(input.account_authority_id.as_str())
        .bind::<Text, _>(input.principal_server_id.as_str())
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(input.device_id.as_str())
        .bind::<Text, _>(input.device_key_digest.as_str())
        .bind::<Text, _>(&input.holder_jkt)
        .bind::<Text, _>(input.canonical_request_digest.as_str())
        .bind::<Bytea, _>(&input.canonical_request)
        .bind::<Text, _>(input.founding_batch_digest.as_str())
        .bind::<Array<Text>, _>(
            input
                .founding_event_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .bind::<Text, _>(input.bootstrap_grant_id.as_str())
        .bind::<Timestamptz, _>(input.expires_at)
        .bind::<Timestamptz, _>(input.now)
        .execute(self.conn)
        .await?;

        let stored = self
            .device_bootstrap_transaction(&input.transaction_id, true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        let exact = stored.principal_id == input.principal_id
            && stored.mode == input.mode
            && stored.account_authority_id == input.account_authority_id
            && stored.principal_server_id == input.principal_server_id
            && stored.device_id == input.device_id
            && stored.device_key_digest == input.device_key_digest
            && stored.holder_jkt == input.holder_jkt
            && stored.canonical_request_digest == input.canonical_request_digest
            && stored.canonical_request == input.canonical_request
            && stored.founding_batch_digest == input.founding_batch_digest
            && stored.founding_event_ids == input.founding_event_ids
            && stored.bootstrap_grant_id == input.bootstrap_grant_id
            && stored.expires_at == input.expires_at;
        if !exact {
            return Ok(DeviceBootstrapTransactionCreate::Conflict(stored));
        }
        if inserted == 1 {
            Ok(DeviceBootstrapTransactionCreate::Created(stored))
        } else {
            Ok(DeviceBootstrapTransactionCreate::Replay(stored))
        }
    }

    async fn get_device_bootstrap_transaction(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
    ) -> Result<Option<DeviceBootstrapTransaction>, Self::Error> {
        self.device_bootstrap_transaction(transaction_id, false)
            .await
    }

    async fn reserve_device_bootstrap_enrollment(
        &mut self,
        input: DeviceBootstrapEnrollmentReservationInput<'_>,
    ) -> Result<DeviceBootstrapEnrollmentReserve, Self::Error> {
        let Some(mut stored) = self
            .device_bootstrap_transaction(input.transaction_id, true)
            .await?
        else {
            return Ok(DeviceBootstrapEnrollmentReserve::NotFound);
        };
        if stored.principal_id != *input.principal_id
            || stored.device_id != *input.device_id
            || stored.canonical_request_digest != *input.request_digest
        {
            return Ok(DeviceBootstrapEnrollmentReserve::Conflict(stored));
        }
        if stored.canonical_enrollment_outcome.is_some() {
            return Ok(DeviceBootstrapEnrollmentReserve::Replay(stored));
        }
        match stored.state {
            DeviceBootstrapTransactionState::Cancelled => {
                return Ok(DeviceBootstrapEnrollmentReserve::Cancelled(stored));
            }
            DeviceBootstrapTransactionState::Expired => {
                return Ok(DeviceBootstrapEnrollmentReserve::Expired(stored));
            }
            DeviceBootstrapTransactionState::Accepted => {
                return Err(DatabaseError::invalid_operation());
            }
            DeviceBootstrapTransactionState::Pending => {}
        }
        if stored.expires_at <= input.now {
            return Ok(DeviceBootstrapEnrollmentReserve::RequiresDecision(stored));
        }
        Ok(DeviceBootstrapEnrollmentReserve::Reserved(stored))
    }

    async fn commit_device_bootstrap_enrollment(
        &mut self,
        input: DeviceBootstrapEnrollmentInput<'_>,
    ) -> Result<DeviceBootstrapEnrollmentCommit, Self::Error> {
        let Some(mut stored) = self
            .device_bootstrap_transaction(input.transaction_id, true)
            .await?
        else {
            return Ok(DeviceBootstrapEnrollmentCommit::NotFound);
        };
        let identity_matches = stored.principal_id == *input.principal_id
            && stored.device_id == *input.device_id
            && stored.canonical_request_digest == *input.request_digest;
        if !identity_matches {
            return Ok(DeviceBootstrapEnrollmentCommit::Conflict(stored));
        }

        if stored.canonical_enrollment_outcome.is_some() {
            // The transaction/request identity is already matched above. A concurrent loser may
            // have produced a different authority proof timestamp, but it must replay the unique
            // winner's durable bytes instead of turning the same logical request into a conflict.
            return Ok(DeviceBootstrapEnrollmentCommit::Replay(stored));
        }

        match stored.state {
            DeviceBootstrapTransactionState::Cancelled => {
                return Ok(DeviceBootstrapEnrollmentCommit::Cancelled(stored));
            }
            DeviceBootstrapTransactionState::Expired => {
                return Ok(DeviceBootstrapEnrollmentCommit::Expired(stored));
            }
            DeviceBootstrapTransactionState::Accepted => {
                return Err(DatabaseError::invalid_operation());
            }
            DeviceBootstrapTransactionState::Pending => {}
        }
        if stored.expires_at <= input.now {
            return Ok(DeviceBootstrapEnrollmentCommit::RequiresDecision(stored));
        }
        if !canonical_device_enroll_outcome_matches(input.canonical_outcome, input.outcome_digest) {
            return Err(DatabaseError::invalid_operation());
        }
        let outcome = serde_json::from_slice::<arkret_models_identity::AccountDeviceEnrollOutcome>(
            input.canonical_outcome,
        )
        .map_err(|_| DatabaseError::invalid_operation())?;
        let request = serde_json::from_slice::<
            arkret_models_identity::AccountDeviceEnrollRequestBody,
        >(&stored.canonical_request)
        .map_err(|_| DatabaseError::invalid_operation())?;
        if outcome.bootstrap_transaction_id != stored.transaction_id
            || outcome.principal_id != *input.principal_id
            || outcome.device_id != *input.device_id
            || outcome.authorized_event_id != *input.authorized_event_id
            || outcome.authorized_event_digest != *input.authorized_event_digest
            || outcome.outcome_digest != *input.outcome_digest
            || outcome.validate_against(&request).is_err()
        {
            return Err(DatabaseError::invalid_operation());
        }

        let updated = diesel::sql_query(
            "UPDATE device_bootstrap_transactions SET enrollment_request_digest = $1, \
             canonical_enrollment_outcome = $2, enrollment_outcome_digest = $3, \
             authorized_event_id = $4, authorized_event_digest = $5, enrolled_at = $6 \
             WHERE transaction_id = $7 AND state = 'pending' \
             AND enrollment_request_digest IS NULL AND expires_at > $6",
        )
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<Bytea, _>(input.canonical_outcome)
        .bind::<Text, _>(input.outcome_digest.as_str())
        .bind::<Text, _>(input.authorized_event_id.as_str())
        .bind::<Text, _>(input.authorized_event_digest.as_str())
        .bind::<Timestamptz, _>(input.now)
        .bind::<Text, _>(input.transaction_id.as_str())
        .execute(self.conn)
        .await?;
        if updated != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        let committed = self
            .device_bootstrap_transaction(input.transaction_id, true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(DeviceBootstrapEnrollmentCommit::Committed(committed))
    }

    async fn commit_device_bootstrap_cancel(
        &mut self,
        input: DeviceBootstrapCancelInput,
    ) -> Result<DeviceBootstrapCancelCommit, Self::Error> {
        let recomputed_request_digest = input
            .request
            .canonical_request_digest()
            .map_err(|_| DatabaseError::invalid_operation())?;
        if recomputed_request_digest != input.canonical_request_digest
            || arkret_canonical::canonical_json_bytes(&input.request)
                .map_err(|_| DatabaseError::invalid_operation())?
                != input.canonical_request
        {
            return Err(DatabaseError::invalid_operation());
        }
        if let Some(operation) = self
            .device_bootstrap_cancel_operation(
                &input.request.transaction_id,
                &input.request.idempotency_key,
                true,
            )
            .await?
        {
            if operation.canonical_request_digest != input.canonical_request_digest
                || operation.canonical_request != input.canonical_request
                || operation.authority_request != input.authority.request
            {
                return Ok(DeviceBootstrapCancelCommit::Conflict);
            }
            if operation.canonical_outcome.is_some() {
                return Ok(DeviceBootstrapCancelCommit::Replay(operation));
            }
        }

        let Some(mut transaction) = self
            .device_bootstrap_transaction(&input.request.transaction_id, true)
            .await?
        else {
            return Ok(DeviceBootstrapCancelCommit::NotFound);
        };
        if let Some(operation) = self
            .device_bootstrap_cancel_operation(
                &input.request.transaction_id,
                &input.request.idempotency_key,
                false,
            )
            .await?
        {
            if operation.canonical_request_digest != input.canonical_request_digest
                || operation.canonical_request != input.canonical_request
                || operation.authority_request != input.authority.request
            {
                return Ok(DeviceBootstrapCancelCommit::Conflict);
            }
            if operation.canonical_outcome.is_some() {
                return Ok(DeviceBootstrapCancelCommit::Replay(operation));
            }
        }
        if transaction.mode != input.request.mode
            || transaction.canonical_request_digest != input.request.canonical_request_digest
        {
            return Ok(DeviceBootstrapCancelCommit::Conflict);
        }
        match transaction.state {
            DeviceBootstrapTransactionState::Accepted
                if matches!(
                    input.decision,
                    coauth_data::DeviceBootstrapCancelDecision::Accept
                ) => {}
            DeviceBootstrapTransactionState::Accepted => {
                return Ok(DeviceBootstrapCancelCommit::Accepted(transaction));
            }
            DeviceBootstrapTransactionState::Cancelled
                if matches!(
                    input.decision,
                    coauth_data::DeviceBootstrapCancelDecision::Cancel
                ) => {}
            DeviceBootstrapTransactionState::Cancelled => {
                return Ok(DeviceBootstrapCancelCommit::Cancelled(transaction));
            }
            DeviceBootstrapTransactionState::Expired
                if matches!(
                    input.decision,
                    coauth_data::DeviceBootstrapCancelDecision::Expire
                ) => {}
            DeviceBootstrapTransactionState::Expired => {
                return Ok(DeviceBootstrapCancelCommit::Expired(transaction));
            }
            DeviceBootstrapTransactionState::Pending => {}
        }

        let placeholder = arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("placeholder digest has a valid wire shape");
        let expected_decision = match input.decision {
            coauth_data::DeviceBootstrapCancelDecision::Accept => {
                arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted
            }
            coauth_data::DeviceBootstrapCancelDecision::Cancel => {
                arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Cancelled
            }
            coauth_data::DeviceBootstrapCancelDecision::Expire => {
                arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Expired
            }
        };
        validate_device_bootstrap_decision_evidence(
            &transaction,
            &input.authority,
            expected_decision,
        )?;
        if transaction.state != DeviceBootstrapTransactionState::Pending
            && (transaction.decision_principal_server_id.as_ref()
                != Some(&input.authority.outcome.receipt.principal_server_id)
                || transaction.canonical_decision_receipt.as_deref()
                    != Some(input.authority.canonical_receipt.as_slice())
                || transaction.decision_receipt_digest.as_ref()
                    != Some(&input.authority.outcome.receipt.receipt_digest))
        {
            return Ok(DeviceBootstrapCancelCommit::Conflict);
        }
        let accepting = matches!(
            input.decision,
            coauth_data::DeviceBootstrapCancelDecision::Accept
        );
        let expiring = matches!(
            input.decision,
            coauth_data::DeviceBootstrapCancelDecision::Expire
        );
        let (canonical_outcome, outcome_digest) = if accepting {
            let envelope = arkret_wire::ErrorEnvelope::new(
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "founding bootstrap transaction is already accepted",
            )
            .with_detail(
                "transaction_id",
                serde_json::Value::String(input.request.transaction_id.as_str().to_owned()),
            )
            .with_detail("state", serde_json::Value::String("accepted".to_owned()));
            let bytes = arkret_canonical::canonical_json_bytes(&envelope)
                .map_err(|_| DatabaseError::invalid_operation())?;
            let digest =
                arkret_identifiers::Hash::new(format!("sha256:{:x}", sha2::Sha256::digest(&bytes)))
                    .map_err(|_| DatabaseError::invalid_operation())?;
            (bytes, digest)
        } else {
            let mut outcome = if expiring {
                arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Expired {
                transaction_id: input.request.transaction_id.clone(),
                expired_at: transaction.expires_at,
                outcome_digest: placeholder,
            }
            } else {
                arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Cancelled {
                transaction_id: input.request.transaction_id.clone(),
                outcome_digest: placeholder,
            }
            };
            let outcome_digest = outcome
                .recompute_outcome_digest()
                .map_err(|_| DatabaseError::invalid_operation())?;
            match &mut outcome {
                arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Cancelled {
                    outcome_digest: slot,
                    ..
                }
                | arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Expired {
                    outcome_digest: slot,
                    ..
                }
                | arkret_models_collaboration::contact_operations::CancelDeviceBootstrapOutcome::Pending {
                    outcome_digest: slot,
                    ..
                } => *slot = outcome_digest.clone(),
            }
            outcome
                .validate_against(&input.request)
                .map_err(|_| DatabaseError::invalid_operation())?;
            let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
                .map_err(|_| DatabaseError::invalid_operation())?;
            (canonical_outcome, outcome_digest)
        };

        if accepting {
            diesel::sql_query(
                "UPDATE device_bootstrap_transactions SET state = 'accepted', accepted_at = $1, \
                 decision_principal_server_id = $3, canonical_decision_receipt = $4, \
                 decision_receipt_digest = $5 \
                 WHERE transaction_id = $2 AND state = 'pending'",
            )
            .bind::<Timestamptz, _>(input.authority.outcome.receipt.decided_at)
            .bind::<Text, _>(input.request.transaction_id.as_str())
            .bind::<Text, _>(input.authority.outcome.receipt.principal_server_id.as_str())
            .bind::<Bytea, _>(&input.authority.canonical_receipt)
            .bind::<Text, _>(input.authority.outcome.receipt.receipt_digest.as_str())
            .execute(self.conn)
            .await?;
        } else if expiring {
            diesel::sql_query(
                "UPDATE device_bootstrap_transactions SET state = 'expired', expired_at = $1, \
                 decision_principal_server_id = $3, canonical_decision_receipt = $4, \
                 decision_receipt_digest = $5 \
                 WHERE transaction_id = $2 AND state = 'pending'",
            )
            .bind::<Timestamptz, _>(transaction.expires_at)
            .bind::<Text, _>(input.request.transaction_id.as_str())
            .bind::<Text, _>(input.authority.outcome.receipt.principal_server_id.as_str())
            .bind::<Bytea, _>(&input.authority.canonical_receipt)
            .bind::<Text, _>(input.authority.outcome.receipt.receipt_digest.as_str())
            .execute(self.conn)
            .await?;
        } else {
            diesel::sql_query(
                "UPDATE device_bootstrap_transactions SET state = 'cancelled', cancelled_at = $1, \
                 decision_principal_server_id = $3, canonical_decision_receipt = $4, \
                 decision_receipt_digest = $5 \
                 WHERE transaction_id = $2 AND state = 'pending'",
            )
            .bind::<Timestamptz, _>(input.authority.outcome.receipt.decided_at)
            .bind::<Text, _>(input.request.transaction_id.as_str())
            .bind::<Text, _>(input.authority.outcome.receipt.principal_server_id.as_str())
            .bind::<Bytea, _>(&input.authority.canonical_receipt)
            .bind::<Text, _>(input.authority.outcome.receipt.receipt_digest.as_str())
            .execute(self.conn)
            .await?;
        }
        let completed = diesel::sql_query(
            "UPDATE device_bootstrap_cancel_operations SET canonical_outcome = $1, \
             outcome_digest = $2 WHERE transaction_id = $3 AND idempotency_key = $4 \
             AND canonical_outcome IS NULL AND outcome_digest IS NULL",
        )
        .bind::<Bytea, _>(&canonical_outcome)
        .bind::<Text, _>(outcome_digest.as_str())
        .bind::<Text, _>(input.request.transaction_id.as_str())
        .bind::<Text, _>(input.request.idempotency_key.as_str())
        .execute(self.conn)
        .await?;
        if completed != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        let operation = self
            .device_bootstrap_cancel_operation(
                &input.request.transaction_id,
                &input.request.idempotency_key,
                false,
            )
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        transaction = self
            .device_bootstrap_transaction(&input.request.transaction_id, false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(DeviceBootstrapCancelCommit::Committed {
            transaction,
            operation,
        })
    }

    async fn reserve_device_bootstrap_cancel(
        &mut self,
        input: DeviceBootstrapCancelReserveInput,
    ) -> Result<DeviceBootstrapCancelReserve, Self::Error> {
        let recomputed_request_digest = input
            .request
            .canonical_request_digest()
            .map_err(|_| DatabaseError::invalid_operation())?;
        if recomputed_request_digest != input.canonical_request_digest
            || arkret_canonical::canonical_json_bytes(&input.request)
                .map_err(|_| DatabaseError::invalid_operation())?
                != input.canonical_request
            || arkret_canonical::canonical_json_bytes(&input.authority_request)
                .map_err(|_| DatabaseError::invalid_operation())?
                != input.canonical_authority_request
        {
            return Err(DatabaseError::invalid_operation());
        }
        if let Some(operation) = self
            .device_bootstrap_cancel_operation(
                &input.request.transaction_id,
                &input.request.idempotency_key,
                true,
            )
            .await?
        {
            return if operation.canonical_request_digest == input.canonical_request_digest
                && operation.canonical_request == input.canonical_request
            {
                Ok(DeviceBootstrapCancelReserve::Replay(operation))
            } else {
                Ok(DeviceBootstrapCancelReserve::Conflict)
            };
        }
        let Some(transaction) = self
            .device_bootstrap_transaction(&input.request.transaction_id, true)
            .await?
        else {
            return Ok(DeviceBootstrapCancelReserve::NotFound);
        };
        if transaction.mode != input.request.mode
            || transaction.canonical_request_digest != input.request.canonical_request_digest
        {
            return Ok(DeviceBootstrapCancelReserve::Conflict);
        }
        if transaction.state != DeviceBootstrapTransactionState::Pending {
            return Ok(DeviceBootstrapCancelReserve::Terminal(transaction));
        }
        validate_device_bootstrap_decision_request(&transaction, &input.authority_request)?;
        let requested_decision = match input.authority_request.requested_decision {
            arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Cancelled => "cancelled",
            arkret_models_collaboration::contact_operations::RequestedDeviceBootstrapDecision::Expired => "expired",
        };
        diesel::sql_query(
            "INSERT INTO device_bootstrap_cancel_operations \
             (transaction_id, idempotency_key, canonical_request_digest, canonical_request, \
              authority_request_digest, canonical_authority_request, requested_decision, \
              canonical_outcome, outcome_digest, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, $8) \
             ON CONFLICT (transaction_id, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(input.request.transaction_id.as_str())
        .bind::<Text, _>(input.request.idempotency_key.as_str())
        .bind::<Text, _>(input.canonical_request_digest.as_str())
        .bind::<Bytea, _>(&input.canonical_request)
        .bind::<Text, _>(input.authority_request.decision_request_digest.as_str())
        .bind::<Bytea, _>(&input.canonical_authority_request)
        .bind::<Text, _>(requested_decision)
        .bind::<Timestamptz, _>(input.now)
        .execute(self.conn)
        .await?;
        let operation = self
            .device_bootstrap_cancel_operation(
                &input.request.transaction_id,
                &input.request.idempotency_key,
                false,
            )
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if operation.canonical_request_digest != input.canonical_request_digest
            || operation.canonical_request != input.canonical_request
        {
            Ok(DeviceBootstrapCancelReserve::Conflict)
        } else {
            Ok(DeviceBootstrapCancelReserve::Reserved(operation))
        }
    }

    async fn get_device_bootstrap_cancel_operation(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        idempotency_key: &arkret_wire::IdempotencyKey,
    ) -> Result<Option<DeviceBootstrapCancelOperation>, Self::Error> {
        self.device_bootstrap_cancel_operation(transaction_id, idempotency_key, false)
            .await
    }

    async fn mark_device_bootstrap_accepted(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        authorized_event_id: &arkret_identifiers::EventId,
        device_key_digest: &arkret_identifiers::Hash,
        authority: coauth_data::DeviceBootstrapDecisionEvidence,
    ) -> Result<DeviceBootstrapAcceptanceCommit, Self::Error> {
        let Some(transaction) = self
            .device_bootstrap_transaction(transaction_id, true)
            .await?
        else {
            return Ok(DeviceBootstrapAcceptanceCommit::NotFound);
        };
        if transaction.authorized_event_id.as_ref() != Some(authorized_event_id)
            || transaction.device_key_digest != *device_key_digest
            || transaction.canonical_enrollment_outcome.is_none()
        {
            return Ok(DeviceBootstrapAcceptanceCommit::Conflict(transaction));
        }
        match transaction.state {
            DeviceBootstrapTransactionState::Accepted => {
                return if validate_device_bootstrap_decision_evidence(
                    &transaction,
                    &authority,
                    arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted,
                )
                .is_ok()
                    && transaction.canonical_decision_receipt.as_deref()
                        == Some(authority.canonical_receipt.as_slice())
                {
                    Ok(DeviceBootstrapAcceptanceCommit::Replay(transaction))
                } else {
                    Ok(DeviceBootstrapAcceptanceCommit::Conflict(transaction))
                };
            }
            DeviceBootstrapTransactionState::Cancelled => {
                return Ok(DeviceBootstrapAcceptanceCommit::Cancelled(transaction));
            }
            DeviceBootstrapTransactionState::Expired => {
                return Ok(DeviceBootstrapAcceptanceCommit::Expired(transaction));
            }
            DeviceBootstrapTransactionState::Pending => {}
        }
        validate_device_bootstrap_decision_evidence(
            &transaction,
            &authority,
            arkret_models_collaboration::contact_operations::DeviceBootstrapDecision::Accepted,
        )?;
        let updated = diesel::sql_query(
            "UPDATE device_bootstrap_transactions SET state = 'accepted', accepted_at = $1, \
             decision_principal_server_id = $5, canonical_decision_receipt = $6, \
             decision_receipt_digest = $7 \
             WHERE transaction_id = $2 AND state = 'pending' \
             AND authorized_event_id = $3 AND device_key_digest = $4",
        )
        .bind::<Timestamptz, _>(authority.outcome.receipt.decided_at)
        .bind::<Text, _>(transaction_id.as_str())
        .bind::<Text, _>(authorized_event_id.as_str())
        .bind::<Text, _>(device_key_digest.as_str())
        .bind::<Text, _>(authority.outcome.receipt.principal_server_id.as_str())
        .bind::<Bytea, _>(&authority.canonical_receipt)
        .bind::<Text, _>(authority.outcome.receipt.receipt_digest.as_str())
        .execute(self.conn)
        .await?;
        if updated != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        let accepted = self
            .device_bootstrap_transaction(transaction_id, false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(DeviceBootstrapAcceptanceCommit::Accepted(accepted))
    }

    async fn get_by_request_id(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error> {
        self.handoff_by_request_uuid(request_id.uuid()).await
    }

    async fn get_active_by_token(
        &mut self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error> {
        let row = diesel::sql_query(
            "SELECT id, request_id, request_digest, service_account_id, browser_session_id, \
             audience, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
             revoked_at, consumed_at FROM account_handoff_grants \
             WHERE account_handoff_grant = $1 AND expires_at > $2 \
             AND revoked_at IS NULL AND consumed_at IS NULL",
        )
        .bind::<Text, _>(token)
        .bind::<Timestamptz, _>(now)
        .get_result::<HandoffRow>(self.conn)
        .await
        .optional()?;
        row.map(handoff_from_row).transpose()
    }

    async fn create_with_lease(
        &mut self,
        input: AccountHandoffGrantInput,
    ) -> Result<AccountHandoffCreation, Self::Error> {
        diesel::sql_query(
            "INSERT INTO account_handoff_grants \
             (id, request_id, request_digest, service_account_id, browser_session_id, audience, \
              cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.id))
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Nullable<SqlUuid>, _>(input.browser_session_id.map(Uuid::from))
        .bind::<Text, _>(&input.audience)
        .bind::<Text, _>(&input.cnf_jkt)
        .bind::<Array<Text>, _>(ALLOWED_OPERATIONS.to_vec())
        .bind::<Text, _>(&input.account_handoff_grant)
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<Timestamptz, _>(input.expires_at)
        .execute(self.conn)
        .await?;

        let grant = self
            .handoff_by_request_uuid(input.request_id.uuid())
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if grant.request_digest != input.request_digest
            || grant.service_account_id != input.service_account_id
            || grant.audience != input.audience
            || grant.cnf_jkt != input.cnf_jkt
        {
            return Ok(AccountHandoffCreation::DuplicateConflict);
        }
        if grant.expires_at <= input.issued_at
            || grant.revoked_at.is_some()
            || grant.consumed_at.is_some()
        {
            return Ok(AccountHandoffCreation::ExpiredReplay);
        }

        if let Some(principal_id) = self
            .bound_principal(Uuid::from(input.service_account_id), &input.audience)
            .await?
        {
            return Ok(AccountHandoffCreation::Bound {
                grant,
                principal_id,
            });
        }

        diesel::sql_query(
            "INSERT INTO identity_creation_leases \
             (service_account_id, audience, lease_id, holder_jkt, fence, expires_at, state, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 1, $5, 'active', $6, $6) \
             ON CONFLICT (service_account_id, audience) DO NOTHING",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(&input.audience)
        .bind::<Text, _>(&input.lease_id)
        .bind::<Text, _>(&input.cnf_jkt)
        .bind::<Timestamptz, _>(input.lease_expires_at)
        .bind::<Timestamptz, _>(input.issued_at)
        .execute(self.conn)
        .await?;

        let mut lease = self
            .lease_for_account(Uuid::from(input.service_account_id), &input.audience, true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if lease.state == IdentityCreationSagaState::Bound {
            let principal_id = lease
                .reserved_identity
                .as_ref()
                .map(|reserved| reserved.principal_id.clone())
                .ok_or_else(DatabaseError::invalid_operation)?;
            return Ok(AccountHandoffCreation::Bound {
                grant,
                principal_id,
            });
        }
        if lease.expires_at > input.issued_at && lease.holder_jkt != input.cnf_jkt {
            return Ok(AccountHandoffCreation::Busy {
                grant,
                retry_after_ms: retry_after_ms(lease.expires_at, input.issued_at),
            });
        }

        if lease.expires_at <= input.issued_at {
            diesel::sql_query(
                "UPDATE identity_creation_leases SET lease_id = $3, holder_jkt = $4, \
                 fence = fence + 1, expires_at = $5, updated_at = $6 \
                 WHERE service_account_id = $1 AND audience = $2",
            )
            .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
            .bind::<Text, _>(&input.audience)
            .bind::<Text, _>(&input.lease_id)
            .bind::<Text, _>(&input.cnf_jkt)
            .bind::<Timestamptz, _>(input.lease_expires_at)
            .bind::<Timestamptz, _>(input.issued_at)
            .execute(self.conn)
            .await?;
        } else {
            diesel::sql_query(
                "UPDATE identity_creation_leases SET expires_at = GREATEST(expires_at, $3), \
                 updated_at = $4 WHERE service_account_id = $1 AND audience = $2 \
                 AND holder_jkt = $5",
            )
            .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
            .bind::<Text, _>(&input.audience)
            .bind::<Timestamptz, _>(input.lease_expires_at)
            .bind::<Timestamptz, _>(input.issued_at)
            .bind::<Text, _>(&input.cnf_jkt)
            .execute(self.conn)
            .await?;
        }
        lease = self
            .lease_for_account(Uuid::from(input.service_account_id), &input.audience, false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(AccountHandoffCreation::Active {
            grant,
            lease: Box::new(lease),
        })
    }

    async fn resolve_creation(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreation, Self::Error> {
        if grant.expires_at <= now || grant.revoked_at.is_some() || grant.consumed_at.is_some() {
            return Ok(AccountHandoffCreation::ExpiredReplay);
        }
        if let Some(principal_id) = self
            .bound_principal(Uuid::from(grant.service_account_id), &grant.audience)
            .await?
        {
            return Ok(AccountHandoffCreation::Bound {
                grant: grant.clone(),
                principal_id,
            });
        }
        let lease = self
            .lease_for_account(Uuid::from(grant.service_account_id), &grant.audience, false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if lease.state == IdentityCreationSagaState::Bound {
            let principal_id = lease
                .reserved_identity
                .as_ref()
                .map(|reserved| reserved.principal_id.clone())
                .ok_or_else(DatabaseError::invalid_operation)?;
            return Ok(AccountHandoffCreation::Bound {
                grant: grant.clone(),
                principal_id,
            });
        }
        if lease.expires_at <= now {
            return Ok(AccountHandoffCreation::ExpiredReplay);
        }
        if lease.holder_jkt == grant.cnf_jkt {
            Ok(AccountHandoffCreation::Active {
                grant: grant.clone(),
                lease: Box::new(lease),
            })
        } else {
            Ok(AccountHandoffCreation::Busy {
                grant: grant.clone(),
                retry_after_ms: retry_after_ms(lease.expires_at, now),
            })
        }
    }

    async fn reserve_and_issue_challenge(
        &mut self,
        input: IdentityBindingChallengeInput,
    ) -> Result<IdentityBindingChallengeIssue, Self::Error> {
        // These timestamps are replayed verbatim in the client-signed control
        // proof. Canonical wire serialization uses fixed millisecond precision,
        // so persist that same value rather than PostgreSQL's finer-grained
        // representation; otherwise the proof can never equal the durable row.
        let input = IdentityBindingChallengeInput {
            issued_at: arkret_canonical::normalize_timestamp_canonical(input.issued_at),
            expires_at: arkret_canonical::normalize_timestamp_canonical(input.expires_at),
            lease_expires_at: arkret_canonical::normalize_timestamp_canonical(
                input.lease_expires_at,
            ),
            ..input
        };
        if let Some(existing) = self.challenge_by_request(input.request_id.uuid()).await? {
            if existing.request_digest != input.request_digest
                || existing.service_account_id != input.service_account_id
            {
                return Ok(IdentityBindingChallengeIssue::DuplicateConflict);
            }
            if existing.consumed_at.is_some()
                || existing.replaced_at.is_some()
                || existing.expires_at <= input.issued_at
            {
                return Ok(IdentityBindingChallengeIssue::StaleRequest);
            }
            return Ok(IdentityBindingChallengeIssue::Replay(existing));
        }

        let lease = self
            .lease_for_account(Uuid::from(input.service_account_id), &input.audience, true)
            .await?;
        let Some(lease) = lease else {
            return Ok(IdentityBindingChallengeIssue::LeaseMismatch);
        };
        if lease.lease_id != input.lease_id
            || lease.fence != input.lease_fence
            || lease.holder_jkt != input.holder_jkt
            || lease.expires_at <= input.issued_at
            || lease.state == IdentityCreationSagaState::Bound
        {
            return Ok(IdentityBindingChallengeIssue::LeaseMismatch);
        }

        let reserved = arkret_models_identity::ReservedIdentityCreation::from_operation(
            input.did_operation.clone(),
        )
        .map_err(|_| DatabaseError::invalid_operation())?;
        if reserved.operation_digest != input.operation_digest {
            return Ok(IdentityBindingChallengeIssue::ReservationConflict);
        }
        if let Some(existing) = lease.reserved_identity.as_ref()
            && existing != &reserved
        {
            return Ok(IdentityBindingChallengeIssue::ReservationConflict);
        }

        diesel::sql_query(
            "UPDATE identity_creation_leases SET reserved_principal_id = $3, \
             reserved_operation_digest = $4, did_operation = $5, \
             state = CASE WHEN state = 'published' THEN state ELSE 'reserved' END, \
             expires_at = GREATEST(expires_at, $6), updated_at = $7 \
             WHERE service_account_id = $1 AND audience = $2 AND lease_id = $8 \
             AND fence = $9 AND holder_jkt = $10 \
             AND state IN ('active', 'reserved', 'published')",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(&input.audience)
        .bind::<Text, _>(reserved.principal_id.as_str())
        .bind::<Text, _>(reserved.operation_digest.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&reserved.did_operation)
                .map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Timestamptz, _>(input.lease_expires_at)
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(input.lease_fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(&input.holder_jkt)
        .execute(self.conn)
        .await?;

        diesel::sql_query(
            "UPDATE identity_binding_challenges SET replaced_at = $1 \
             WHERE service_account_id = $2 AND audience = $3 AND lease_id = $4 \
             AND lease_fence = $5 AND operation_digest = $6 \
             AND consumed_at IS NULL AND replaced_at IS NULL AND expires_at > $1",
        )
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(&input.audience)
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(input.lease_fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(input.operation_digest.as_str())
        .execute(self.conn)
        .await?;

        diesel::sql_query(
            "INSERT INTO identity_binding_challenges \
             (request_id, request_digest, service_account_id, challenge_id, challenge, purpose, \
              principal_id, operation_digest, lease_id, lease_fence, dpop_jkt, audience, origin, \
              trust_domain, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'account_binding', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(&input.challenge_id)
        .bind::<Text, _>(&input.challenge)
        .bind::<Text, _>(reserved.principal_id.as_str())
        .bind::<Text, _>(input.operation_digest.as_str())
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(i64::try_from(input.lease_fence).map_err(|_| DatabaseError::invalid_operation())?)
        .bind::<Text, _>(&input.holder_jkt)
        .bind::<Text, _>(&input.audience)
        .bind::<Text, _>(&input.origin)
        .bind::<Text, _>(input.trust_domain.as_str())
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<Timestamptz, _>(input.expires_at)
        .execute(self.conn)
        .await?;
        let challenge = self
            .challenge_by_request(input.request_id.uuid())
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if challenge.request_digest != input.request_digest
            || challenge.service_account_id != input.service_account_id
        {
            return Ok(IdentityBindingChallengeIssue::DuplicateConflict);
        }
        Ok(IdentityBindingChallengeIssue::Issued(challenge))
    }

    async fn registration_context(
        &mut self,
        grant: &AccountHandoffGrant,
        lease_id: &str,
        lease_fence: u64,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<IdentityCreationRegistrationContext>, Self::Error> {
        let Some(lease) = self
            .lease_for_account(Uuid::from(grant.service_account_id), &grant.audience, true)
            .await?
        else {
            return Ok(None);
        };
        if lease.lease_id != lease_id
            || lease.fence != lease_fence
            || lease.holder_jkt != grant.cnf_jkt
            || lease.expires_at <= now
        {
            return Ok(None);
        }
        let Some(challenge) = self.challenge_by_id(challenge_id, false).await? else {
            return Ok(None);
        };
        if challenge.service_account_id != grant.service_account_id
            || challenge.audience.as_str() != grant.audience
            || challenge.lease_id != lease_id
            || challenge.lease_fence != lease_fence
            || challenge.dpop_jkt != grant.cnf_jkt
            || challenge.replaced_at.is_some()
            || challenge.expires_at <= now
            || !registration_challenge_state_is_usable(lease.state, challenge.consumed_at.is_some())
        {
            return Ok(None);
        }
        Ok(Some(IdentityCreationRegistrationContext {
            grant: grant.clone(),
            lease,
            challenge,
        }))
    }

    async fn registration_replay(
        &mut self,
        grant: &AccountHandoffGrant,
        lease_id: &str,
        lease_fence: u64,
        challenge_id: &str,
        request_digest: &arkret_identifiers::Hash,
    ) -> Result<IdentityCreationRegisterReplay, Self::Error> {
        let Some(lease) = self
            // Serialize with the final binding transaction so a concurrent
            // retry cannot observe Published immediately before Bound commits.
            .lease_for_account(Uuid::from(grant.service_account_id), &grant.audience, true)
            .await?
        else {
            return Ok(IdentityCreationRegisterReplay::Pending);
        };
        if lease.state != IdentityCreationSagaState::Bound {
            return Ok(IdentityCreationRegisterReplay::Pending);
        }
        let Some(ledger) = lease.register_ledger else {
            // Rows bound before the replay ledger migration cannot prove that
            // an incoming body is byte-for-byte the completed request.
            return Ok(IdentityCreationRegisterReplay::DuplicateConflict);
        };
        if lease.lease_id != lease_id
            || lease.fence != lease_fence
            || lease.holder_jkt != grant.cnf_jkt
            || ledger.challenge_id != challenge_id
            || ledger.request_digest != *request_digest
        {
            return Ok(IdentityCreationRegisterReplay::DuplicateConflict);
        }
        Ok(IdentityCreationRegisterReplay::Replay(Box::new(
            ledger.outcome,
        )))
    }

    async fn mark_published(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        registry_receipt: &serde_json::Value,
        head_event_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(context.grant.service_account_id),
                &context.grant.audience,
                true,
            )
            .await?
        else {
            return Ok(false);
        };
        if lease.lease_id != context.lease.lease_id
            || lease.fence != context.lease.fence
            || lease.holder_jkt != context.grant.cnf_jkt
            || lease.reserved_identity.as_ref().is_none_or(|reserved| {
                reserved.operation_digest != context.challenge.operation_digest
            })
            || !matches!(
                lease.state,
                IdentityCreationSagaState::Reserved | IdentityCreationSagaState::Published
            )
        {
            return Ok(false);
        }
        let Some(challenge) = self
            .challenge_by_id(&context.challenge.challenge_id, true)
            .await?
        else {
            return Ok(false);
        };
        if !challenge_matches_context(&challenge, context) || challenge.replaced_at.is_some() {
            return Ok(false);
        }
        match (context.lease.state, lease.state) {
            (IdentityCreationSagaState::Reserved, IdentityCreationSagaState::Reserved) => {
                if challenge.consumed_at.is_some() {
                    return Ok(false);
                }
                let consumed = diesel::sql_query(
                    "UPDATE identity_binding_challenges SET consumed_at = $1 \
                     WHERE challenge_id = $2 AND consumed_at IS NULL AND replaced_at IS NULL",
                )
                .bind::<Timestamptz, _>(now)
                .bind::<Text, _>(&context.challenge.challenge_id)
                .execute(self.conn)
                .await?;
                if consumed != 1 {
                    return Ok(false);
                }
            }
            (IdentityCreationSagaState::Published, IdentityCreationSagaState::Published) => {
                if challenge.consumed_at.is_none() {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'published', registry_receipt = $1, \
             head_event_digest = $2, updated_at = $3 \
             WHERE service_account_id = $4 AND audience = $5 AND lease_id = $6 AND fence = $7 \
             AND holder_jkt = $8 AND reserved_operation_digest = $9 \
             AND state IN ('reserved', 'published')",
        )
        .bind::<Jsonb, _>(registry_receipt)
        .bind::<Text, _>(head_event_digest.as_str())
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.service_account_id))
        .bind::<Text, _>(&context.grant.audience)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(context.lease.fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .bind::<Text, _>(context.challenge.operation_digest.as_str())
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }

    async fn mark_bound(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        binding_receipt: &arkret_models_identity::AccountBindingReceipt,
        request_digest: &arkret_identifiers::Hash,
        outcome: &arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
        now: DateTime<Utc>,
    ) -> Result<IdentityCreationBindingCommit, Self::Error> {
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(context.grant.service_account_id),
                &context.grant.audience,
                true,
            )
            .await?
        else {
            return Ok(IdentityCreationBindingCommit::Stale);
        };
        if lease.lease_id != context.lease.lease_id
            || lease.fence != context.lease.fence
            || lease.holder_jkt != context.grant.cnf_jkt
        {
            return Ok(IdentityCreationBindingCommit::Stale);
        }
        if lease.state == IdentityCreationSagaState::Bound {
            let Some(ledger) = lease.register_ledger else {
                return Ok(IdentityCreationBindingCommit::DuplicateConflict);
            };
            if ledger.challenge_id == context.challenge.challenge_id
                && ledger.request_digest == *request_digest
            {
                return Ok(IdentityCreationBindingCommit::Replay(Box::new(
                    ledger.outcome,
                )));
            }
            return Ok(IdentityCreationBindingCommit::DuplicateConflict);
        }
        if lease.state != IdentityCreationSagaState::Published
            || lease.reserved_identity.as_ref().is_none_or(|reserved| {
                reserved.operation_digest != context.challenge.operation_digest
            })
        {
            return Ok(IdentityCreationBindingCommit::Stale);
        }
        let Some(challenge) = self
            .challenge_by_id(&context.challenge.challenge_id, true)
            .await?
        else {
            return Ok(IdentityCreationBindingCommit::Stale);
        };
        if !challenge_matches_context(&challenge, context)
            || challenge.consumed_at.is_none()
            || challenge.replaced_at.is_some()
        {
            return Ok(IdentityCreationBindingCommit::Stale);
        }

        let receipt = serde_json::to_value(binding_receipt)
            .map_err(|_| DatabaseError::invalid_operation())?;
        let outcome =
            serde_json::to_value(outcome).map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'bound', binding_receipt = $1, \
             register_handoff_grant_id = $2, register_challenge_id = $3, \
             register_request_digest = $4, register_outcome = $5, updated_at = $6 \
             WHERE service_account_id = $7 AND audience = $8 \
             AND lease_id = $9 AND fence = $10 AND holder_jkt = $11 \
             AND reserved_operation_digest = $12 AND state = 'published'",
        )
        .bind::<Jsonb, _>(receipt)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.id))
        .bind::<Text, _>(&context.challenge.challenge_id)
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Jsonb, _>(outcome)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.service_account_id))
        .bind::<Text, _>(&context.grant.audience)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(context.lease.fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .bind::<Text, _>(context.challenge.operation_digest.as_str())
        .execute(self.conn)
        .await?;
        Ok(if updated == 1 {
            IdentityCreationBindingCommit::Committed
        } else {
            IdentityCreationBindingCommit::Stale
        })
    }

    async fn commit_first_device_enrollment(
        &mut self,
        input: FirstDeviceEnrollmentInput<'_>,
    ) -> Result<FirstDeviceEnrollmentCommit, Self::Error> {
        let FirstDeviceEnrollmentInput {
            service_account_id,
            audience,
            principal_id,
            device_id,
            request_digest,
            outcome,
            now,
        } = input;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET first_device_id = $1, \
             first_device_request_digest = $2, first_device_outcome = $3, \
             first_device_enrolled_at = $4, updated_at = $4 \
             WHERE service_account_id = $5 AND audience = $6 AND state = 'bound' \
             AND binding_receipt IS NOT NULL AND reserved_principal_id = $7 \
             AND first_device_id IS NULL AND first_device_enrolled_at IS NULL",
        )
        .bind::<Text, _>(device_id.as_str())
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Jsonb, _>(outcome)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(service_account_id))
        .bind::<Text, _>(audience)
        .bind::<Text, _>(principal_id.as_str())
        .execute(self.conn)
        .await?;
        if updated == 1 {
            return Ok(FirstDeviceEnrollmentCommit::Committed);
        }

        let stored = diesel::sql_query(
            "SELECT first_device_id AS device_id, \
             first_device_request_digest AS request_digest, \
             first_device_outcome AS outcome \
             FROM identity_creation_leases \
             WHERE service_account_id = $1 AND audience = $2 AND state = 'bound' \
             AND binding_receipt IS NOT NULL AND reserved_principal_id = $3",
        )
        .bind::<SqlUuid, _>(Uuid::from(service_account_id))
        .bind::<Text, _>(audience)
        .bind::<Text, _>(principal_id.as_str())
        .get_result::<FirstDeviceEnrollmentRow>(self.conn)
        .await
        .optional()?;
        let Some(stored) = stored else {
            return Ok(FirstDeviceEnrollmentCommit::Conflict);
        };
        if stored.device_id.as_deref() == Some(device_id.as_str())
            && stored.request_digest.as_deref() == Some(request_digest.as_str())
            && let Some(outcome) = stored.outcome
        {
            return Ok(FirstDeviceEnrollmentCommit::Replay(outcome));
        }
        Ok(FirstDeviceEnrollmentCommit::Conflict)
    }

    async fn consume_grant(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let updated = diesel::sql_query(
            "UPDATE account_handoff_grants SET consumed_at = $1 WHERE id = $2 \
             AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $1",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(grant.id))
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }
}

fn registration_challenge_state_is_usable(
    lease_state: IdentityCreationSagaState,
    challenge_consumed: bool,
) -> bool {
    match lease_state {
        IdentityCreationSagaState::Reserved => !challenge_consumed,
        // Publishing and challenge consumption are committed together before
        // the verified account binding. A retry after a binding-store failure
        // must be able to finish only this exact durable reservation.
        IdentityCreationSagaState::Published => challenge_consumed,
        IdentityCreationSagaState::Active | IdentityCreationSagaState::Bound => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, Timelike as _};
    use coauth_data::clock::MockClock;
    use coauth_data::user::UserRepository as _;
    use coauth_data::{Clock as _, RepositoryAccess as _, RepositoryFactory as _, new_id};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use sha2::Digest as _;

    use super::*;
    use crate::PgRepositoryFactory;

    fn handoff_input(
        rng: &mut ChaChaRng,
        service_account_id: Ulid,
        issued_at: DateTime<Utc>,
        holder_jkt: &str,
        lease_id: &str,
    ) -> AccountHandoffGrantInput {
        AccountHandoffGrantInput {
            id: new_id(issued_at, rng),
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64)))
                .unwrap(),
            service_account_id,
            browser_session_id: None,
            audience: "did:web:principal.example".to_owned(),
            cnf_jkt: holder_jkt.to_owned(),
            account_handoff_grant: format!("{}{}", Uuid::now_v7().simple(), "A".repeat(11)),
            issued_at,
            expires_at: issued_at + Duration::minutes(30),
            lease_id: lease_id.to_owned(),
            lease_expires_at: issued_at + Duration::minutes(15),
        }
    }

    fn unique_lease_id() -> String {
        Uuid::now_v7().simple().to_string()
    }

    /// Deterministic ids from a fixed seed collide with rows committed by a
    /// previous run of the same test (`MockClock` pins the ULID timestamp),
    /// so seed each run from a fresh UUIDv7. Fold in the low half too:
    /// concurrent same-millisecond UUIDv7s share their first eight bytes and
    /// differ only in the monotonic counter tail.
    fn test_rng() -> ChaChaRng {
        let bytes = Uuid::now_v7().into_bytes();
        let hi = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
        let lo = u64::from_le_bytes(bytes[8..].try_into().expect("8 bytes"));
        ChaChaRng::seed_from_u64(hi ^ lo)
    }

    #[test]
    fn cancel_operation_codec_rejects_tampered_terminal_outcome() {
        use arkret_models_collaboration::contact_operations::{
            BootstrapMode, CancelDeviceBootstrapOutcome, CancelDeviceBootstrapRequestBody,
            DeviceBootstrapDecisionRequestPreimage, RequestedDeviceBootstrapDecision,
        };

        let now = Utc::now();
        let hash = |fill: char| {
            arkret_identifiers::Hash::new(format!("sha256:{}", fill.to_string().repeat(64)))
                .unwrap()
        };
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json")
                .unwrap();
        let enroll: arkret_models_identity::AccountDeviceEnrollRequestBody =
            serde_json::from_value(fixture["enroll_request"].clone()).unwrap();
        let transaction_id =
            arkret_wire::ProtocolOpaqueId::new("bootstrap-codec-test".to_owned()).unwrap();
        let idempotency_key =
            arkret_wire::IdempotencyKey::new("cancel-codec-test".to_owned()).unwrap();
        let request = CancelDeviceBootstrapRequestBody {
            transaction_id: transaction_id.clone(),
            mode: BootstrapMode::Founding,
            canonical_request_digest: enroll.canonical_request_digest().unwrap(),
            idempotency_key: idempotency_key.clone(),
        };
        let authority_request = DeviceBootstrapDecisionRequestPreimage {
            account_authority_id: arkret_identifiers::Did::new(
                "did:web:accounts.example".to_owned(),
            )
            .unwrap(),
            transaction_id: transaction_id.clone(),
            idempotency_key: idempotency_key.clone(),
            requested_decision: RequestedDeviceBootstrapDecision::Cancelled,
            principal_id: enroll.authorize_event_preimage.actor_id.clone(),
            device_id: enroll.device_id.clone(),
            grant_id: arkret_identifiers::SessionGrantId::new(
                "ak:session_grant:AbmggbDOpDR8J1xRW3EU4354odEGafHu4vk9FVv4vimH",
            )
            .unwrap(),
            canonical_request_digest: request.canonical_request_digest.clone(),
            founding_event_ids: [
                enroll.authorize_event_preimage.prev_refs[0].clone(),
                enroll.authorize_event_preimage.event_id.clone(),
            ],
            founding_batch_digest: arkret_models_identity::founding_batch_digest(&[
                enroll.authorize_event_preimage.prev_refs[0].clone(),
                enroll.authorize_event_preimage.event_id.clone(),
            ])
            .unwrap(),
            bootstrap_transaction_expires_at: now + Duration::hours(1),
        }
        .finalize()
        .unwrap();
        let placeholder = hash('0');
        let mut outcome = CancelDeviceBootstrapOutcome::Cancelled {
            transaction_id: transaction_id.clone(),
            outcome_digest: placeholder,
        };
        let outcome_digest = outcome.recompute_outcome_digest().unwrap();
        let CancelDeviceBootstrapOutcome::Cancelled {
            outcome_digest: slot,
            ..
        } = &mut outcome
        else {
            unreachable!()
        };
        *slot = outcome_digest.clone();
        let row = DeviceBootstrapCancelOperationRow {
            transaction_id: transaction_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            canonical_request_digest: request.canonical_request_digest().unwrap().to_string(),
            canonical_request: arkret_canonical::canonical_json_bytes(&request).unwrap(),
            authority_request_digest: authority_request.decision_request_digest.to_string(),
            canonical_authority_request: arkret_canonical::canonical_json_bytes(&authority_request)
                .unwrap(),
            requested_decision: "cancelled".to_owned(),
            canonical_outcome: Some(arkret_canonical::canonical_json_bytes(&outcome).unwrap()),
            outcome_digest: Some(outcome_digest.to_string()),
            created_at: now,
        };
        assert!(device_bootstrap_cancel_operation_from_row(row).is_ok());

        let mut tampered = serde_json::to_value(&outcome).unwrap();
        tampered["transaction_id"] = serde_json::Value::String("bootstrap-other".to_owned());
        let row = DeviceBootstrapCancelOperationRow {
            transaction_id: transaction_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            canonical_request_digest: request.canonical_request_digest().unwrap().to_string(),
            canonical_request: arkret_canonical::canonical_json_bytes(&request).unwrap(),
            authority_request_digest: authority_request.decision_request_digest.to_string(),
            canonical_authority_request: arkret_canonical::canonical_json_bytes(&authority_request)
                .unwrap(),
            requested_decision: "cancelled".to_owned(),
            canonical_outcome: Some(arkret_canonical::canonical_json_bytes(&tampered).unwrap()),
            outcome_digest: Some(outcome_digest.to_string()),
            created_at: now,
        };
        assert!(device_bootstrap_cancel_operation_from_row(row).is_err());

        let accepted = arkret_wire::ErrorEnvelope::new(
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "founding bootstrap transaction is already accepted",
        )
        .with_detail(
            "transaction_id",
            serde_json::Value::String(transaction_id.to_string()),
        )
        .with_detail("state", serde_json::Value::String("accepted".to_owned()));
        let accepted_bytes = arkret_canonical::canonical_json_bytes(&accepted).unwrap();
        let accepted_digest = format!("sha256:{:x}", sha2::Sha256::digest(&accepted_bytes));
        let accepted_row = DeviceBootstrapCancelOperationRow {
            transaction_id: transaction_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            canonical_request_digest: request.canonical_request_digest().unwrap().to_string(),
            canonical_request: arkret_canonical::canonical_json_bytes(&request).unwrap(),
            authority_request_digest: authority_request.decision_request_digest.to_string(),
            canonical_authority_request: arkret_canonical::canonical_json_bytes(&authority_request)
                .unwrap(),
            requested_decision: "cancelled".to_owned(),
            canonical_outcome: Some(accepted_bytes),
            outcome_digest: Some(accepted_digest),
            created_at: now,
        };
        assert!(device_bootstrap_cancel_operation_from_row(accepted_row).is_ok());
    }

    #[test]
    fn bootstrap_transaction_codec_binds_all_terminal_receipts_and_times() {
        use arkret_models_collaboration::contact_operations::{
            DeviceBootstrapDecision, DeviceBootstrapDecisionReceiptPreimage,
            DeviceBootstrapDecisionReceiptSchema,
        };
        use arkret_wire::{Audience, PayloadProof, PayloadProofPurpose};

        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json")
                .unwrap();
        let enroll: arkret_models_identity::AccountDeviceEnrollRequestBody =
            serde_json::from_value(fixture["enroll_request"].clone()).unwrap();
        let created_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let expires_at = created_at + Duration::hours(1);
        let transaction_id =
            arkret_wire::ProtocolOpaqueId::new("bootstrap-receipt-codec".to_owned()).unwrap();
        let account_authority_id =
            arkret_identifiers::Did::new("did:web:accounts.example".to_owned()).unwrap();
        let principal_server_id =
            arkret_identifiers::Did::new("did:webvh:z6mkfixture:principal.example".to_owned())
                .unwrap();
        let event_ids = [
            enroll.authorize_event_preimage.prev_refs[0].clone(),
            enroll.authorize_event_preimage.event_id.clone(),
        ];
        let founding_digest = arkret_models_identity::founding_batch_digest(&event_ids).unwrap();
        let grant_id = arkret_identifiers::SessionGrantId::new(
            "ak:session_grant:AbmggbDOpDR8J1xRW3EU4354odEGafHu4vk9FVv4vimH",
        )
        .unwrap();
        let request_digest = enroll.canonical_request_digest().unwrap();
        let raw_device_key = {
            let payload: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
                serde_json::from_value(serde_json::Value::Object(
                    enroll
                        .authorize_event_preimage
                        .payload
                        .clone()
                        .into_iter()
                        .collect(),
                ))
                .unwrap();
            arkret_canonical::decode_ed25519_multibase(payload.device_public_key.as_str()).unwrap()
        };
        let device_key_digest =
            arkret_models_identity::device_bootstrap_device_key_digest(raw_device_key).unwrap();

        for (decision, state, decided_at) in [
            (
                DeviceBootstrapDecision::Accepted,
                "accepted",
                created_at + Duration::minutes(1),
            ),
            (
                DeviceBootstrapDecision::Cancelled,
                "cancelled",
                created_at + Duration::minutes(2),
            ),
            (
                DeviceBootstrapDecision::Expired,
                "expired",
                expires_at + Duration::seconds(1),
            ),
        ] {
            let preimage = DeviceBootstrapDecisionReceiptPreimage {
                schema: DeviceBootstrapDecisionReceiptSchema::V1,
                receipt_id: arkret_wire::ProtocolOpaqueId::new(format!("receipt-{state}")).unwrap(),
                principal_server_id: principal_server_id.clone(),
                account_authority_id: account_authority_id.clone(),
                transaction_id: transaction_id.clone(),
                decision,
                principal_id: enroll.authorize_event_preimage.actor_id.clone(),
                device_id: enroll.device_id.clone(),
                grant_id: grant_id.clone(),
                canonical_request_digest: request_digest.clone(),
                founding_event_ids: event_ids.clone(),
                founding_batch_digest: founding_digest.clone(),
                bootstrap_transaction_expires_at: expires_at,
                decided_at,
            };
            let receipt_digest = preimage.receipt_digest().unwrap();
            let receipt = preimage
                .finalize(PayloadProof {
                    kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: arkret_wire::DidUrl::new(format!(
                        "{}#notary",
                        principal_server_id
                    ))
                    .unwrap(),
                    payload_digest: receipt_digest,
                    created_at: decided_at,
                    domain: None,
                    audience: Some(Audience::Single(account_authority_id.to_string())),
                    proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
                    jws: "a..b".to_owned(),
                })
                .unwrap();
            let canonical_receipt = arkret_canonical::canonical_json_bytes(&receipt).unwrap();
            let row = DeviceBootstrapTransactionRow {
                transaction_id: transaction_id.to_string(),
                mode: "founding".to_owned(),
                account_authority_id: account_authority_id.to_string(),
                principal_server_id: principal_server_id.to_string(),
                principal_id: enroll.authorize_event_preimage.actor_id.to_string(),
                device_id: enroll.device_id.to_string(),
                device_key_digest: device_key_digest.to_string(),
                holder_jkt: "H".repeat(43),
                canonical_request_digest: request_digest.to_string(),
                canonical_request: arkret_canonical::canonical_json_bytes(&enroll).unwrap(),
                founding_batch_digest: founding_digest.to_string(),
                founding_event_ids: event_ids.iter().map(ToString::to_string).collect(),
                bootstrap_grant_id: grant_id.to_string(),
                state: state.to_owned(),
                enrollment_request_digest: None,
                canonical_enrollment_outcome: None,
                enrollment_outcome_digest: None,
                authorized_event_id: None,
                authorized_event_digest: None,
                standard_grant_id: None,
                expires_at,
                created_at,
                enrolled_at: None,
                accepted_at: (decision == DeviceBootstrapDecision::Accepted).then_some(decided_at),
                cancelled_at: (decision == DeviceBootstrapDecision::Cancelled)
                    .then_some(decided_at),
                expired_at: (decision == DeviceBootstrapDecision::Expired).then_some(expires_at),
                decision_principal_server_id: Some(principal_server_id.to_string()),
                canonical_decision_receipt: Some(canonical_receipt),
                decision_receipt_digest: Some(receipt.receipt_digest.to_string()),
            };
            let mut tampered = row.clone();
            tampered.decision_principal_server_id =
                Some("did:web:wrong-principal.example".to_owned());
            assert!(device_bootstrap_transaction_from_row(tampered).is_err());
            let decoded = device_bootstrap_transaction_from_row(row).unwrap();
            assert_eq!(decoded.state.as_str(), state);
        }
    }

    fn did_operation(label: &str) -> arkret_models_identity::DidOperationSubmitRequestBody {
        let did = arkret_identifiers::Did::new(format!("did:webvh:z{label}:example.com")).unwrap();
        arkret_models_identity::DidOperationSubmitRequestBody {
            did: did.clone(),
            did_method: "webvh".to_owned(),
            seq: Some(0),
            prev_event_digest: None,
            operation: BTreeMap::from([(
                "state".to_owned(),
                serde_json::json!({ "id": did.as_str() }),
            )]),
        }
    }

    fn register_request_digest(fill: char) -> arkret_identifiers::Hash {
        arkret_identifiers::Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn register_outcome(
        principal_id: arkret_identifiers::Did,
        binding_receipt: arkret_models_identity::AccountBindingReceipt,
    ) -> arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome {
        arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome {
            principal_id,
            state: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            devices: Vec::new(),
            primary_handle_claim: None,
            primary_handle_claim_ref: None,
            handle_claim_digests: Vec::new(),
            profile: None,
            registration_audit: None,
            binding_receipt: Some(binding_receipt),
        }
    }

    #[test]
    fn published_saga_can_resume_with_its_consumed_challenge_only() {
        assert!(registration_challenge_state_is_usable(
            IdentityCreationSagaState::Reserved,
            false,
        ));
        assert!(!registration_challenge_state_is_usable(
            IdentityCreationSagaState::Reserved,
            true,
        ));
        assert!(registration_challenge_state_is_usable(
            IdentityCreationSagaState::Published,
            true,
        ));
        assert!(!registration_challenge_state_is_usable(
            IdentityCreationSagaState::Published,
            false,
        ));
        assert!(!registration_challenge_state_is_usable(
            IdentityCreationSagaState::Bound,
            true,
        ));
    }

    #[tokio::test]
    async fn handoff_creation_attempt_fences_external_exchange_and_replays_exact_bytes() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let now = Utc::now();
        let request_id =
            arkret_identifiers::RequestId::new(format!("ak:request:{}", Uuid::now_v7())).unwrap();
        let hash = |fill: char| {
            arkret_identifiers::Hash::new(format!("sha256:{}", fill.to_string().repeat(64)))
                .unwrap()
        };
        let canonical_intent =
            br#"{"authorization_code":"sha256:redacted","issuer":"https://issuer.example"}"#
                .to_vec();
        let digest = |bytes: &[u8]| {
            arkret_identifiers::Hash::new(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
                .unwrap()
        };
        let input = NewAccountHandoffCreationAttempt {
            request_id: request_id.clone(),
            request_digest: hash('1'),
            canonical_intent_digest: digest(&canonical_intent),
            canonical_intent,
            holder_jkt: "H".repeat(43),
            issuer: "https://issuer.example".to_owned(),
            client_id: "arkret-client".to_owned(),
            authorization_code_digest: hash('3'),
            dpop_jti_digest: hash('4'),
            retained_until: now + Duration::days(7),
            now,
        };

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .reserve_creation_attempt(input.clone())
                .await
                .unwrap(),
            AccountHandoffCreationAttemptReserve::Reserved(_)
        ));
        repo.save().await.unwrap();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .reserve_creation_attempt(input.clone())
                .await
                .unwrap(),
            AccountHandoffCreationAttemptReserve::Pending(AccountHandoffCreationAttempt {
                state: AccountHandoffCreationAttemptState::Reserved,
                ..
            })
        ));
        repo.cancel().await.unwrap();

        let checkpoint = serde_json::json!({
            "service_account_id": Ulid::nil().to_string(),
            "browser_session_id": null,
            "audience": "did:web:principal.example",
            "account_handle": "alice:example.com",
            "preferred_locale": "zh",
        });
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .checkpoint_creation_authorization(
                    &request_id,
                    &input.canonical_intent_digest,
                    &checkpoint,
                    now + Duration::minutes(1),
                )
                .await
                .unwrap(),
            AccountHandoffCreationAttemptCommit::Committed(AccountHandoffCreationAttempt {
                state: AccountHandoffCreationAttemptState::Authorized,
                ..
            })
        ));
        repo.save().await.unwrap();

        let canonical_outcome = br#"{"account_handoff_grant":"opaque","request_id":"test"}"#;
        let outcome_digest = digest(canonical_outcome);
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .commit_creation_attempt(
                    &request_id,
                    &input.canonical_intent_digest,
                    canonical_outcome,
                    &outcome_digest,
                    now + Duration::minutes(2),
                )
                .await
                .unwrap(),
            AccountHandoffCreationAttemptCommit::Committed(AccountHandoffCreationAttempt {
                state: AccountHandoffCreationAttemptState::Committed,
                ..
            })
        ));
        repo.save().await.unwrap();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let replay = repo
            .account_handoff()
            .reserve_creation_attempt(input)
            .await
            .unwrap();
        let AccountHandoffCreationAttemptReserve::Replay(replay) = replay else {
            panic!("committed attempt must replay");
        };
        assert_eq!(
            replay.canonical_outcome.as_deref(),
            Some(&canonical_outcome[..])
        );
        assert_eq!(replay.outcome_digest, Some(outcome_digest));
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn device_bootstrap_transaction_has_closed_exact_replay_and_expiry() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            eprintln!("SKIP: DATABASE_URL is required for the device-bootstrap PG state test");
            return;
        };
        let now = Utc::now();
        let hash = |fill: char| {
            arkret_identifiers::Hash::new(format!("sha256:{}", fill.to_string().repeat(64)))
                .unwrap()
        };
        let enroll_request: arkret_models_identity::AccountDeviceEnrollRequestBody =
            serde_json::from_value(
                arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json")
                    .unwrap()["enroll_request"]
                    .clone(),
            )
            .unwrap();
        let event_ids = vec![
            enroll_request.authorize_event_preimage.prev_refs[0].clone(),
            enroll_request.authorize_event_preimage.event_id.clone(),
        ];
        let enroll_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
            serde_json::from_value(serde_json::Value::Object(
                enroll_request
                    .authorize_event_preimage
                    .payload
                    .clone()
                    .into_iter()
                    .collect(),
            ))
            .unwrap();
        let raw_device_key =
            arkret_canonical::decode_ed25519_multibase(enroll_payload.device_public_key.as_str())
                .unwrap();
        let transaction_id =
            arkret_wire::ProtocolOpaqueId::new(format!("bootstrap-{}", Uuid::now_v7().simple()))
                .unwrap();
        let input = NewDeviceBootstrapTransaction {
            transaction_id: transaction_id.clone(),
            mode: arkret_models_collaboration::contact_operations::BootstrapMode::Founding,
            account_authority_id: arkret_identifiers::Did::new(
                "did:webvh:z6mkfixture:auth-a.example",
            )
            .unwrap(),
            principal_server_id: arkret_identifiers::Did::new(
                "did:webvh:z6mkfixture:principal.example",
            )
            .unwrap(),
            principal_id: enroll_request.authorize_event_preimage.actor_id.clone(),
            device_id: enroll_request.device_id.clone(),
            device_key_digest: arkret_models_identity::device_bootstrap_device_key_digest(
                raw_device_key,
            )
            .unwrap(),
            holder_jkt: "H".repeat(43),
            canonical_request_digest: enroll_request.canonical_request_digest().unwrap(),
            canonical_request: arkret_canonical::canonical_json_bytes(&enroll_request).unwrap(),
            founding_batch_digest: arkret_models_identity::founding_batch_digest(&event_ids)
                .unwrap(),
            founding_event_ids: event_ids.clone(),
            bootstrap_grant_id: arkret_identifiers::SessionGrantId::new(
                "ak:session_grant:AbmggbDOpDR8J1xRW3EU4354odEGafHu4vk9FVv4vimH",
            )
            .unwrap(),
            expires_at: now + Duration::seconds(5),
            now,
        };

        let mut rolled_back = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            rolled_back
                .account_handoff()
                .create_device_bootstrap_transaction(input.clone())
                .await
                .unwrap(),
            DeviceBootstrapTransactionCreate::Created(_)
        ));
        rolled_back.cancel().await.unwrap();
        let mut after_rollback = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(
            after_rollback
                .account_handoff()
                .get_device_bootstrap_transaction(&transaction_id)
                .await
                .unwrap()
                .is_none()
        );
        after_rollback.cancel().await.unwrap();

        let left_pool = pool.clone();
        let left_input = input.clone();
        let right_pool = pool.clone();
        let right_input = input.clone();
        let (left, right) = tokio::join!(
            async move {
                let mut repo = PgRepositoryFactory::new(left_pool).create().await.unwrap();
                let result = repo
                    .account_handoff()
                    .create_device_bootstrap_transaction(left_input)
                    .await
                    .unwrap();
                repo.save().await.unwrap();
                result
            },
            async move {
                let mut repo = PgRepositoryFactory::new(right_pool).create().await.unwrap();
                let result = repo
                    .account_handoff()
                    .create_device_bootstrap_transaction(right_input)
                    .await
                    .unwrap();
                repo.save().await.unwrap();
                result
            }
        );
        let created = [&left, &right]
            .into_iter()
            .filter(|result| matches!(result, DeviceBootstrapTransactionCreate::Created(_)))
            .count();
        let replayed = [&left, &right]
            .into_iter()
            .filter(|result| matches!(result, DeviceBootstrapTransactionCreate::Replay(_)))
            .count();
        assert_eq!((created, replayed), (1, 1));

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .create_device_bootstrap_transaction(input.clone())
                .await
                .unwrap(),
            DeviceBootstrapTransactionCreate::Replay(_)
        ));
        let mut conflicting = input.clone();
        conflicting.canonical_request_digest = hash('3');
        assert!(matches!(
            repo.account_handoff()
                .create_device_bootstrap_transaction(conflicting)
                .await
                .unwrap(),
            DeviceBootstrapTransactionCreate::Conflict(_)
        ));
        repo.cancel().await.unwrap();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let authorized_event_digest = hash('4');
        let outcome_digest = hash('5');
        let requires_decision = repo
            .account_handoff()
            .commit_device_bootstrap_enrollment(DeviceBootstrapEnrollmentInput {
                transaction_id: &transaction_id,
                principal_id: &input.principal_id,
                device_id: &input.device_id,
                request_digest: &input.canonical_request_digest,
                authorized_event_id: &event_ids[1],
                authorized_event_digest: &authorized_event_digest,
                canonical_outcome: b"{}",
                outcome_digest: &outcome_digest,
                now: now + Duration::seconds(10),
            })
            .await
            .unwrap();
        assert!(matches!(
            requires_decision,
            DeviceBootstrapEnrollmentCommit::RequiresDecision(DeviceBootstrapTransaction {
                state: DeviceBootstrapTransactionState::Pending,
                ..
            })
        ));
        repo.save().await.unwrap();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let pending = repo
            .account_handoff()
            .get_device_bootstrap_transaction(&transaction_id)
            .await
            .unwrap()
            .expect("bootstrap transaction remains durable");
        assert_eq!(pending.state, DeviceBootstrapTransactionState::Pending);
        assert!(pending.decision_principal_server_id.is_none());
        assert!(pending.canonical_decision_receipt.is_none());
        assert!(pending.decision_receipt_digest.is_none());
        repo.cancel().await.unwrap();

        // Two idempotency keys may be durably prepared before the Principal
        // decision. The first local committer owns the lifecycle transition;
        // the loser must complete its own operation with the same immutable
        // receipt and byte-identical outcome.
        use arkret_models_collaboration::contact_operations::{
            CancelDeviceBootstrapRequestBody, DeviceBootstrapDecision,
            DeviceBootstrapDecisionOutcome, DeviceBootstrapDecisionReceiptPreimage,
            DeviceBootstrapDecisionReceiptSchema, DeviceBootstrapDecisionRequestPreimage,
            RequestedDeviceBootstrapDecision,
        };
        use arkret_wire::{Audience, PayloadProof, PayloadProofPurpose};
        let mut terminal_input = input.clone();
        terminal_input.transaction_id = arkret_wire::ProtocolOpaqueId::new(format!(
            "bootstrap-terminal-{}",
            Uuid::now_v7().simple()
        ))
        .unwrap();
        terminal_input.expires_at = now + Duration::hours(1);
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .create_device_bootstrap_transaction(terminal_input.clone())
                .await
                .unwrap(),
            DeviceBootstrapTransactionCreate::Created(_)
        ));
        repo.save().await.unwrap();

        let cancel_body = |key: &str| CancelDeviceBootstrapRequestBody {
            transaction_id: terminal_input.transaction_id.clone(),
            mode: terminal_input.mode,
            canonical_request_digest: terminal_input.canonical_request_digest.clone(),
            idempotency_key: arkret_wire::IdempotencyKey::new(key.to_owned()).unwrap(),
        };
        let decision_request = |body: &CancelDeviceBootstrapRequestBody| {
            DeviceBootstrapDecisionRequestPreimage {
                account_authority_id: terminal_input.account_authority_id.clone(),
                transaction_id: terminal_input.transaction_id.clone(),
                idempotency_key: body.idempotency_key.clone(),
                requested_decision: RequestedDeviceBootstrapDecision::Cancelled,
                principal_id: terminal_input.principal_id.clone(),
                device_id: terminal_input.device_id.clone(),
                grant_id: terminal_input.bootstrap_grant_id.clone(),
                canonical_request_digest: terminal_input.canonical_request_digest.clone(),
                founding_event_ids: [
                    terminal_input.founding_event_ids[0].clone(),
                    terminal_input.founding_event_ids[1].clone(),
                ],
                founding_batch_digest: terminal_input.founding_batch_digest.clone(),
                bootstrap_transaction_expires_at: terminal_input.expires_at,
            }
            .finalize()
            .unwrap()
        };
        let body_a = cancel_body("cancel-a");
        let body_b = cancel_body("cancel-b");
        let authority_a = decision_request(&body_a);
        let authority_b = decision_request(&body_b);
        for (body, authority) in [(&body_a, &authority_a), (&body_b, &authority_b)] {
            let mut repo = PgRepositoryFactory::new(pool.clone())
                .create()
                .await
                .unwrap();
            assert!(matches!(
                repo.account_handoff()
                    .reserve_device_bootstrap_cancel(DeviceBootstrapCancelReserveInput {
                        request: body.clone(),
                        canonical_request_digest: body.canonical_request_digest().unwrap(),
                        canonical_request: arkret_canonical::canonical_json_bytes(body).unwrap(),
                        authority_request: authority.clone(),
                        canonical_authority_request: arkret_canonical::canonical_json_bytes(
                            authority,
                        )
                        .unwrap(),
                        now,
                    })
                    .await
                    .unwrap(),
                DeviceBootstrapCancelReserve::Reserved(_)
            ));
            repo.save().await.unwrap();
        }
        let decided_at = now + Duration::minutes(1);
        let receipt_preimage = DeviceBootstrapDecisionReceiptPreimage {
            schema: DeviceBootstrapDecisionReceiptSchema::V1,
            receipt_id: arkret_wire::ProtocolOpaqueId::new("receipt-cancelled".to_owned()).unwrap(),
            principal_server_id: terminal_input.principal_server_id.clone(),
            account_authority_id: terminal_input.account_authority_id.clone(),
            transaction_id: terminal_input.transaction_id.clone(),
            decision: DeviceBootstrapDecision::Cancelled,
            principal_id: terminal_input.principal_id.clone(),
            device_id: terminal_input.device_id.clone(),
            grant_id: terminal_input.bootstrap_grant_id.clone(),
            canonical_request_digest: terminal_input.canonical_request_digest.clone(),
            founding_event_ids: [
                terminal_input.founding_event_ids[0].clone(),
                terminal_input.founding_event_ids[1].clone(),
            ],
            founding_batch_digest: terminal_input.founding_batch_digest.clone(),
            bootstrap_transaction_expires_at: terminal_input.expires_at,
            decided_at,
        };
        let receipt_digest = receipt_preimage.receipt_digest().unwrap();
        let receipt = receipt_preimage
            .finalize(PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new(format!(
                    "{}#notary",
                    terminal_input.principal_server_id
                ))
                .unwrap(),
                payload_digest: receipt_digest,
                created_at: decided_at,
                domain: None,
                audience: Some(Audience::Single(
                    terminal_input.account_authority_id.to_string(),
                )),
                proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
                jws: "a..b".to_owned(),
            })
            .unwrap();
        let outcome = DeviceBootstrapDecisionOutcome {
            transaction_id: terminal_input.transaction_id.clone(),
            decision: DeviceBootstrapDecision::Cancelled,
            receipt,
        };
        let canonical_receipt = arkret_canonical::canonical_json_bytes(&outcome.receipt).unwrap();
        let mut exact_outcomes = Vec::new();
        for (body, authority) in [(body_a, authority_a), (body_b, authority_b)] {
            let mut repo = PgRepositoryFactory::new(pool.clone())
                .create()
                .await
                .unwrap();
            let committed = repo
                .account_handoff()
                .commit_device_bootstrap_cancel(DeviceBootstrapCancelInput {
                    canonical_request_digest: body.canonical_request_digest().unwrap(),
                    canonical_request: arkret_canonical::canonical_json_bytes(&body).unwrap(),
                    request: body,
                    decision: coauth_data::DeviceBootstrapCancelDecision::Cancel,
                    authority: coauth_data::DeviceBootstrapDecisionEvidence {
                        request: authority,
                        outcome: outcome.clone(),
                        canonical_receipt: canonical_receipt.clone(),
                    },
                    now: decided_at,
                })
                .await
                .unwrap();
            let operation = match committed {
                DeviceBootstrapCancelCommit::Committed { operation, .. } => operation,
                other => panic!("prepared cancel must commit, got {other:?}"),
            };
            repo.save().await.unwrap();
            exact_outcomes.push(operation.canonical_outcome.unwrap());
        }
        assert_eq!(exact_outcomes[0], exact_outcomes[1]);
    }

    #[tokio::test]
    async fn future_bound_rows_require_a_complete_register_ledger() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let user = repo
            .user()
            .add(&mut rng, &clock, format!("ledger-required-{label}"))
            .await
            .unwrap();
        let created = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                user.id,
                now,
                &"L".repeat(43),
                &unique_lease_id(),
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active { grant, .. } = created else {
            panic!("identity creation must acquire an active lease");
        };
        repo.save().await.unwrap();

        let mut conn = pool.get().await.unwrap();
        let result = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'bound' \
             WHERE service_account_id = $1 AND audience = $2",
        )
        .bind::<SqlUuid, _>(Uuid::from(user.id))
        .bind::<Text, _>(&grant.audience)
        .execute(&mut *conn)
        .await;
        assert!(
            result.is_err(),
            "a post-migration Bound row without a replay ledger must violate the constraint"
        );
    }

    #[tokio::test]
    async fn expired_lease_reclaim_preserves_reservation_and_rejects_old_fence() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let holder_one = "A".repeat(43);
        let holder_two = "B".repeat(43);
        let holder_three = "C".repeat(43);
        // Lease ids are globally unique in the database and committed rows
        // survive this test's mid-flight save, so every id must be fresh per
        // run instead of a shared constant.
        let lease_one = unique_lease_id();
        let lease_two = unique_lease_id();
        let renewal_lease = unique_lease_id();
        let lease_three = unique_lease_id();
        let user = repo
            .user()
            .add(&mut rng, &clock, format!("handoff-{label}"))
            .await
            .unwrap();

        let first = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                user.id,
                now,
                &holder_one,
                &lease_one,
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active {
            grant: first_grant,
            lease: first_lease,
        } = first
        else {
            panic!("first holder must acquire an active lease");
        };
        assert_eq!(first_lease.fence, 1);

        let operation = did_operation(&label);
        let reserved =
            arkret_models_identity::ReservedIdentityCreation::from_operation(operation.clone())
                .unwrap();
        let challenge_issued_at = now.with_nanosecond(123_456_789).unwrap();
        let first_challenge = IdentityBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64)))
                .unwrap(),
            service_account_id: user.id,
            audience: first_grant.audience.clone(),
            lease_id: first_lease.lease_id.clone(),
            lease_fence: first_lease.fence,
            holder_jkt: first_lease.holder_jkt.clone(),
            did_operation: operation.clone(),
            operation_digest: reserved.operation_digest.clone(),
            challenge_id: Uuid::now_v7().simple().to_string(),
            challenge: format!("{}{}", Uuid::now_v7().simple(), "H".repeat(11)),
            origin: "https://account.example".to_owned(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:example.net",
            )
            .unwrap(),
            issued_at: challenge_issued_at,
            expires_at: challenge_issued_at + Duration::minutes(5),
            lease_expires_at: first_lease.expires_at,
        };
        let issued_challenge = match repo
            .account_handoff()
            .reserve_and_issue_challenge(first_challenge.clone())
            .await
            .unwrap()
        {
            IdentityBindingChallengeIssue::Issued(challenge) => challenge,
            other => panic!("first challenge must be issued, got {other:?}"),
        };
        assert_eq!(
            issued_challenge.issued_at,
            arkret_canonical::normalize_timestamp_canonical(challenge_issued_at),
            "durable challenge timestamps must exactly match their canonical wire value"
        );
        let wire_challenge: arkret_models_identity::IdentityBindingChallengeOutcome =
            serde_json::from_value(serde_json::to_value(issued_challenge.wire_outcome()).unwrap())
                .unwrap();
        assert_eq!(wire_challenge.issued_at, issued_challenge.issued_at);
        assert_eq!(wire_challenge.expires_at, issued_challenge.expires_at);
        repo.save().await.unwrap();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .reserve_and_issue_challenge(first_challenge.clone())
                .await
                .unwrap(),
            IdentityBindingChallengeIssue::Replay(_)
        ));
        let conflicting_replay = IdentityBindingChallengeInput {
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "9".repeat(64)))
                .unwrap(),
            ..first_challenge.clone()
        };
        assert!(matches!(
            repo.account_handoff()
                .reserve_and_issue_challenge(conflicting_replay)
                .await
                .unwrap(),
            IdentityBindingChallengeIssue::DuplicateConflict
        ));
        assert!(
            repo.account_handoff()
                .registration_context(
                    &first_grant,
                    &first_lease.lease_id,
                    first_lease.fence,
                    &issued_challenge.challenge_id,
                    issued_challenge.expires_at + Duration::seconds(1),
                )
                .await
                .unwrap()
                .is_none(),
            "an expired challenge must not produce a registration context"
        );

        let reclaimed_at = first_lease.expires_at + Duration::seconds(1);
        let reclaimed = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                user.id,
                reclaimed_at,
                &holder_two,
                &lease_two,
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active {
            lease: reclaimed_lease,
            ..
        } = reclaimed
        else {
            panic!("the second holder must reclaim the expired lease");
        };
        assert_eq!(reclaimed_lease.fence, first_lease.fence + 1);
        assert_eq!(reclaimed_lease.lease_id, lease_two);
        assert_eq!(reclaimed_lease.holder_jkt, holder_two);
        assert_eq!(reclaimed_lease.reserved_identity, Some(reserved));

        let renewed = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                user.id,
                reclaimed_at + Duration::seconds(1),
                &holder_two,
                &renewal_lease,
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active {
            lease: renewed_lease,
            ..
        } = renewed
        else {
            panic!("the current holder must renew its active lease");
        };
        assert_eq!(renewed_lease.lease_id, reclaimed_lease.lease_id);
        assert_eq!(renewed_lease.fence, reclaimed_lease.fence);

        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(handoff_input(
                    &mut rng,
                    user.id,
                    reclaimed_at + Duration::seconds(2),
                    &holder_three,
                    &lease_three,
                ))
                .await
                .unwrap(),
            AccountHandoffCreation::Busy { .. }
        ));

        let stale_challenge = IdentityBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "c".repeat(64)))
                .unwrap(),
            issued_at: reclaimed_at,
            expires_at: reclaimed_at + Duration::minutes(5),
            lease_expires_at: reclaimed_at + Duration::minutes(15),
            ..first_challenge
        };
        assert!(matches!(
            repo.account_handoff()
                .reserve_and_issue_challenge(stale_challenge)
                .await
                .unwrap(),
            IdentityBindingChallengeIssue::LeaseMismatch
        ));

        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn verified_binding_replays_exact_founding_device_outcome() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let user = repo
            .user()
            .add(&mut rng, &clock, format!("device-claim-{label}"))
            .await
            .unwrap();
        let created = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                user.id,
                now,
                &"A".repeat(43),
                &unique_lease_id(),
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active { grant, lease } = created else {
            panic!("identity creation must acquire an active lease");
        };

        let operation = did_operation(&label);
        let reserved =
            arkret_models_identity::ReservedIdentityCreation::from_operation(operation.clone())
                .unwrap();
        let challenge_input = IdentityBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "4".repeat(64)))
                .unwrap(),
            service_account_id: user.id,
            audience: grant.audience.clone(),
            lease_id: lease.lease_id.clone(),
            lease_fence: lease.fence,
            holder_jkt: lease.holder_jkt.clone(),
            did_operation: operation,
            operation_digest: reserved.operation_digest.clone(),
            challenge_id: Uuid::now_v7().simple().to_string(),
            challenge: format!("{}{}", Uuid::now_v7().simple(), "H".repeat(11)),
            origin: "https://account.example".to_owned(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:example.net",
            )
            .unwrap(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            lease_expires_at: lease.expires_at,
        };
        let issued = match repo
            .account_handoff()
            .reserve_and_issue_challenge(challenge_input)
            .await
            .unwrap()
        {
            IdentityBindingChallengeIssue::Issued(challenge) => challenge,
            other => panic!("challenge must be issued, got {other:?}"),
        };
        let context = repo
            .account_handoff()
            .registration_context(
                &grant,
                &lease.lease_id,
                lease.fence,
                &issued.challenge_id,
                now,
            )
            .await
            .unwrap()
            .expect("fresh challenge must produce registration context");
        let head = arkret_identifiers::Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap();
        assert!(
            repo.account_handoff()
                .mark_published(
                    &context,
                    &serde_json::json!({ "status": "accepted" }),
                    &head,
                    now
                )
                .await
                .unwrap()
        );
        let binding_receipt = arkret_models_identity::AccountBindingReceipt {
            binding_state: arkret_models_identity::AccountBindingState::Bound,
            lease_id: lease.lease_id.clone(),
            lease_fence: lease.fence,
            operation_status: arkret_models_identity::IdentityCreationOperationStatus::Accepted,
            operation_digest: reserved.operation_digest,
            head_event_digest: head,
        };
        let request_digest = register_request_digest('6');
        let outcome = register_outcome(reserved.principal_id.clone(), binding_receipt.clone());
        assert!(matches!(
            repo.account_handoff()
                .mark_bound(&context, &binding_receipt, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Committed
        ));

        let first_device =
            arkret_identifiers::DeviceId::new(format!("ak:device:{}", Uuid::now_v7())).unwrap();
        let second_device =
            arkret_identifiers::DeviceId::new(format!("ak:device:{}", Uuid::now_v7())).unwrap();
        let enrollment_digest = register_request_digest('7');
        let enrollment_outcome = serde_json::json!({
            "device_id": first_device,
            "authorized_event": { "event_id": format!("ak:event:{}", Uuid::now_v7()) }
        });
        assert!(matches!(
            repo.account_handoff()
                .commit_first_device_enrollment(FirstDeviceEnrollmentInput {
                    service_account_id: user.id,
                    audience: &grant.audience,
                    principal_id: &reserved.principal_id,
                    device_id: &first_device,
                    request_digest: &enrollment_digest,
                    outcome: &enrollment_outcome,
                    now,
                })
                .await
                .unwrap(),
            FirstDeviceEnrollmentCommit::Committed
        ));
        assert_eq!(
            repo.account_handoff()
                .commit_first_device_enrollment(FirstDeviceEnrollmentInput {
                    service_account_id: user.id,
                    audience: &grant.audience,
                    principal_id: &reserved.principal_id,
                    device_id: &first_device,
                    request_digest: &enrollment_digest,
                    outcome: &serde_json::json!({ "newly_minted": "must-not-replace-stored-outcome" }),
                    now: now + Duration::seconds(1),
                })
                .await
                .unwrap(),
            FirstDeviceEnrollmentCommit::Replay(enrollment_outcome.clone()),
        );
        assert!(
            matches!(
                repo.account_handoff()
                    .commit_first_device_enrollment(FirstDeviceEnrollmentInput {
                        service_account_id: user.id,
                        audience: &grant.audience,
                        principal_id: &reserved.principal_id,
                        device_id: &second_device,
                        request_digest: &register_request_digest('8'),
                        outcome: &serde_json::json!({ "device_id": second_device }),
                        now: now + Duration::seconds(1),
                    })
                    .await
                    .unwrap(),
                FirstDeviceEnrollmentCommit::Conflict
            ),
            "a second device must not reuse the founding-device enrollment endpoint"
        );

        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn published_binding_failure_resumes_only_the_original_reservation() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let user = repo
            .user()
            .add(&mut rng, &clock, format!("binding-crash-{label}"))
            .await
            .unwrap();
        let created = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                user.id,
                now,
                &"A".repeat(43),
                &unique_lease_id(),
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active { grant, lease } = created else {
            panic!("identity creation must acquire an active lease");
        };

        let operation = did_operation(&label);
        let reserved =
            arkret_models_identity::ReservedIdentityCreation::from_operation(operation.clone())
                .unwrap();
        let challenge_input = IdentityBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "7".repeat(64)))
                .unwrap(),
            service_account_id: user.id,
            audience: grant.audience.clone(),
            lease_id: lease.lease_id.clone(),
            lease_fence: lease.fence,
            holder_jkt: lease.holder_jkt.clone(),
            did_operation: operation,
            operation_digest: reserved.operation_digest.clone(),
            challenge_id: Uuid::now_v7().simple().to_string(),
            challenge: format!("{}{}", Uuid::now_v7().simple(), "H".repeat(11)),
            origin: "https://account.example".to_owned(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:example.net",
            )
            .unwrap(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            lease_expires_at: lease.expires_at,
        };
        let stale_challenge = match repo
            .account_handoff()
            .reserve_and_issue_challenge(challenge_input.clone())
            .await
            .unwrap()
        {
            IdentityBindingChallengeIssue::Issued(challenge) => challenge,
            other => panic!("challenge must be issued, got {other:?}"),
        };
        let stale_context = repo
            .account_handoff()
            .registration_context(
                &grant,
                &lease.lease_id,
                lease.fence,
                &stale_challenge.challenge_id,
                now,
            )
            .await
            .unwrap()
            .expect("fresh challenge must produce registration context");
        let replacement_input = IdentityBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64)))
                .unwrap(),
            challenge_id: Uuid::now_v7().simple().to_string(),
            challenge: format!("{}{}", Uuid::now_v7().simple(), "R".repeat(11)),
            issued_at: now + Duration::seconds(1),
            ..challenge_input
        };
        let issued = match repo
            .account_handoff()
            .reserve_and_issue_challenge(replacement_input)
            .await
            .unwrap()
        {
            IdentityBindingChallengeIssue::Issued(challenge) => challenge,
            other => panic!("replacement challenge must be issued, got {other:?}"),
        };
        let head = arkret_identifiers::Hash::new(format!("sha256:{}", "8".repeat(64))).unwrap();
        let registry_receipt = serde_json::json!({ "status": "accepted" });
        assert!(
            !repo
                .account_handoff()
                .mark_published(&stale_context, &registry_receipt, &head, now)
                .await
                .unwrap(),
            "a replaced challenge must not publish the reserved operation"
        );
        let context = repo
            .account_handoff()
            .registration_context(
                &grant,
                &lease.lease_id,
                lease.fence,
                &issued.challenge_id,
                now + Duration::seconds(1),
            )
            .await
            .unwrap()
            .expect("replacement challenge must produce registration context");
        assert!(
            repo.account_handoff()
                .mark_published(
                    &context,
                    &registry_receipt,
                    &head,
                    now + Duration::seconds(1)
                )
                .await
                .unwrap()
        );
        // The registry accepted the operation: commit exactly what the
        // register handler commits before the binding store transaction.
        repo.save().await.unwrap();

        // The binding transaction fails after the registry acceptance: its
        // partial work must leave no durable trace.
        let binding_receipt = arkret_models_identity::AccountBindingReceipt {
            binding_state: arkret_models_identity::AccountBindingState::Bound,
            lease_id: lease.lease_id.clone(),
            lease_fence: lease.fence,
            operation_status: arkret_models_identity::IdentityCreationOperationStatus::Accepted,
            operation_digest: reserved.operation_digest.clone(),
            head_event_digest: head.clone(),
        };
        let request_digest = register_request_digest('9');
        let outcome = register_outcome(reserved.principal_id.clone(), binding_receipt.clone());
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .mark_bound(&context, &binding_receipt, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Committed
        ));
        repo.cancel().await.unwrap();

        // A fresh process recovers the exact published reservation together
        // with its consumed challenge and the durable registry receipt.
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let recovered = repo
            .account_handoff()
            .registration_context(
                &grant,
                &lease.lease_id,
                lease.fence,
                &issued.challenge_id,
                now + Duration::seconds(1),
            )
            .await
            .unwrap()
            .expect("published saga must recover its registration context");
        assert_eq!(recovered.lease.state, IdentityCreationSagaState::Published);
        assert_eq!(recovered.lease.reserved_identity, Some(reserved.clone()));
        assert_eq!(recovered.lease.registry_receipt, Some(registry_receipt));
        assert_eq!(recovered.lease.head_event_digest, Some(head));
        assert!(recovered.challenge.consumed_at.is_some());

        // No other operation may replace the published reservation.
        let foreign_operation = did_operation(&format!("{label}f"));
        let foreign_reserved = arkret_models_identity::ReservedIdentityCreation::from_operation(
            foreign_operation.clone(),
        )
        .unwrap();
        let foreign_challenge = IdentityBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                Uuid::now_v7()
            ))
            .unwrap(),
            request_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "d".repeat(64)))
                .unwrap(),
            service_account_id: user.id,
            audience: grant.audience.clone(),
            lease_id: lease.lease_id.clone(),
            lease_fence: lease.fence,
            holder_jkt: lease.holder_jkt.clone(),
            did_operation: foreign_operation,
            operation_digest: foreign_reserved.operation_digest,
            challenge_id: Uuid::now_v7().simple().to_string(),
            challenge: format!("{}{}", Uuid::now_v7().simple(), "J".repeat(11)),
            origin: "https://account.example".to_owned(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:example.net",
            )
            .unwrap(),
            issued_at: now + Duration::seconds(1),
            expires_at: now + Duration::minutes(5),
            lease_expires_at: lease.expires_at,
        };
        assert!(matches!(
            repo.account_handoff()
                .reserve_and_issue_challenge(foreign_challenge)
                .await
                .unwrap(),
            IdentityBindingChallengeIssue::ReservationConflict
        ));

        // The final transaction re-reads the exact challenge, rather than
        // trusting a stale in-memory context with the same lease fence.
        let mut foreign_request = recovered.clone();
        foreign_request.challenge.request_id =
            arkret_identifiers::RequestId::new(format!("ak:request:{}", Uuid::now_v7())).unwrap();
        assert!(matches!(
            repo.account_handoff()
                .mark_bound(
                    &foreign_request,
                    &binding_receipt,
                    &request_digest,
                    &outcome,
                    now
                )
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Stale
        ));

        // Neither a tampered digest nor a foreign holder can finalize.
        let mut tampered = recovered.clone();
        tampered.challenge.operation_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap();
        assert!(matches!(
            repo.account_handoff()
                .mark_bound(&tampered, &binding_receipt, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Stale
        ));
        let mut foreign_holder = recovered.clone();
        foreign_holder.grant.cnf_jkt = "Z".repeat(43);
        assert!(matches!(
            repo.account_handoff()
                .mark_bound(
                    &foreign_holder,
                    &binding_receipt,
                    &request_digest,
                    &outcome,
                    now
                )
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Stale
        ));

        // Only the original context completes the saga, and the founding
        // device claim works solely for the reserved principal.
        assert!(matches!(
            repo.account_handoff()
                .mark_bound(&recovered, &binding_receipt, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Committed
        ));

        // A second process must wait for the uncommitted Bound transition,
        // then observe and replay the stored outcome instead of falling back
        // to a now-stale registration context.
        let replay_pool = pool.clone();
        let replay_grant = grant.clone();
        let replay_lease_id = lease.lease_id.clone();
        let replay_lease_fence = lease.fence;
        let replay_challenge_id = issued.challenge_id.clone();
        let replay_request_digest = request_digest.clone();
        let mut replay_task = tokio::spawn(async move {
            let mut replay_repo = PgRepositoryFactory::new(replay_pool)
                .create()
                .await
                .unwrap();
            let replay = replay_repo
                .account_handoff()
                .registration_replay(
                    &replay_grant,
                    &replay_lease_id,
                    replay_lease_fence,
                    &replay_challenge_id,
                    &replay_request_digest,
                )
                .await
                .unwrap();
            replay_repo.cancel().await.unwrap();
            replay
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut replay_task)
                .await
                .is_err(),
            "the replay lookup must wait on the in-flight binding transaction"
        );
        repo.save().await.unwrap();
        let replay = tokio::time::timeout(std::time::Duration::from_secs(5), replay_task)
            .await
            .expect("replay lookup must finish after the binding commits")
            .unwrap();
        let IdentityCreationRegisterReplay::Replay(stored_outcome) = replay else {
            panic!("exact cross-process retry must return the stored outcome");
        };
        assert_eq!(
            serde_json::to_value(*stored_outcome).unwrap(),
            serde_json::to_value(&outcome).unwrap()
        );

        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let mut renewed_grant = grant.clone();
        renewed_grant.id = new_id(now + Duration::seconds(2), &mut rng);
        renewed_grant.account_handoff_grant =
            format!("{}{}", Uuid::now_v7().simple(), "N".repeat(11));
        assert!(matches!(
            repo.account_handoff()
                .registration_replay(
                    &renewed_grant,
                    &lease.lease_id,
                    lease.fence,
                    &issued.challenge_id,
                    &request_digest,
                )
                .await
                .unwrap(),
            IdentityCreationRegisterReplay::Replay(_)
        ));
        assert!(matches!(
            repo.account_handoff()
                .registration_replay(
                    &grant,
                    &lease.lease_id,
                    lease.fence,
                    &issued.challenge_id,
                    &register_request_digest('0'),
                )
                .await
                .unwrap(),
            IdentityCreationRegisterReplay::DuplicateConflict
        ));

        let foreign_principal =
            arkret_identifiers::Did::new(format!("did:webvh:z{label}f:example.com")).unwrap();
        let device =
            arkret_identifiers::DeviceId::new(format!("ak:device:{}", Uuid::now_v7())).unwrap();
        let enrollment_digest = register_request_digest('8');
        let enrollment_outcome = serde_json::json!({ "device_id": device });
        assert!(matches!(
            repo.account_handoff()
                .commit_first_device_enrollment(FirstDeviceEnrollmentInput {
                    service_account_id: user.id,
                    audience: &grant.audience,
                    principal_id: &foreign_principal,
                    device_id: &device,
                    request_digest: &enrollment_digest,
                    outcome: &enrollment_outcome,
                    now,
                })
                .await
                .unwrap(),
            FirstDeviceEnrollmentCommit::Conflict
        ));
        assert!(matches!(
            repo.account_handoff()
                .commit_first_device_enrollment(FirstDeviceEnrollmentInput {
                    service_account_id: user.id,
                    audience: &grant.audience,
                    principal_id: &reserved.principal_id,
                    device_id: &device,
                    request_digest: &enrollment_digest,
                    outcome: &enrollment_outcome,
                    now,
                })
                .await
                .unwrap(),
            FirstDeviceEnrollmentCommit::Committed
        ));

        repo.cancel().await.unwrap();
    }
}
