//! PostgreSQL account-handoff state machine.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::account_handoff::{
    AccountHandoffCreation, AccountHandoffCreationAttempt, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffCreationAttemptState, AccountHandoffGrant,
    AccountHandoffGrantInput, IdentityBindingChallengeInput, IdentityBindingChallengeIssue,
    IdentityBindingChallengeRecord, IdentityCreationBindingCommit, IdentityCreationLeaseRecord,
    IdentityCreationRegisterLedger, IdentityCreationRegisterReplay,
    IdentityCreationRegistrationContext, IdentityCreationSagaState,
    NewAccountHandoffCreationAttempt,
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

const ALLOWED_OPERATIONS: [&str; 4] = [
    "ak.gate.account.command.issue_identity_binding_challenge",
    "ak.gate.account.command.register",
    "ak.gate.account.command.issue_session_grant",
    "ak.gate.account.command.issue_recovery_completion_grant",
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
             registry_receipt, head_event_digest, pcr_genesis_request_digest, \
             pcr_genesis_receipt, binding_receipt, register_handoff_grant_id, \
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
             purpose, principal_id, operation_digest, pcr_realm_id, realm_create_payload_digest, \
             founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience, \
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
             purpose, principal_id, operation_digest, pcr_realm_id, realm_create_payload_digest, \
             founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience, \
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
    #[diesel(sql_type = Nullable<Text>)]
    pcr_genesis_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pcr_genesis_receipt: Option<serde_json::Value>,
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
        pcr_genesis_request_digest: row
            .pcr_genesis_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        pcr_genesis_receipt: row
            .pcr_genesis_receipt
            .map(serde_json::from_value)
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
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    realm_create_payload_digest: String,
    #[diesel(sql_type = Text)]
    founding_authorize_payload_digest: String,
    #[diesel(sql_type = Text)]
    initial_session_request_digest: String,
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
    if row.purpose != "account_binding_and_pcr_genesis" {
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
        purpose: arkret_models_identity::IdentityBindingPurpose::AccountBindingAndPcrGenesis,
        principal_id: arkret_identifiers::Did::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        operation_digest: arkret_identifiers::Hash::new(row.operation_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        pcr_realm_id: arkret_identifiers::RealmId::new(row.pcr_realm_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        realm_create_payload_digest: arkret_identifiers::Hash::new(row.realm_create_payload_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        founding_authorize_payload_digest: arkret_identifiers::Hash::new(
            row.founding_authorize_payload_digest,
        )
        .map_err(|_| DatabaseError::invalid_operation())?,
        initial_session_request_digest: arkret_identifiers::Hash::new(
            row.initial_session_request_digest,
        )
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
        && challenge.pcr_realm_id == expected.pcr_realm_id
        && challenge.realm_create_payload_digest == expected.realm_create_payload_digest
        && challenge.founding_authorize_payload_digest == expected.founding_authorize_payload_digest
        && challenge.initial_session_request_digest == expected.initial_session_request_digest
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

    async fn get_by_token(
        &mut self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error> {
        let row = diesel::sql_query(
            "SELECT id, request_id, request_digest, service_account_id, browser_session_id, \
             audience, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
             revoked_at, consumed_at FROM account_handoff_grants \
             WHERE account_handoff_grant = $1 AND expires_at > $2 AND revoked_at IS NULL",
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
        if matches!(
            lease.state,
            IdentityCreationSagaState::AccountBound | IdentityCreationSagaState::Completed
        ) {
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
        if matches!(
            lease.state,
            IdentityCreationSagaState::AccountBound | IdentityCreationSagaState::Completed
        ) {
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
            || matches!(
                lease.state,
                IdentityCreationSagaState::AccountBound | IdentityCreationSagaState::Completed
            )
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
             state = CASE WHEN state <> 'active' THEN state ELSE 'reserved' END, \
             expires_at = GREATEST(expires_at, $6), updated_at = $7 \
             WHERE service_account_id = $1 AND audience = $2 AND lease_id = $8 \
             AND fence = $9 AND holder_jkt = $10 \
             AND state IN ('active', 'reserved', 'did_published', 'pcr_accepted', 'account_bound')",
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
              principal_id, operation_digest, pcr_realm_id, realm_create_payload_digest, \
              founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience, origin, \
              trust_domain, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'account_binding_and_pcr_genesis', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(&input.challenge_id)
        .bind::<Text, _>(&input.challenge)
        .bind::<Text, _>(reserved.principal_id.as_str())
        .bind::<Text, _>(input.operation_digest.as_str())
        .bind::<Text, _>(input.pcr_realm_id.as_str())
        .bind::<Text, _>(input.realm_create_payload_digest.as_str())
        .bind::<Text, _>(input.founding_authorize_payload_digest.as_str())
        .bind::<Text, _>(input.initial_session_request_digest.as_str())
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
            // Serialize with the final completion transaction so a concurrent
            // retry cannot observe AccountBound immediately before the
            // Standard grant and exact replay outcome commit.
            .lease_for_account(Uuid::from(grant.service_account_id), &grant.audience, true)
            .await?
        else {
            return Ok(IdentityCreationRegisterReplay::Pending);
        };
        if lease.state != IdentityCreationSagaState::Completed {
            return Ok(IdentityCreationRegisterReplay::Pending);
        }
        let Some(ledger) = lease.register_ledger else {
            // A completed row without its replay ledger cannot prove that an
            // incoming body is byte-for-byte the completed request.
            return Ok(IdentityCreationRegisterReplay::DuplicateConflict);
        };
        if lease.lease_id != lease_id
            || lease.fence != lease_fence
            || lease.holder_jkt != grant.cnf_jkt
            || ledger.handoff_grant_id != grant.id
            || ledger.challenge_id != challenge_id
            || ledger.request_digest != *request_digest
        {
            return Ok(IdentityCreationRegisterReplay::DuplicateConflict);
        }
        Ok(IdentityCreationRegisterReplay::Replay(Box::new(
            ledger.outcome,
        )))
    }

    async fn mark_did_published(
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
            || lease.expires_at <= now
            || lease.reserved_identity.as_ref().is_none_or(|reserved| {
                reserved.operation_digest != context.challenge.operation_digest
            })
            || !matches!(
                lease.state,
                IdentityCreationSagaState::Reserved | IdentityCreationSagaState::DidPublished
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
        if !challenge_matches_context(&challenge, context)
            || challenge.replaced_at.is_some()
            || challenge.expires_at <= now
        {
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
            (IdentityCreationSagaState::DidPublished, IdentityCreationSagaState::DidPublished) => {
                if challenge.consumed_at.is_none() {
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
            }
            _ => return Ok(false),
        }
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'did_published', registry_receipt = $1, \
             head_event_digest = $2, updated_at = $3 \
             WHERE service_account_id = $4 AND audience = $5 AND lease_id = $6 AND fence = $7 \
             AND holder_jkt = $8 AND reserved_operation_digest = $9 \
             AND state IN ('reserved', 'did_published')",
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

    async fn mark_pcr_accepted(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        request_digest: &arkret_identifiers::Hash,
        receipt: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome,
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
                IdentityCreationSagaState::DidPublished | IdentityCreationSagaState::PcrAccepted
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
        if !challenge_matches_context(&challenge, context)
            || challenge.consumed_at.is_none()
            || challenge.replaced_at.is_some()
        {
            return Ok(false);
        }
        if lease.state == IdentityCreationSagaState::PcrAccepted {
            let stored = lease
                .pcr_genesis_receipt
                .as_ref()
                .and_then(|stored| arkret_canonical::canonical_json_bytes(stored).ok());
            let received = arkret_canonical::canonical_json_bytes(receipt).ok();
            return Ok(
                lease.pcr_genesis_request_digest.as_ref() == Some(request_digest)
                    && stored.is_some()
                    && stored == received,
            );
        }
        let receipt =
            serde_json::to_value(receipt).map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'pcr_accepted', \
             pcr_genesis_request_digest = $1, pcr_genesis_receipt = $2, updated_at = $3 \
             WHERE service_account_id = $4 AND audience = $5 AND lease_id = $6 AND fence = $7 \
             AND holder_jkt = $8 AND state = 'did_published'",
        )
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Jsonb, _>(receipt)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.service_account_id))
        .bind::<Text, _>(&context.grant.audience)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(context.lease.fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }

    async fn mark_account_bound(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        binding_receipt: &arkret_models_identity::AccountBindingReceipt,
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
            || lease.state != IdentityCreationSagaState::PcrAccepted
            || lease.pcr_genesis_receipt.is_none()
        {
            return Ok(false);
        }
        if binding_receipt.identity_creation_lease_id != lease.lease_id
            || binding_receipt.lease_fence != lease.fence
            || binding_receipt.operation_digest != context.challenge.operation_digest
            || lease.head_event_digest.as_ref() != Some(&binding_receipt.head_event_digest)
        {
            return Ok(false);
        }
        let Some(challenge) = self
            .challenge_by_id(&context.challenge.challenge_id, true)
            .await?
        else {
            return Ok(false);
        };
        if !challenge_matches_context(&challenge, context)
            || challenge.consumed_at.is_none()
            || challenge.replaced_at.is_some()
        {
            return Ok(false);
        }
        let receipt = serde_json::to_value(binding_receipt)
            .map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'account_bound', binding_receipt = $1, \
             updated_at = $2 WHERE service_account_id = $3 AND audience = $4 \
             AND lease_id = $5 AND fence = $6 AND holder_jkt = $7 \
             AND reserved_operation_digest = $8 AND state = 'pcr_accepted'",
        )
        .bind::<Jsonb, _>(receipt)
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

    async fn mark_completed(
        &mut self,
        context: &IdentityCreationRegistrationContext,
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
        if lease.state == IdentityCreationSagaState::Completed {
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
        if lease.state != IdentityCreationSagaState::AccountBound
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

        let outcome =
            serde_json::to_value(outcome).map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'completed', \
             register_handoff_grant_id = $1, register_challenge_id = $2, \
             register_request_digest = $3, register_outcome = $4, updated_at = $5 \
             WHERE service_account_id = $6 AND audience = $7 \
             AND lease_id = $8 AND fence = $9 AND holder_jkt = $10 \
             AND reserved_operation_digest = $11 AND state = 'account_bound'",
        )
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
        // A reclaimed lease may issue a fresh holder-bound challenge after the
        // DID was published but before PCR genesis. `mark_did_published`
        // consumes that replacement challenge without republishing the DID.
        IdentityCreationSagaState::DidPublished => true,
        IdentityCreationSagaState::PcrAccepted | IdentityCreationSagaState::AccountBound => {
            challenge_consumed
        }
        IdentityCreationSagaState::Active | IdentityCreationSagaState::Completed => false,
    }
}

#[cfg(all(test, any()))]
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
            IdentityCreationSagaState::DidPublished,
            true,
        ));
        assert!(!registration_challenge_state_is_usable(
            IdentityCreationSagaState::DidPublished,
            false,
        ));
        assert!(!registration_challenge_state_is_usable(
            IdentityCreationSagaState::Completed,
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
            "UPDATE identity_creation_leases SET state = 'completed' \
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
                .mark_did_published(
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
                .mark_completed(&context, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Committed
        ));

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
                .mark_did_published(&stale_context, &registry_receipt, &head, now)
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
                .mark_did_published(
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
                .mark_completed(&context, &request_digest, &outcome, now)
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
        assert_eq!(
            recovered.lease.state,
            IdentityCreationSagaState::DidPublished
        );
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
                .mark_completed(&foreign_request, &request_digest, &outcome, now)
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
                .mark_completed(&tampered, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Stale
        ));
        let mut foreign_holder = recovered.clone();
        foreign_holder.grant.cnf_jkt = "Z".repeat(43);
        assert!(matches!(
            repo.account_handoff()
                .mark_completed(&foreign_holder, &request_digest, &outcome, now)
                .await
                .unwrap(),
            IdentityCreationBindingCommit::Stale
        ));

        // Only the original context completes the saga, and the founding
        // device claim works solely for the reserved principal.
        assert!(matches!(
            repo.account_handoff()
                .mark_completed(&recovered, &request_digest, &outcome, now)
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

        repo.cancel().await.unwrap();
    }
}
