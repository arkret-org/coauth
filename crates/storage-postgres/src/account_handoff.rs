//! PostgreSQL account-handoff state machine.

use arkret_models_identity::IdentityCreationLeaseState;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::account_handoff::{
    AccountHandoffCreation, AccountHandoffCreationAttempt, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffCreationAttemptState, AccountHandoffGrant,
    AccountHandoffGrantInput, ControllerGateAttestationCommit, ControllerGateAttestationIssuance,
    ControllerGateAttestationReserve, DidBindingChallengeConsume, DidBindingChallengeInput,
    DidBindingChallengeIssue, DidBindingChallengeRecord, IdentityAbandonmentChallengeInput,
    IdentityAbandonmentChallengeIssue, IdentityAbandonmentChallengeRecord,
    IdentityAbandonmentCommit, IdentityAbandonmentCommitInput, IdentityBindingChallengeInput,
    IdentityBindingChallengeIssue, IdentityBindingChallengeRecord, IdentityCreationBindingCommit,
    IdentityCreationLeaseRecord, IdentityCreationLeaseRiskDecision, IdentityCreationRegisterLedger,
    IdentityCreationRegisterReplay, IdentityCreationRegistrationContext,
    NewAccountHandoffCreationAttempt, NewControllerGateAttestationIssuance,
    PublishedDidRegisterCommit, PublishedDidRegisterReplay,
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

const ALLOWED_OPERATIONS: [&str; 7] = [
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_ABANDONMENT_CHALLENGE_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1,
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

fn reserved_identity_matches_abandonment_checkpoint(
    reserved: &arkret_models_identity::ReservedIdentityCreation,
    principal_id: &arkret_identifiers::DidCoreId,
    did_version_id: &str,
) -> bool {
    reserved.principal_id == *principal_id
        && reserved
            .did_operation
            .operation
            .get("versionId")
            .and_then(serde_json::Value::as_str)
            == Some(did_version_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingDidBindingChallengeDisposition {
    Replay,
    DuplicateConflict,
    StaleRequest,
}

fn classify_existing_did_binding_challenge(
    existing_request_digest: &arkret_identifiers::Hash,
    existing_issuing_handoff_grant_id: Ulid,
    existing_consumed_at: Option<DateTime<Utc>>,
    existing_expires_at: DateTime<Utc>,
    requested_digest: &arkret_identifiers::Hash,
    requested_issuing_handoff_grant_id: Ulid,
    requested_at: DateTime<Utc>,
) -> ExistingDidBindingChallengeDisposition {
    if existing_request_digest != requested_digest
        || existing_issuing_handoff_grant_id != requested_issuing_handoff_grant_id
    {
        return ExistingDidBindingChallengeDisposition::DuplicateConflict;
    }
    if existing_consumed_at.is_some() || existing_expires_at <= requested_at {
        return ExistingDidBindingChallengeDisposition::StaleRequest;
    }
    ExistingDidBindingChallengeDisposition::Replay
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

    async fn controller_gate_issuance(
        &mut self,
        request_id: Uuid,
        for_update: bool,
    ) -> Result<Option<ControllerGateAttestationIssuance>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, canonical_intent_digest, principal_id, \
             agent_authority_id, canonical_outcome, outcome_digest, \
             attestation_expires_at, retained_until, created_at, committed_at \
             FROM controller_gate_attestation_issuances WHERE request_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<SqlUuid, _>(request_id)
            .get_result::<ControllerGateAttestationIssuanceRow>(self.conn)
            .await
            .optional()?
            .map(controller_gate_issuance_from_row)
            .transpose()
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
             registry_receipt, head_event_digest, registration_did_evidence, pcr_genesis_request_digest, \
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
    ) -> Result<Option<(arkret_identifiers::DidCoreId, arkret_identifiers::Did)>, DatabaseError>
    {
        let row = diesel::sql_query(
            "SELECT owners.principal_id, bindings.verified_did \
             FROM principal_did_bindings bindings \
             JOIN principal_did_owners owners ON owners.id = bindings.principal_did_owner_id \
             WHERE bindings.user_id = $1 AND bindings.audience = $2",
        )
        .bind::<SqlUuid, _>(service_account_id)
        .bind::<Text, _>(audience)
        .get_result::<PrincipalRow>(self.conn)
        .await
        .optional()?;
        row.map(|row| {
            Ok((
                row.principal_id,
                arkret_identifiers::Did::new(row.verified_did)
                    .map_err(|_| DatabaseError::invalid_operation())?,
            ))
        })
        .transpose()
    }

    async fn challenge_by_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<IdentityBindingChallengeRecord>, DatabaseError> {
        let row = diesel::sql_query(
            "SELECT request_id, request_digest, service_account_id, challenge_id, challenge, \
             purpose, account_subject, principal_id, did, operation_digest, did_version_id, log_head_digest, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
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
             purpose, account_subject, principal_id, did, operation_digest, did_version_id, log_head_digest, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
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

    async fn did_binding_challenge_by_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<DidBindingChallengeRecord>, DatabaseError> {
        diesel::sql_query(
            "SELECT request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
             account_subject, principal_id, did, did_version_id, log_head_digest, \
             control_key_digest, witness_evidence, challenge_id, challenge, dpop_jkt, audience, \
             origin, trust_domain, issued_at, expires_at, consumed_at, register_request_digest, \
             register_outcome FROM did_binding_challenges WHERE request_id = $1",
        )
        .bind::<SqlUuid, _>(request_id)
        .get_result::<DidBindingChallengeRow>(self.conn)
        .await
        .optional()?
        .map(did_binding_challenge_from_row)
        .transpose()
    }

    async fn did_binding_challenge_by_id(
        &mut self,
        challenge_id: &str,
        for_update: bool,
    ) -> Result<Option<DidBindingChallengeRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
             account_subject, principal_id, did, did_version_id, log_head_digest, \
             control_key_digest, witness_evidence, challenge_id, challenge, dpop_jkt, audience, \
             origin, trust_domain, issued_at, expires_at, consumed_at, register_request_digest, \
             register_outcome FROM did_binding_challenges WHERE challenge_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<Text, _>(challenge_id)
            .get_result::<DidBindingChallengeRow>(self.conn)
            .await
            .optional()?
            .map(did_binding_challenge_from_row)
            .transpose()
    }

    async fn abandonment_challenge_by_request(
        &mut self,
        request_id: Uuid,
        for_update: bool,
    ) -> Result<Option<IdentityAbandonmentChallengeRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
             audience, account_subject, holder_jkt, lease_id, lease_fence, principal_id, \
             did_version_id, challenge_id, challenge, origin, trust_domain, issued_at, expires_at, \
             consumed_at, confirmation_request_id, confirmation_request_digest, outcome \
             FROM identity_abandonment_challenges WHERE request_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<SqlUuid, _>(request_id)
            .get_result::<AbandonmentChallengeRow>(self.conn)
            .await
            .optional()?
            .map(abandonment_challenge_from_row)
            .transpose()
    }

    async fn abandonment_challenge_by_id(
        &mut self,
        challenge_id: &str,
        for_update: bool,
    ) -> Result<Option<IdentityAbandonmentChallengeRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
             audience, account_subject, holder_jkt, lease_id, lease_fence, principal_id, \
             did_version_id, challenge_id, challenge, origin, trust_domain, issued_at, expires_at, \
             consumed_at, confirmation_request_id, confirmation_request_digest, outcome \
             FROM identity_abandonment_challenges WHERE challenge_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<Text, _>(challenge_id)
            .get_result::<AbandonmentChallengeRow>(self.conn)
            .await
            .optional()?
            .map(abandonment_challenge_from_row)
            .transpose()
    }

    async fn abandonment_challenge_by_confirmation_request(
        &mut self,
        request_id: Uuid,
        for_update: bool,
    ) -> Result<Option<IdentityAbandonmentChallengeRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
             audience, account_subject, holder_jkt, lease_id, lease_fence, principal_id, \
             did_version_id, challenge_id, challenge, origin, trust_domain, issued_at, expires_at, \
             consumed_at, confirmation_request_id, confirmation_request_digest, outcome \
             FROM identity_abandonment_challenges WHERE confirmation_request_id = $1{suffix}"
        );
        diesel::sql_query(query)
            .bind::<SqlUuid, _>(request_id)
            .get_result::<AbandonmentChallengeRow>(self.conn)
            .await
            .optional()?
            .map(abandonment_challenge_from_row)
            .transpose()
    }

    async fn suppress_reserved_identity_checkpoints(
        &mut self,
        service_account_id: Ulid,
        lease_id: &str,
        abandoned_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let rows = diesel::sql_query(
            "SELECT request_id, canonical_outcome FROM account_handoff_creation_attempts \
             WHERE state = 'committed' AND canonical_outcome IS NOT NULL \
             AND authorization_checkpoint ->> 'service_account_id' = $1 FOR UPDATE",
        )
        .bind::<Text, _>(service_account_id.to_string())
        .load::<CommittedHandoffOutcomeRow>(self.conn)
        .await?;
        for row in rows {
            let mut outcome: arkret_models_identity::AccountHandoffOutcome =
                serde_json::from_slice(&row.canonical_outcome)
                    .map_err(|_| DatabaseError::invalid_operation())?;
            let arkret_models_identity::AccountHandoffBinding::IdentityCreationActive {
                identity_creation_lease,
            } = &mut outcome.binding
            else {
                continue;
            };
            if identity_creation_lease.identity_creation_lease_id != lease_id {
                continue;
            }
            identity_creation_lease.reserved_identity = None;
            identity_creation_lease.expires_at = abandoned_at;
            let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
                .map_err(|_| DatabaseError::invalid_operation())?;
            let outcome_digest = format!("sha256:{:x}", sha2::Sha256::digest(&canonical_outcome));
            let updated = diesel::sql_query(
                "UPDATE account_handoff_creation_attempts SET canonical_outcome = $2, \
                 outcome_digest = $3 WHERE request_id = $1 AND state = 'committed'",
            )
            .bind::<SqlUuid, _>(row.request_id)
            .bind::<Bytea, _>(canonical_outcome)
            .bind::<Text, _>(outcome_digest)
            .execute(self.conn)
            .await?;
            if updated != 1 {
                return Err(DatabaseError::invalid_operation());
            }
        }
        Ok(())
    }

    async fn server_now(&mut self) -> Result<DateTime<Utc>, DatabaseError> {
        Ok(diesel::sql_query("SELECT CURRENT_TIMESTAMP AS now")
            .get_result::<ServerNowRow>(self.conn)
            .await?
            .now)
    }

    async fn account_risk_allows_identity_creation(
        &mut self,
        service_account_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        // Hold a share lock until the lease transaction commits. A concurrent
        // status transition therefore cannot race between this fail-closed
        // check and quota/lease consumption.
        Ok(
            diesel::sql_query("SELECT status FROM users WHERE id = $1 FOR SHARE")
                .bind::<SqlUuid, _>(service_account_id)
                .get_result::<AccountStatusRow>(self.conn)
                .await
                .optional()?
                .is_some_and(|row| row.status == "active"),
        )
    }

    async fn lock_lease_quota(
        &mut self,
        account_subject: &arkret_identifiers::Hash,
        audience: &str,
    ) -> Result<(), DatabaseError> {
        // Serialize the no-row acquisition case as well as renewal. PostgreSQL
        // `text` cannot contain NUL bytes, so use a length-prefixed transcript
        // rather than the protocol-style NUL separator used by some hashes.
        let key = lease_quota_advisory_key(account_subject, audience);
        // A PostgreSQL `void` result is not SQL NULL. Select a sentinel row
        // from the volatile lock function instead of testing the result with
        // `IS NULL`, which is always false and trips the debug assertion.
        let lock = diesel::sql_query(
            "SELECT TRUE AS locked \
             FROM pg_advisory_xact_lock(hashtextextended($1, 0))",
        )
        .bind::<Text, _>(key)
        .get_result::<AdvisoryLockRow>(self.conn)
        .await?;
        debug_assert!(lock.locked);
        Ok(())
    }

    async fn quota_event_exists(
        &mut self,
        request_id: Uuid,
        action: &str,
    ) -> Result<bool, DatabaseError> {
        Ok(diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM identity_creation_lease_rate_limit_events \
             WHERE request_id = $1 AND action = $2) AS present",
        )
        .bind::<SqlUuid, _>(request_id)
        .bind::<Text, _>(action)
        .get_result::<ExistsRow>(self.conn)
        .await?
        .present)
    }

    async fn consume_acquisition_quota(
        &mut self,
        request_id: Uuid,
        account_subject: &arkret_identifiers::Hash,
        audience: &str,
        lease_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, DatabaseError> {
        if self.quota_event_exists(request_id, "acquisition").await? {
            return Ok(None);
        }
        let window = diesel::sql_query(
            "SELECT COUNT(*)::bigint AS count, MIN(occurred_at) AS oldest_at \
             FROM identity_creation_lease_rate_limit_events \
             WHERE account_subject = $1 AND audience = $2 AND action = 'acquisition' \
             AND occurred_at > $3",
        )
        .bind::<Text, _>(account_subject.as_str())
        .bind::<Text, _>(audience)
        .bind::<Timestamptz, _>(now - Duration::minutes(10))
        .get_result::<RateWindowRow>(self.conn)
        .await?;
        if window.count >= 5 {
            let retry_at = window
                .oldest_at
                .ok_or_else(DatabaseError::invalid_operation)?
                + Duration::minutes(10);
            return Ok(Some(retry_after_ms(retry_at, now)));
        }
        self.insert_quota_event(
            request_id,
            account_subject,
            audience,
            lease_id,
            "acquisition",
        )
        .await?;
        Ok(None)
    }

    async fn consume_renewal_quota(
        &mut self,
        request_id: Uuid,
        account_subject: &arkret_identifiers::Hash,
        audience: &str,
        lease_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, DatabaseError> {
        if self.quota_event_exists(request_id, "renewal").await? {
            return Ok(None);
        }
        let minute = self
            .renewal_window(lease_id, now - Duration::minutes(1))
            .await?;
        let hour = self
            .renewal_window(lease_id, now - Duration::hours(1))
            .await?;
        let mut retry_at = None;
        if minute.count >= 1 {
            retry_at = minute.oldest_at.map(|value| value + Duration::minutes(1));
        }
        if hour.count >= 12 {
            let hour_retry = hour.oldest_at.map(|value| value + Duration::hours(1));
            retry_at = retry_at.max(hour_retry);
        }
        if let Some(retry_at) = retry_at {
            return Ok(Some(retry_after_ms(retry_at, now)));
        }
        self.insert_quota_event(request_id, account_subject, audience, lease_id, "renewal")
            .await?;
        Ok(None)
    }

    async fn renewal_window(
        &mut self,
        lease_id: &str,
        since: DateTime<Utc>,
    ) -> Result<RateWindowRow, DatabaseError> {
        Ok(diesel::sql_query(
            "SELECT COUNT(*)::bigint AS count, MIN(occurred_at) AS oldest_at \
             FROM identity_creation_lease_rate_limit_events \
             WHERE lease_id = $1 AND action = 'renewal' AND occurred_at > $2",
        )
        .bind::<Text, _>(lease_id)
        .bind::<Timestamptz, _>(since)
        .get_result::<RateWindowRow>(self.conn)
        .await?)
    }

    async fn insert_quota_event(
        &mut self,
        request_id: Uuid,
        account_subject: &arkret_identifiers::Hash,
        audience: &str,
        lease_id: &str,
        action: &str,
    ) -> Result<(), DatabaseError> {
        diesel::sql_query(
            "INSERT INTO identity_creation_lease_rate_limit_events \
             (request_id, account_subject, audience, lease_id, action) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (request_id, action) DO NOTHING",
        )
        .bind::<SqlUuid, _>(request_id)
        .bind::<Text, _>(account_subject.as_str())
        .bind::<Text, _>(audience)
        .bind::<Text, _>(lease_id)
        .bind::<Text, _>(action)
        .execute(self.conn)
        .await?;
        Ok(())
    }
}

fn lease_quota_advisory_key(account_subject: &arkret_identifiers::Hash, audience: &str) -> String {
    let account_subject = account_subject.as_str();
    format!("{}:{account_subject}{audience}", account_subject.len())
}

#[derive(QueryableByName)]
struct ServerNowRow {
    #[diesel(sql_type = Timestamptz)]
    now: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct AccountStatusRow {
    #[diesel(sql_type = Text)]
    status: String,
}

#[derive(QueryableByName)]
struct AdvisoryLockRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    locked: bool,
}

#[derive(QueryableByName)]
struct ExistsRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct RateWindowRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    oldest_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct PrincipalRow {
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    verified_did: String,
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

#[derive(QueryableByName)]
struct ControllerGateAttestationIssuanceRow {
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Text)]
    canonical_intent_digest: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    agent_authority_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Nullable<Bytea>)]
    canonical_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    outcome_digest: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    attestation_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Timestamptz)]
    retained_until: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    committed_at: Option<DateTime<Utc>>,
}

fn controller_gate_issuance_from_row(
    row: ControllerGateAttestationIssuanceRow,
) -> Result<ControllerGateAttestationIssuance, DatabaseError> {
    Ok(ControllerGateAttestationIssuance {
        request_id: arkret_identifiers::RequestId::from_uuid(row.request_id),
        canonical_intent_digest: arkret_identifiers::Hash::new(row.canonical_intent_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        principal_id: row.principal_id,
        agent_authority_id: row.agent_authority_id,
        canonical_outcome: row.canonical_outcome,
        outcome_digest: row
            .outcome_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        attestation_expires_at: row.attestation_expires_at,
        retained_until: row.retained_until,
        created_at: row.created_at,
        committed_at: row.committed_at,
    })
}

#[derive(QueryableByName)]
struct CommittedHandoffOutcomeRow {
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Bytea)]
    canonical_outcome: Vec<u8>,
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
        authorization_checkpoint: row
            .authorization_checkpoint
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
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
    reserved_principal_id: Option<arkret_identifiers::DidCoreId>,
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
    registration_did_evidence: Option<serde_json::Value>,
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
            let did_operation = serde_json::from_value(did_operation)
                .map_err(|_| DatabaseError::invalid_operation())?;
            let reserved =
                arkret_models_identity::ReservedIdentityCreation::from_operation(did_operation)
                    .map_err(|_| DatabaseError::invalid_operation())?;
            if reserved.principal_id != principal_id
                || reserved.operation_digest.as_str() != operation_digest
            {
                return Err(DatabaseError::invalid_operation());
            }
            Some(reserved)
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
        state: IdentityCreationLeaseState::try_from(row.state.as_str())
            .map_err(|_| DatabaseError::invalid_operation())?,
        registry_receipt: row
            .registry_receipt
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        head_event_digest: row
            .head_event_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        registration_did_evidence: row
            .registration_did_evidence
            .map(serde_json::from_value)
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
    account_subject: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    operation_digest: String,
    #[diesel(sql_type = Text)]
    did_version_id: String,
    #[diesel(sql_type = Text)]
    log_head_digest: String,
    #[diesel(sql_type = Text)]
    control_key_digest: String,
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
    audience: arkret_identifiers::DidCoreId,
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

#[derive(QueryableByName)]
struct DidBindingChallengeRow {
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = SqlUuid)]
    issuing_handoff_grant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    service_account_id: Uuid,
    #[diesel(sql_type = Text)]
    account_subject: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    did_version_id: String,
    #[diesel(sql_type = Text)]
    log_head_digest: String,
    #[diesel(sql_type = Text)]
    control_key_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    witness_evidence: Option<String>,
    #[diesel(sql_type = Text)]
    challenge_id: String,
    #[diesel(sql_type = Text)]
    challenge: String,
    #[diesel(sql_type = Text)]
    dpop_jkt: String,
    #[diesel(sql_type = Text)]
    audience: arkret_identifiers::DidCoreId,
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
    #[diesel(sql_type = Nullable<Text>)]
    register_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    register_outcome: Option<serde_json::Value>,
}

fn did_binding_challenge_from_row(
    row: DidBindingChallengeRow,
) -> Result<DidBindingChallengeRecord, DatabaseError> {
    Ok(DidBindingChallengeRecord {
        input: DidBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                row.request_id
            ))
            .map_err(|_| DatabaseError::invalid_operation())?,
            request_digest: arkret_identifiers::Hash::new(row.request_digest)
                .map_err(|_| DatabaseError::invalid_operation())?,
            issuing_handoff_grant_id: Ulid::from(row.issuing_handoff_grant_id),
            service_account_id: Ulid::from(row.service_account_id),
            account_subject: arkret_identifiers::Hash::new(row.account_subject)
                .map_err(|_| DatabaseError::invalid_operation())?,
            principal_id: row.principal_id,
            did: arkret_identifiers::Did::new(row.did)
                .map_err(|_| DatabaseError::invalid_operation())?,
            did_version_id: row.did_version_id,
            log_head_digest: arkret_identifiers::Hash::new(row.log_head_digest)
                .map_err(|_| DatabaseError::invalid_operation())?,
            control_key_digest: arkret_identifiers::Hash::new(row.control_key_digest)
                .map_err(|_| DatabaseError::invalid_operation())?,
            witness_evidence: row.witness_evidence,
            challenge_id: row.challenge_id,
            challenge: row.challenge,
            dpop_jkt: row.dpop_jkt,
            audience: row.audience,
            origin: row.origin,
            trust_domain: arkret_identifiers::TrustDomainId::new(row.trust_domain)
                .map_err(|_| DatabaseError::invalid_operation())?,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
        },
        consumed_at: row.consumed_at,
        register_request_digest: row
            .register_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        register_outcome: row
            .register_outcome
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?
            .map(Box::new),
    })
}

#[derive(QueryableByName)]
struct AbandonmentChallengeRow {
    #[diesel(sql_type = SqlUuid)]
    request_id: Uuid,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = SqlUuid)]
    issuing_handoff_grant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    service_account_id: Uuid,
    #[diesel(sql_type = Text)]
    audience: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    account_subject: String,
    #[diesel(sql_type = Text)]
    holder_jkt: String,
    #[diesel(sql_type = Text)]
    lease_id: String,
    #[diesel(sql_type = BigInt)]
    lease_fence: i64,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    did_version_id: String,
    #[diesel(sql_type = Text)]
    challenge_id: String,
    #[diesel(sql_type = Text)]
    challenge: String,
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
    #[diesel(sql_type = Nullable<SqlUuid>)]
    confirmation_request_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    confirmation_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<serde_json::Value>,
}

fn abandonment_challenge_from_row(
    row: AbandonmentChallengeRow,
) -> Result<IdentityAbandonmentChallengeRecord, DatabaseError> {
    Ok(IdentityAbandonmentChallengeRecord {
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))
            .map_err(|_| DatabaseError::invalid_operation())?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        issuing_handoff_grant_id: Ulid::from(row.issuing_handoff_grant_id),
        service_account_id: Ulid::from(row.service_account_id),
        audience: row.audience,
        account_subject: arkret_identifiers::Hash::new(row.account_subject)
            .map_err(|_| DatabaseError::invalid_operation())?,
        holder_jkt: row.holder_jkt,
        lease_id: row.lease_id,
        lease_fence: u64::try_from(row.lease_fence)
            .map_err(|_| DatabaseError::invalid_operation())?,
        principal_id: row.principal_id,
        did_version_id: row.did_version_id,
        challenge_id: row.challenge_id,
        challenge: row.challenge,
        origin: row.origin,
        trust_domain: arkret_identifiers::TrustDomainId::new(row.trust_domain)
            .map_err(|_| DatabaseError::invalid_operation())?,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        consumed_at: row.consumed_at,
        confirmation_request_id: row
            .confirmation_request_id
            .map(|id| arkret_identifiers::RequestId::new(format!("ak:request:{id}")))
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        confirmation_request_digest: row
            .confirmation_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        outcome: row
            .outcome
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
    })
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
        account_subject: arkret_identifiers::Hash::new(row.account_subject)
            .map_err(|_| DatabaseError::invalid_operation())?,
        principal_id: row.principal_id,
        did: arkret_identifiers::Did::new(row.did)
            .map_err(|_| DatabaseError::invalid_operation())?,
        operation_digest: arkret_identifiers::Hash::new(row.operation_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        did_version_id: row.did_version_id,
        log_head_digest: arkret_identifiers::Hash::new(row.log_head_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        control_key_digest: arkret_identifiers::Hash::new(row.control_key_digest)
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
        audience: row.audience,
        origin: row.origin,
        trust_domain: arkret_identifiers::TrustDomainId::new(row.trust_domain)
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
        && challenge.account_subject == expected.account_subject
        && challenge.principal_id == expected.principal_id
        && challenge.did == expected.did
        && challenge.operation_digest == expected.operation_digest
        && challenge.did_version_id == expected.did_version_id
        && challenge.log_head_digest == expected.log_head_digest
        && challenge.control_key_digest == expected.control_key_digest
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

    async fn reserve_controller_gate_attestation(
        &mut self,
        input: NewControllerGateAttestationIssuance,
    ) -> Result<ControllerGateAttestationReserve, Self::Error> {
        if input.retained_until <= input.now {
            return Err(DatabaseError::invalid_operation());
        }
        let inserted = diesel::sql_query(
            "INSERT INTO controller_gate_attestation_issuances \
             (request_id, canonical_intent_digest, principal_id, \
              agent_authority_id, retained_until, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.canonical_intent_digest.as_str())
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(input.agent_authority_id.as_str())
        .bind::<Timestamptz, _>(input.retained_until)
        .bind::<Timestamptz, _>(input.now)
        .execute(self.conn)
        .await?
            == 1;
        let issuance = self
            .controller_gate_issuance(input.request_id.uuid(), true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if issuance.canonical_intent_digest != input.canonical_intent_digest
            || issuance.principal_id != input.principal_id
            || issuance.agent_authority_id != input.agent_authority_id
        {
            return Ok(ControllerGateAttestationReserve::Conflict(issuance));
        }
        if issuance.retained_until <= input.now {
            return Ok(ControllerGateAttestationReserve::Indeterminate(issuance));
        }
        if inserted {
            return Ok(ControllerGateAttestationReserve::Reserved(issuance));
        }
        if issuance.canonical_outcome.is_some() {
            Ok(ControllerGateAttestationReserve::Replay(issuance))
        } else {
            Ok(ControllerGateAttestationReserve::Indeterminate(issuance))
        }
    }

    async fn commit_controller_gate_attestation(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        canonical_outcome: &[u8],
        outcome_digest: &arkret_identifiers::Hash,
        attestation_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<ControllerGateAttestationCommit, Self::Error> {
        if !canonical_json_digest_matches(canonical_outcome, outcome_digest)
            || attestation_expires_at <= now
            || attestation_expires_at - now > Duration::minutes(5)
        {
            return Err(DatabaseError::invalid_operation());
        }
        let issuance = self
            .controller_gate_issuance(request_id.uuid(), true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if issuance.canonical_intent_digest != *canonical_intent_digest {
            return Ok(ControllerGateAttestationCommit::Conflict(issuance));
        }
        if let Some(existing) = issuance.canonical_outcome.as_ref() {
            return Ok(if existing == canonical_outcome {
                ControllerGateAttestationCommit::Replay(issuance)
            } else {
                ControllerGateAttestationCommit::Conflict(issuance)
            });
        }
        let updated = diesel::sql_query(
            "UPDATE controller_gate_attestation_issuances SET canonical_outcome = $3, \
             outcome_digest = $4, attestation_expires_at = $5, committed_at = $6 \
             WHERE request_id = $1 AND canonical_intent_digest = $2 \
               AND canonical_outcome IS NULL",
        )
        .bind::<SqlUuid, _>(request_id.uuid())
        .bind::<Text, _>(canonical_intent_digest.as_str())
        .bind::<Bytea, _>(canonical_outcome)
        .bind::<Text, _>(outcome_digest.as_str())
        .bind::<Timestamptz, _>(attestation_expires_at)
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        if updated != 1 {
            return Ok(ControllerGateAttestationCommit::Indeterminate(issuance));
        }
        let committed = self
            .controller_gate_issuance(request_id.uuid(), true)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(ControllerGateAttestationCommit::Committed(committed))
    }

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
        checkpoint: &coauth_data::AccountHandoffAuthorizationCheckpoint,
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
        .bind::<Jsonb, _>(
            serde_json::to_value(checkpoint).map_err(|_| DatabaseError::invalid_operation())?,
        )
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

        if let Some((principal_id, did)) = self
            .bound_principal(Uuid::from(input.service_account_id), &input.audience)
            .await?
        {
            let incomplete_lease = self
                .lease_for_account(
                    Uuid::from(input.service_account_id),
                    input.audience.as_str(),
                    false,
                )
                .await?
                .is_some_and(|lease| lease.state == IdentityCreationLeaseState::AccountBound);
            if !incomplete_lease {
                return Ok(AccountHandoffCreation::Bound {
                    grant,
                    principal_id,
                    did,
                });
            }
        }

        if input.risk_decision != IdentityCreationLeaseRiskDecision::Allowed
            || !self
                .account_risk_allows_identity_creation(Uuid::from(input.service_account_id))
                .await?
        {
            return Ok(AccountHandoffCreation::RiskRejected { grant });
        }

        self.lock_lease_quota(&input.account_subject, input.audience.as_str())
            .await?;
        let server_now = self.server_now().await?;
        let existing_lease = self
            .lease_for_account(
                Uuid::from(input.service_account_id),
                input.audience.as_str(),
                true,
            )
            .await?;
        if let Some(lease) = existing_lease.as_ref() {
            if lease.state == IdentityCreationLeaseState::Completed {
                let reserved = lease
                    .reserved_identity
                    .as_ref()
                    .ok_or_else(DatabaseError::invalid_operation)?;
                return Ok(AccountHandoffCreation::Bound {
                    grant,
                    principal_id: reserved.principal_id.clone(),
                    did: reserved.did.clone(),
                });
            }
            if lease.expires_at > input.issued_at && lease.holder_jkt != input.cnf_jkt {
                return Ok(AccountHandoffCreation::Busy {
                    grant,
                    retry_after_ms: retry_after_ms(lease.expires_at, input.issued_at),
                    expires_at: lease.expires_at,
                });
            }
        }

        let is_acquisition = existing_lease
            .as_ref()
            .is_none_or(|lease| lease.expires_at <= input.issued_at);
        let exact_quota_replay = self
            .quota_event_exists(input.request_id.uuid(), "acquisition")
            .await?
            || self
                .quota_event_exists(input.request_id.uuid(), "renewal")
                .await?;
        let retry_after_ms = if exact_quota_replay {
            None
        } else if is_acquisition {
            self.consume_acquisition_quota(
                input.request_id.uuid(),
                &input.account_subject,
                input.audience.as_str(),
                &input.lease_id,
                server_now,
            )
            .await?
        } else {
            let lease = existing_lease
                .as_ref()
                .ok_or_else(DatabaseError::invalid_operation)?;
            self.consume_renewal_quota(
                input.request_id.uuid(),
                &input.account_subject,
                &input.audience,
                &lease.lease_id,
                server_now,
            )
            .await?
        };
        if let Some(retry_after_ms) = retry_after_ms {
            return Ok(AccountHandoffCreation::RateLimited {
                grant,
                retry_after_ms,
            });
        }

        if existing_lease.is_none() {
            diesel::sql_query(
                "INSERT INTO identity_creation_leases \
                 (service_account_id, audience, lease_id, holder_jkt, fence, expires_at, state, \
                  created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, 1, $5, 'active', $6, $6)",
            )
            .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
            .bind::<Text, _>(&input.audience)
            .bind::<Text, _>(&input.lease_id)
            .bind::<Text, _>(&input.cnf_jkt)
            .bind::<Timestamptz, _>(input.lease_expires_at)
            .bind::<Timestamptz, _>(input.issued_at)
            .execute(self.conn)
            .await?;
        } else if is_acquisition {
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
        let lease = self
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
        if grant.expires_at <= now || grant.revoked_at.is_some() {
            return Ok(AccountHandoffCreation::ExpiredReplay);
        }
        let lease = self
            .lease_for_account(Uuid::from(grant.service_account_id), &grant.audience, false)
            .await?;
        let Some(lease) = lease else {
            return if let Some((principal_id, did)) = self
                .bound_principal(Uuid::from(grant.service_account_id), &grant.audience)
                .await?
            {
                Ok(AccountHandoffCreation::Bound {
                    grant: grant.clone(),
                    principal_id,
                    did,
                })
            } else {
                Ok(AccountHandoffCreation::ExpiredReplay)
            };
        };
        if lease.state == IdentityCreationLeaseState::Completed {
            let reserved = lease
                .reserved_identity
                .as_ref()
                .ok_or_else(DatabaseError::invalid_operation)?;
            return Ok(AccountHandoffCreation::Bound {
                grant: grant.clone(),
                principal_id: reserved.principal_id.clone(),
                did: reserved.did.clone(),
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
                expires_at: lease.expires_at,
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

        self.lock_lease_quota(&input.account_subject, input.audience.as_str())
            .await?;
        // A concurrent exact request may have committed while this transaction
        // waited for the quota lock. Re-read before consuming renewal quota or
        // replacing the active challenge so response-loss replay remains
        // byte-for-byte stable across instances.
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
        let server_now = self.server_now().await?;
        let lease = self
            .lease_for_account(
                Uuid::from(input.service_account_id),
                input.audience.as_str(),
                true,
            )
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
                IdentityCreationLeaseState::AccountBound | IdentityCreationLeaseState::Completed
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
        let orphan_anchor_reserved = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM identity_orphan_anchor_tombstones \
             WHERE principal_id = $1) AS present",
        )
        .bind::<Text, _>(input.principal_id.as_str())
        .get_result::<ExistsRow>(self.conn)
        .await?
        .present;
        if orphan_anchor_reserved {
            return Ok(IdentityBindingChallengeIssue::ReservationConflict);
        }

        if let Some(retry_after_ms) = self
            .consume_renewal_quota(
                input.request_id.uuid(),
                &input.account_subject,
                input.audience.as_str(),
                &input.lease_id,
                server_now,
            )
            .await?
        {
            return Ok(IdentityBindingChallengeIssue::RateLimited { retry_after_ms });
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
        .bind::<Text, _>(input.audience.as_str())
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
        .bind::<Text, _>(input.audience.as_str())
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
              account_subject, principal_id, did, operation_digest, did_version_id, log_head_digest, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
              founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience, origin, \
              trust_domain, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'account_binding_and_pcr_genesis', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(&input.challenge_id)
        .bind::<Text, _>(&input.challenge)
        .bind::<Text, _>(input.account_subject.as_str())
        .bind::<Text, _>(reserved.principal_id.as_str())
        .bind::<Text, _>(input.did.as_str())
        .bind::<Text, _>(input.operation_digest.as_str())
        .bind::<Text, _>(&input.did_version_id)
        .bind::<Text, _>(input.log_head_digest.as_str())
        .bind::<Text, _>(input.control_key_digest.as_str())
        .bind::<Text, _>(input.pcr_realm_id.as_str())
        .bind::<Text, _>(input.realm_create_payload_digest.as_str())
        .bind::<Text, _>(input.founding_authorize_payload_digest.as_str())
        .bind::<Text, _>(input.initial_session_request_digest.as_str())
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(i64::try_from(input.lease_fence).map_err(|_| DatabaseError::invalid_operation())?)
        .bind::<Text, _>(&input.holder_jkt)
        .bind::<Text, _>(input.audience.as_str())
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

    async fn issue_did_binding_challenge(
        &mut self,
        input: DidBindingChallengeInput,
    ) -> Result<DidBindingChallengeIssue, Self::Error> {
        let input = DidBindingChallengeInput {
            issued_at: arkret_canonical::normalize_timestamp_canonical(input.issued_at),
            expires_at: arkret_canonical::normalize_timestamp_canonical(input.expires_at),
            ..input
        };
        if let Some(existing) = self
            .did_binding_challenge_by_request(input.request_id.uuid())
            .await?
        {
            return Ok(
                match classify_existing_did_binding_challenge(
                    &existing.input.request_digest,
                    existing.input.issuing_handoff_grant_id,
                    existing.consumed_at,
                    existing.input.expires_at,
                    &input.request_digest,
                    input.issuing_handoff_grant_id,
                    input.issued_at,
                ) {
                    ExistingDidBindingChallengeDisposition::Replay => {
                        DidBindingChallengeIssue::Replay(existing)
                    }
                    ExistingDidBindingChallengeDisposition::DuplicateConflict => {
                        DidBindingChallengeIssue::DuplicateConflict
                    }
                    ExistingDidBindingChallengeDisposition::StaleRequest => {
                        DidBindingChallengeIssue::StaleRequest
                    }
                },
            );
        }
        diesel::sql_query(
            "INSERT INTO did_binding_challenges \
             (request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
              account_subject, principal_id, did, did_version_id, log_head_digest, \
              control_key_digest, witness_evidence, challenge_id, challenge, dpop_jkt, audience, \
              origin, trust_domain, issued_at, expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.issuing_handoff_grant_id))
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(input.account_subject.as_str())
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(input.did.as_str())
        .bind::<Text, _>(&input.did_version_id)
        .bind::<Text, _>(input.log_head_digest.as_str())
        .bind::<Text, _>(input.control_key_digest.as_str())
        .bind::<Nullable<Text>, _>(input.witness_evidence.as_deref())
        .bind::<Text, _>(&input.challenge_id)
        .bind::<Text, _>(&input.challenge)
        .bind::<Text, _>(&input.dpop_jkt)
        .bind::<Text, _>(input.audience.as_str())
        .bind::<Text, _>(&input.origin)
        .bind::<Text, _>(input.trust_domain.as_str())
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<Timestamptz, _>(input.expires_at)
        .execute(self.conn)
        .await?;
        let stored = self
            .did_binding_challenge_by_request(input.request_id.uuid())
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if stored.input.request_digest != input.request_digest
            || stored.input.issuing_handoff_grant_id != input.issuing_handoff_grant_id
        {
            return Ok(DidBindingChallengeIssue::DuplicateConflict);
        }
        Ok(DidBindingChallengeIssue::Issued(stored))
    }

    async fn consume_did_binding_challenge(
        &mut self,
        service_account_id: Ulid,
        account_subject: &arkret_identifiers::Hash,
        challenge_id: &str,
        request_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<DidBindingChallengeConsume, Self::Error> {
        let Some(record) = self.did_binding_challenge_by_id(challenge_id, true).await? else {
            return Ok(DidBindingChallengeConsume::Stale);
        };
        if record.consumed_at.is_some() || record.input.expires_at <= now {
            return Ok(DidBindingChallengeConsume::Stale);
        }
        if record.input.service_account_id != service_account_id
            || &record.input.account_subject != account_subject
            || &record.input.request_digest != request_digest
        {
            return Ok(DidBindingChallengeConsume::Mismatch);
        }
        let updated = diesel::sql_query(
            "UPDATE did_binding_challenges SET consumed_at = $2 \
             WHERE challenge_id = $1 AND consumed_at IS NULL AND expires_at > $2",
        )
        .bind::<Text, _>(challenge_id)
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        if updated != 1 {
            return Ok(DidBindingChallengeConsume::Stale);
        }
        Ok(DidBindingChallengeConsume::Consumed(Box::new(record)))
    }

    async fn published_did_registration_replay(
        &mut self,
        grant: &AccountHandoffGrant,
        challenge_id: &str,
        request_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<PublishedDidRegisterReplay, Self::Error> {
        let Some(record) = self.did_binding_challenge_by_id(challenge_id, true).await? else {
            return Ok(PublishedDidRegisterReplay::Stale);
        };
        let input = &record.input;
        if input.issuing_handoff_grant_id != grant.id
            || input.service_account_id != grant.service_account_id
            || input.dpop_jkt != grant.cnf_jkt
            || input.audience.as_str() != grant.audience
        {
            return Ok(PublishedDidRegisterReplay::Stale);
        }
        if let Some(stored_digest) = record.register_request_digest.as_ref() {
            if stored_digest != request_digest {
                return Ok(PublishedDidRegisterReplay::DuplicateConflict);
            }
            return record
                .register_outcome
                .map(PublishedDidRegisterReplay::Replay)
                .ok_or_else(DatabaseError::invalid_operation);
        }
        if record.consumed_at.is_some() || input.expires_at <= now {
            return Ok(PublishedDidRegisterReplay::Stale);
        }
        Ok(PublishedDidRegisterReplay::Pending(Box::new(record)))
    }

    async fn commit_published_did_registration(
        &mut self,
        grant: &AccountHandoffGrant,
        challenge_id: &str,
        request_digest: &arkret_identifiers::Hash,
        outcome: &arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
        now: DateTime<Utc>,
    ) -> Result<PublishedDidRegisterCommit, Self::Error> {
        match self
            .published_did_registration_replay(grant, challenge_id, request_digest, now)
            .await?
        {
            PublishedDidRegisterReplay::Replay(outcome) => {
                return Ok(PublishedDidRegisterCommit::Replay(outcome));
            }
            PublishedDidRegisterReplay::DuplicateConflict => {
                return Ok(PublishedDidRegisterCommit::DuplicateConflict);
            }
            PublishedDidRegisterReplay::Stale => return Ok(PublishedDidRegisterCommit::Stale),
            PublishedDidRegisterReplay::Pending(_) => {}
        }
        let affected = diesel::sql_query(
            "UPDATE did_binding_challenges SET consumed_at = $1, register_request_digest = $2, \
             register_outcome = $3 WHERE challenge_id = $4 AND issuing_handoff_grant_id = $5 \
             AND consumed_at IS NULL AND expires_at > $1",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(outcome).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(challenge_id)
        .bind::<SqlUuid, _>(Uuid::from(grant.id))
        .execute(self.conn)
        .await?;
        if affected == 1 {
            Ok(PublishedDidRegisterCommit::Committed)
        } else {
            Ok(PublishedDidRegisterCommit::Stale)
        }
    }

    async fn issue_identity_abandonment_challenge(
        &mut self,
        input: IdentityAbandonmentChallengeInput,
    ) -> Result<IdentityAbandonmentChallengeIssue, Self::Error> {
        let input = IdentityAbandonmentChallengeInput {
            issued_at: arkret_canonical::normalize_timestamp_canonical(input.issued_at),
            expires_at: arkret_canonical::normalize_timestamp_canonical(input.expires_at),
            ..input
        };
        if input.expires_at <= input.issued_at
            || input.expires_at - input.issued_at > Duration::minutes(5)
        {
            return Err(DatabaseError::invalid_operation());
        }
        if let Some(existing) = self
            .abandonment_challenge_by_request(input.request_id.uuid(), false)
            .await?
        {
            if existing.request_digest != input.request_digest
                || existing.issuing_handoff_grant_id != input.issuing_handoff_grant_id
                || existing.service_account_id != input.service_account_id
                || existing.audience.as_str() != input.audience.as_str()
                || existing.holder_jkt != input.holder_jkt
            {
                return Ok(IdentityAbandonmentChallengeIssue::DuplicateConflict);
            }
            return Ok(IdentityAbandonmentChallengeIssue::Replay(existing));
        }

        self.lock_lease_quota(&input.account_subject, input.audience.as_str())
            .await?;
        if let Some(existing) = self
            .abandonment_challenge_by_request(input.request_id.uuid(), false)
            .await?
        {
            if existing.request_digest != input.request_digest
                || existing.issuing_handoff_grant_id != input.issuing_handoff_grant_id
                || existing.service_account_id != input.service_account_id
                || existing.audience.as_str() != input.audience.as_str()
                || existing.holder_jkt != input.holder_jkt
            {
                return Ok(IdentityAbandonmentChallengeIssue::DuplicateConflict);
            }
            return Ok(IdentityAbandonmentChallengeIssue::Replay(existing));
        }

        let server_now = self.server_now().await?;
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(input.service_account_id),
                input.audience.as_str(),
                true,
            )
            .await?
        else {
            return Ok(IdentityAbandonmentChallengeIssue::LeaseFenced);
        };
        if lease.lease_id != input.lease_id
            || lease.fence != input.lease_fence
            || lease.holder_jkt != input.holder_jkt
            || lease.expires_at <= server_now
        {
            return Ok(IdentityAbandonmentChallengeIssue::LeaseFenced);
        }
        if matches!(
            lease.state,
            IdentityCreationLeaseState::PcrAccepted
                | IdentityCreationLeaseState::AccountBound
                | IdentityCreationLeaseState::Completed
        ) {
            return Ok(IdentityAbandonmentChallengeIssue::AlreadyAccepted);
        }
        if lease.state != IdentityCreationLeaseState::DidPublished {
            return Ok(IdentityAbandonmentChallengeIssue::CheckpointMismatch);
        }
        let Some(reserved) = lease.reserved_identity.as_ref() else {
            return Ok(IdentityAbandonmentChallengeIssue::CheckpointMismatch);
        };
        // The abandonment transcript pins the stable projected principal id,
        // not the method-specific DID.  For did:webvh those are distinct
        // strings, so comparing `did` here rejects every valid reserved
        // principal even though the lease carries the matching projection.
        if !reserved_identity_matches_abandonment_checkpoint(
            reserved,
            &input.principal_id,
            &input.did_version_id,
        ) {
            return Ok(IdentityAbandonmentChallengeIssue::CheckpointMismatch);
        }

        diesel::sql_query(
            "INSERT INTO identity_abandonment_challenges \
             (request_id, request_digest, issuing_handoff_grant_id, service_account_id, audience, \
              account_subject, holder_jkt, lease_id, lease_fence, principal_id, did_version_id, \
              challenge_id, challenge, origin, trust_domain, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.issuing_handoff_grant_id))
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(input.audience.as_str())
        .bind::<Text, _>(input.account_subject.as_str())
        .bind::<Text, _>(&input.holder_jkt)
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(input.lease_fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(&input.did_version_id)
        .bind::<Text, _>(&input.challenge_id)
        .bind::<Text, _>(&input.challenge)
        .bind::<Text, _>(&input.origin)
        .bind::<Text, _>(input.trust_domain.as_str())
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<Timestamptz, _>(input.expires_at)
        .execute(self.conn)
        .await?;
        let challenge = self
            .abandonment_challenge_by_request(input.request_id.uuid(), false)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if challenge.request_digest != input.request_digest
            || challenge.issuing_handoff_grant_id != input.issuing_handoff_grant_id
            || challenge.service_account_id != input.service_account_id
        {
            return Ok(IdentityAbandonmentChallengeIssue::DuplicateConflict);
        }
        Ok(IdentityAbandonmentChallengeIssue::Issued(challenge))
    }

    async fn active_identity_abandonment_challenge(
        &mut self,
        service_account_id: Ulid,
        audience: &arkret_identifiers::DidCoreId,
        lease_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<IdentityAbandonmentChallengeRecord>, Self::Error> {
        diesel::sql_query(
            "SELECT request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
             audience, account_subject, holder_jkt, lease_id, lease_fence, principal_id, \
             did_version_id, challenge_id, challenge, origin, trust_domain, issued_at, expires_at, \
             consumed_at, confirmation_request_id, confirmation_request_digest, outcome \
             FROM identity_abandonment_challenges \
             WHERE service_account_id = $1 AND audience = $2 AND lease_id = $3 \
             AND consumed_at IS NULL AND expires_at > $4 \
             ORDER BY issued_at DESC LIMIT 1",
        )
        .bind::<SqlUuid, _>(Uuid::from(service_account_id))
        .bind::<Text, _>(audience.as_str())
        .bind::<Text, _>(lease_id)
        .bind::<Timestamptz, _>(now)
        .get_result::<AbandonmentChallengeRow>(self.conn)
        .await
        .optional()?
        .map(abandonment_challenge_from_row)
        .transpose()
    }

    async fn abandon_identity_creation(
        &mut self,
        input: IdentityAbandonmentCommitInput,
    ) -> Result<IdentityAbandonmentCommit, Self::Error> {
        let now = arkret_canonical::normalize_timestamp_canonical(input.now);
        if let Some(existing) = self
            .abandonment_challenge_by_confirmation_request(input.request_id.uuid(), true)
            .await?
        {
            if existing.confirmation_request_digest.as_ref() == Some(&input.request_digest)
                && existing.service_account_id == input.service_account_id
                && existing.audience.as_str() == input.audience.as_str()
                && existing.holder_jkt == input.holder_jkt
            {
                return existing
                    .outcome
                    .map(IdentityAbandonmentCommit::Replay)
                    .ok_or_else(DatabaseError::invalid_operation);
            }
            return Ok(IdentityAbandonmentCommit::DuplicateConflict);
        }

        let Some(challenge) = self
            .abandonment_challenge_by_id(&input.challenge_id, true)
            .await?
        else {
            return Ok(IdentityAbandonmentCommit::UnknownChallenge);
        };
        // The initial confirmation-request lookup can race a transaction that
        // is currently consuming this same challenge. SELECT FOR UPDATE above
        // observes its committed ledger after waiting, so exact concurrent
        // replay must be recognized here as well.
        if let Some(confirmation_request_id) = challenge.confirmation_request_id.as_ref() {
            if confirmation_request_id == &input.request_id {
                if challenge.confirmation_request_digest.as_ref() == Some(&input.request_digest)
                    && challenge.service_account_id == input.service_account_id
                    && challenge.audience.as_str() == input.audience.as_str()
                    && challenge.holder_jkt == input.holder_jkt
                {
                    return challenge
                        .outcome
                        .map(IdentityAbandonmentCommit::Replay)
                        .ok_or_else(DatabaseError::invalid_operation);
                }
                return Ok(IdentityAbandonmentCommit::DuplicateConflict);
            }
            return Ok(IdentityAbandonmentCommit::ChallengeConsumed);
        }
        if challenge.issuing_handoff_grant_id == input.confirming_handoff_grant_id {
            return Ok(IdentityAbandonmentCommit::GrantReused);
        }
        if challenge.consumed_at.is_some() {
            return Ok(IdentityAbandonmentCommit::ChallengeConsumed);
        }
        if challenge.expires_at <= now {
            return Ok(IdentityAbandonmentCommit::ChallengeExpired);
        }
        if challenge.service_account_id != input.service_account_id
            || challenge.audience.as_str() != input.audience.as_str()
            || challenge.holder_jkt != input.holder_jkt
            || challenge.challenge != input.challenge
            || challenge.lease_id != input.lease_id
            || challenge.lease_fence != input.lease_fence
            || challenge.principal_id != input.principal_id
            || challenge.did_version_id != input.did_version_id
        {
            return Ok(IdentityAbandonmentCommit::ChallengeMismatch);
        }

        let Some(lease) = self
            .lease_for_account(
                Uuid::from(input.service_account_id),
                input.audience.as_str(),
                true,
            )
            .await?
        else {
            return Ok(IdentityAbandonmentCommit::LeaseFenced);
        };
        if lease.lease_id != input.lease_id
            || lease.fence != input.lease_fence
            || lease.holder_jkt != input.holder_jkt
            || lease.expires_at <= now
        {
            return Ok(IdentityAbandonmentCommit::LeaseFenced);
        }
        if matches!(
            lease.state,
            IdentityCreationLeaseState::PcrAccepted
                | IdentityCreationLeaseState::AccountBound
                | IdentityCreationLeaseState::Completed
        ) {
            return Ok(IdentityAbandonmentCommit::AlreadyAccepted);
        }
        if lease.state != IdentityCreationLeaseState::DidPublished {
            return Ok(IdentityAbandonmentCommit::ChallengeMismatch);
        }
        let Some(reserved) = lease.reserved_identity.as_ref() else {
            return Ok(IdentityAbandonmentCommit::ChallengeMismatch);
        };
        if !reserved_identity_matches_abandonment_checkpoint(
            reserved,
            &input.principal_id,
            &input.did_version_id,
        ) {
            return Ok(IdentityAbandonmentCommit::ChallengeMismatch);
        }

        let outcome = arkret_models_identity::IdentityAbandonmentOutcome {
            request_id: input.request_id.clone(),
            status: arkret_models_identity::IdentityAbandonmentStatus::Abandoned,
            account_subject: challenge.account_subject.clone(),
            principal_id: input.principal_id.clone(),
            did_version_id: input.did_version_id.clone(),
            abandoned_at: now,
        };
        let outcome_value =
            serde_json::to_value(&outcome).map_err(|_| DatabaseError::invalid_operation())?;
        let tombstones = diesel::sql_query(
            "INSERT INTO identity_orphan_anchor_tombstones \
             (principal_id, did_version_id, account_subject, abandonment_request_id, abandoned_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(&input.did_version_id)
        .bind::<Text, _>(challenge.account_subject.as_str())
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        if tombstones != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        let challenges = diesel::sql_query(
            "UPDATE identity_abandonment_challenges SET consumed_at = $1, \
             confirmation_request_id = $2, confirmation_request_digest = $3, outcome = $4 \
             WHERE challenge_id = $5 AND consumed_at IS NULL",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<Jsonb, _>(outcome_value)
        .bind::<Text, _>(&input.challenge_id)
        .execute(self.conn)
        .await?;
        if challenges != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        self.suppress_reserved_identity_checkpoints(input.service_account_id, &input.lease_id, now)
            .await?;
        let leases = diesel::sql_query(
            "DELETE FROM identity_creation_leases WHERE service_account_id = $1 AND audience = $2 \
             AND lease_id = $3 AND fence = $4 AND holder_jkt = $5 AND state = 'did_published'",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.service_account_id))
        .bind::<Text, _>(input.audience.as_str())
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(input.lease_fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .bind::<Text, _>(&input.holder_jkt)
        .execute(self.conn)
        .await?;
        if leases != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        Ok(IdentityAbandonmentCommit::Abandoned(outcome))
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
        if lease.state != IdentityCreationLeaseState::Completed {
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
        registry_receipt: &arkret_models_identity::DidOperationSubmitOutcome,
        head_event_digest: &arkret_identifiers::Hash,
        registration_did_evidence: &arkret_wire::RegistrationDidEvidence,
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
                IdentityCreationLeaseState::Reserved | IdentityCreationLeaseState::DidPublished
            )
            || (lease.state == IdentityCreationLeaseState::Reserved
                && lease.registration_did_evidence.is_some())
            || (lease.state == IdentityCreationLeaseState::DidPublished
                && lease.registration_did_evidence.as_ref() != Some(registration_did_evidence))
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
            (IdentityCreationLeaseState::Reserved, IdentityCreationLeaseState::Reserved) => {
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
            (
                IdentityCreationLeaseState::DidPublished,
                IdentityCreationLeaseState::DidPublished,
            ) => {
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
        let registry_receipt = serde_json::to_value(registry_receipt)
            .map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'did_published', registry_receipt = $1, \
             head_event_digest = $2, registration_did_evidence = $3, updated_at = $4 \
             WHERE service_account_id = $5 AND audience = $6 AND lease_id = $7 AND fence = $8 \
             AND holder_jkt = $9 AND reserved_operation_digest = $10 \
             AND state IN ('reserved', 'did_published')",
        )
        .bind::<Jsonb, _>(registry_receipt)
        .bind::<Text, _>(head_event_digest.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(registration_did_evidence)
                .map_err(|_| DatabaseError::invalid_operation())?,
        )
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
                IdentityCreationLeaseState::DidPublished | IdentityCreationLeaseState::PcrAccepted
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
        if lease.state == IdentityCreationLeaseState::PcrAccepted {
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
            || lease.state != IdentityCreationLeaseState::PcrAccepted
            || lease.pcr_genesis_receipt.is_none()
        {
            return Ok(false);
        }
        if binding_receipt.identity_creation_lease_id.as_deref() != Some(lease.lease_id.as_str())
            || binding_receipt.lease_fence != Some(lease.fence)
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
        if lease.state == IdentityCreationLeaseState::Completed {
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
        if lease.state != IdentityCreationLeaseState::AccountBound
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
    lease_state: IdentityCreationLeaseState,
    challenge_consumed: bool,
) -> bool {
    match lease_state {
        IdentityCreationLeaseState::Reserved => !challenge_consumed,
        // A reclaimed lease may issue a fresh holder-bound challenge after the
        // DID was published but before PCR genesis. `mark_did_published`
        // consumes that replacement challenge without republishing the DID.
        IdentityCreationLeaseState::DidPublished => true,
        IdentityCreationLeaseState::PcrAccepted | IdentityCreationLeaseState::AccountBound => {
            challenge_consumed
        }
        IdentityCreationLeaseState::Active | IdentityCreationLeaseState::Completed => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, TimeZone as _, Utc};
    use coauth_data::Ulid;

    use super::{
        ExistingDidBindingChallengeDisposition, classify_existing_did_binding_challenge,
        lease_quota_advisory_key, reserved_identity_matches_abandonment_checkpoint,
    };

    #[test]
    fn lease_quota_advisory_key_is_postgres_text_safe() {
        let account_subject = arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("valid account subject");
        let audience = "ak:did_core:webvh:QmExample";

        let key = lease_quota_advisory_key(&account_subject, audience);

        assert_eq!(key, format!("71:{}{audience}", account_subject.as_str(),));
        assert!(!key.contains('\0'));
    }

    #[test]
    fn abandonment_checkpoint_matches_projected_principal_not_did() {
        let did =
            arkret_identifiers::Did::new("did:webvh:zQ3shExampleScid:alice.example:webvh:user")
                .expect("valid DID");
        let principal_id =
            arkret_identifiers::project_did_to_core_id(&did).expect("projected principal id");
        assert_ne!(did.as_str(), principal_id.as_str());

        let mut operation = BTreeMap::new();
        operation.insert(
            "versionId".to_owned(),
            serde_json::Value::String("version-1".to_owned()),
        );
        let reserved = arkret_models_identity::ReservedIdentityCreation {
            principal_id: principal_id.clone(),
            did,
            operation_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .expect("digest"),
            did_operation: arkret_models_identity::DidOperationSubmitRequestBody {
                did: arkret_identifiers::Did::new(
                    "did:webvh:zQ3shExampleScid:alice.example:webvh:user",
                )
                .expect("operation did"),
                did_method: arkret_models_identity::DidMethodName::Webvh,
                seq: None,
                prev_event_digest: None,
                operation,
            },
        };

        assert!(reserved_identity_matches_abandonment_checkpoint(
            &reserved,
            &principal_id,
            "version-1",
        ));
        assert!(!reserved_identity_matches_abandonment_checkpoint(
            &reserved,
            &principal_id,
            "version-2",
        ));
    }

    #[test]
    fn did_binding_challenge_reissue_replays_only_the_exact_live_request() {
        let now = Utc.timestamp_opt(1_800_000_000, 0).single().expect("time");
        let digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "1".repeat(64))).expect("digest");
        let other_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "2".repeat(64))).expect("digest");
        let grant_id = Ulid::from(1_u128);

        assert_eq!(
            classify_existing_did_binding_challenge(
                &digest,
                grant_id,
                None,
                now + Duration::minutes(5),
                &digest,
                grant_id,
                now,
            ),
            ExistingDidBindingChallengeDisposition::Replay,
        );
        assert_eq!(
            classify_existing_did_binding_challenge(
                &digest,
                grant_id,
                None,
                now + Duration::minutes(5),
                &other_digest,
                grant_id,
                now,
            ),
            ExistingDidBindingChallengeDisposition::DuplicateConflict,
        );
        assert_eq!(
            classify_existing_did_binding_challenge(
                &digest,
                grant_id,
                Some(now),
                now + Duration::minutes(5),
                &digest,
                grant_id,
                now,
            ),
            ExistingDidBindingChallengeDisposition::StaleRequest,
        );
    }
}
