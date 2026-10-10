//! PostgreSQL account-handoff state machine.

use arkret_models_identity::IdentityCreationLeaseState;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::account_handoff::{
    AccountHandoffCreation, AccountHandoffCreationAttempt, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffCreationAttemptState, AccountHandoffGrant,
    AccountHandoffGrantInput, ControllerGateAttestationCommit, ControllerGateAttestationIssuance,
    ControllerGateAttestationReserve, DevicePairingAdmissionCommit, DevicePairingAdmissionRecord,
    DevicePairingAdmissionReserve, DevicePairingAdmissionState, DevicePairingFailureRecord,
    DevicePairingFinalizeCommit, DevicePairingPendingRecord, DevicePairingStageInsert,
    DidBindingChallengeConsume, DidBindingChallengeInput, DidBindingChallengeIssue,
    DidBindingChallengeRecord, IdentityAbandonmentCommit, IdentityAbandonmentCommitInput,
    IdentityBindingChallengeInput, IdentityBindingChallengeIssue, IdentityBindingChallengeRecord,
    IdentityCreationBindingCommit, IdentityCreationLeaseRecord, IdentityCreationLeaseRiskDecision,
    IdentityCreationRegisterLedger, IdentityCreationRegisterReplay,
    IdentityCreationRegisterReservation, IdentityCreationRegisterReserve,
    IdentityCreationRegistrationAdmission, IdentityCreationRegistrationContext,
    NewAccountHandoffCreationAttempt, NewControllerGateAttestationIssuance,
    NewDevicePairingAdmission, NewDevicePairingPendingRecord, PublishedDidRegisterCommit,
    PublishedDidRegisterReplay,
};
use coauth_data::{AccountHandoffRepository, Ulid};
use diesel::OptionalExtension as _;
use diesel::prelude::*;
use diesel::sql_types::{
    Array, BigInt, Bytea, Jsonb, Nullable, SmallInt, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::Digest as _;
use uuid::Uuid;

use crate::DatabaseError;

const ALLOWED_OPERATIONS: [&str; 7] = [
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_IDENTITY_BINDING_CHALLENGE_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_DID_BINDING_CHALLENGE_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ABANDON_IDENTITY_CREATION_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER_V1,
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_FINALIZE_DEVICE_PAIRING_V1,
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
        && arkret_identity::validate_principal_registration_anchor(
            &reserved.principal_registration_anchor,
        )
        .is_ok_and(|validated| validated.did_version_id == did_version_id)
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
            "SELECT id, request_id, request_digest, local_account_id, browser_session_id, \
             audience_id, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
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
        local_account_id: Uuid,
        audience_id: &str,
        for_update: bool,
    ) -> Result<Option<IdentityCreationLeaseRecord>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT local_account_id, audience_id, lease_id, holder_jkt, fence, expires_at, \
             reserved_principal_id, reserved_registration_anchor_digest, principal_registration_anchor, state, \
             registry_receipt, log_head_digest, registration_did_evidence, pcr_genesis_request_digest, \
             pcr_genesis_outcome, binding_receipt, register_handoff_grant_id, \
             register_challenge_id, register_request_digest, register_outcome, created_at, updated_at \
             FROM identity_creation_leases WHERE local_account_id = $1 AND audience_id = $2{suffix}"
        );
        let row = diesel::sql_query(query)
            .bind::<SqlUuid, _>(local_account_id)
            .bind::<Text, _>(audience_id)
            .get_result::<LeaseRow>(self.conn)
            .await
            .optional()?;
        row.map(lease_from_row).transpose()
    }

    async fn bound_principal(
        &mut self,
        local_account_id: Uuid,
        audience_id: &str,
    ) -> Result<Option<(arkret_identifiers::DidCoreId, arkret_identifiers::Did)>, DatabaseError>
    {
        let row = diesel::sql_query(
            "SELECT owners.principal_id, bindings.verified_did \
             FROM principal_did_bindings bindings \
             JOIN principal_did_owners owners ON owners.id = bindings.principal_did_owner_id \
             WHERE bindings.user_id = $1 AND bindings.audience_id = $2",
        )
        .bind::<SqlUuid, _>(local_account_id)
        .bind::<Text, _>(audience_id)
        .get_result::<PrincipalRow>(self.conn)
        .await
        .optional()?;
        row.map(principal_from_row).transpose()
    }

    async fn challenge_by_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<IdentityBindingChallengeRecord>, DatabaseError> {
        let row = diesel::sql_query(
            "SELECT request_id, request_digest, local_account_id, challenge_id, challenge, \
             purpose, account_subject, principal_id, did, registration_anchor_digest, did_version_id, method_history_head, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
             founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience_id, \
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
            "SELECT request_id, request_digest, local_account_id, challenge_id, challenge, \
             purpose, account_subject, principal_id, did, registration_anchor_digest, did_version_id, method_history_head, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
             founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience_id, \
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
            "SELECT request_id, request_digest, issuing_handoff_grant_id, local_account_id, \
             account_subject, principal_id, did, did_version_id, log_head_digest, \
             control_key_digest, witness_evidence, challenge_id, challenge, dpop_jkt, audience_id, \
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
            "SELECT request_id, request_digest, issuing_handoff_grant_id, local_account_id, \
             account_subject, principal_id, did, did_version_id, log_head_digest, \
             control_key_digest, witness_evidence, challenge_id, challenge, dpop_jkt, audience_id, \
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

    async fn suppress_reserved_identity_checkpoints(
        &mut self,
        local_account_id: Ulid,
        lease_id: &str,
        abandoned_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let rows = diesel::sql_query(
            "SELECT request_id, canonical_outcome FROM account_handoff_creation_attempts \
             WHERE state = 'committed' AND canonical_outcome IS NOT NULL \
             AND authorization_checkpoint ->> 'local_account_id' = $1 FOR UPDATE",
        )
        .bind::<Text, _>(local_account_id.to_string())
        .load::<CommittedHandoffOutcomeRow>(self.conn)
        .await?;
        for row in rows {
            let mut outcome: arkret_models_identity::AccountHandoffOutcome =
                serde_json::from_slice(&row.canonical_outcome)?;
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
            let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
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
        Ok(diesel::sql_query("SELECT clock_timestamp() AS now")
            .get_result::<ServerNowRow>(self.conn)
            .await?
            .now)
    }

    async fn account_risk_allows_identity_creation(
        &mut self,
        local_account_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        // Hold a share lock until the lease transaction commits. A concurrent
        // status transition therefore cannot race between this fail-closed
        // check and quota/lease consumption.
        Ok(
            diesel::sql_query("SELECT status FROM users WHERE id = $1 FOR SHARE")
                .bind::<SqlUuid, _>(local_account_id)
                .get_result::<AccountStatusRow>(self.conn)
                .await
                .optional()?
                .is_some_and(|row| row.status == "active"),
        )
    }

    async fn lock_lease_quota(
        &mut self,
        account_subject: &arkret_identifiers::Hash,
        audience_id: &str,
    ) -> Result<(), DatabaseError> {
        // Serialize the no-row acquisition case as well as renewal. PostgreSQL
        // `text` cannot contain NUL bytes, so use a length-prefixed transcript
        // rather than the protocol-style NUL separator used by some hashes.
        let key = lease_quota_advisory_key(account_subject, audience_id);
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

    async fn lock_device_pairing_account(
        &mut self,
        account_id: &arkret_wire::AccountId,
    ) -> Result<(), DatabaseError> {
        let key = String::from_utf8(arkret_canonical::canonical_json_bytes(account_id)?)
            .map_err(|_| DatabaseError::invalid_operation())?;
        let lock = diesel::sql_query(
            "SELECT TRUE AS locked \
             FROM pg_advisory_xact_lock(hashtextextended($1, 84))",
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
            "SELECT EXISTS(SELECT 1 FROM identity_creation_rate_limit_events \
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
        audience_id: &str,
        holder_jkt: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, DatabaseError> {
        if self.quota_event_exists(request_id, "acquisition").await? {
            return Ok(None);
        }
        let window = diesel::sql_query(
            "SELECT COUNT(*)::bigint AS count, MIN(occurred_at) AS oldest_at \
             FROM identity_creation_rate_limit_events \
             WHERE account_subject = $1 AND audience_id = $2 AND action = 'acquisition' \
             AND occurred_at > $3",
        )
        .bind::<Text, _>(account_subject.as_str())
        .bind::<Text, _>(audience_id)
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
            audience_id,
            holder_jkt,
            "acquisition",
            now,
        )
        .await?;
        Ok(None)
    }

    async fn consume_holder_quota(
        &mut self,
        request_id: Uuid,
        account_subject: &arkret_identifiers::Hash,
        audience_id: &str,
        holder_jkt: &str,
        action: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, DatabaseError> {
        if self.quota_event_exists(request_id, action).await? {
            return Ok(None);
        }
        let mut retry_at = None;
        for (duration, limit) in [(Duration::minutes(1), 1), (Duration::hours(1), 12)] {
            let window = diesel::sql_query(
                "SELECT COUNT(*)::bigint AS count, MIN(occurred_at) AS oldest_at \
                 FROM identity_creation_rate_limit_events \
                 WHERE account_subject = $1 AND audience_id = $2 AND holder_jkt = $3 \
                 AND action = $4 AND occurred_at > $5",
            )
            .bind::<Text, _>(account_subject.as_str())
            .bind::<Text, _>(audience_id)
            .bind::<Text, _>(holder_jkt)
            .bind::<Text, _>(action)
            .bind::<Timestamptz, _>(now - duration)
            .get_result::<RateWindowRow>(self.conn)
            .await?;
            if window.count >= limit {
                retry_at = retry_at.max(window.oldest_at.map(|oldest| oldest + duration));
            }
        }
        if let Some(retry_at) = retry_at {
            return Ok(Some(retry_after_ms(retry_at, now)));
        }
        self.insert_quota_event(
            request_id,
            account_subject,
            audience_id,
            holder_jkt,
            action,
            now,
        )
        .await?;
        Ok(None)
    }

    async fn insert_quota_event(
        &mut self,
        request_id: Uuid,
        account_subject: &arkret_identifiers::Hash,
        audience_id: &str,
        holder_jkt: &str,
        action: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        diesel::sql_query(
            "INSERT INTO identity_creation_rate_limit_events \
             (request_id, account_subject, audience_id, holder_jkt, action, occurred_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (request_id, action) DO NOTHING",
        )
        .bind::<SqlUuid, _>(request_id)
        .bind::<Text, _>(account_subject.as_str())
        .bind::<Text, _>(audience_id)
        .bind::<Text, _>(holder_jkt)
        .bind::<Text, _>(action)
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        Ok(())
    }
}

fn lease_quota_advisory_key(
    account_subject: &arkret_identifiers::Hash,
    audience_id: &str,
) -> String {
    let account_subject = account_subject.as_str();
    format!("{}:{account_subject}{audience_id}", account_subject.len())
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

fn principal_from_row(
    row: PrincipalRow,
) -> Result<(arkret_identifiers::DidCoreId, arkret_identifiers::Did), DatabaseError> {
    let did = arkret_identifiers::Did::new(row.verified_did)?;
    ensure_did_projects_to_principal(&did, &row.principal_id)?;
    Ok((row.principal_id, did))
}

fn ensure_did_projects_to_principal(
    did: &arkret_identifiers::Did,
    principal_id: &arkret_identifiers::DidCoreId,
) -> Result<(), DatabaseError> {
    if arkret_identifiers::project_did_to_core_id(did)
        .map_or(true, |projected| &projected != principal_id)
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
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
    local_account_id: Uuid,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    browser_session_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    audience_id: String,
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
struct DevicePairingPendingRow {
    #[diesel(sql_type = Text)]
    device_pairing_request_id: String,
    #[diesel(sql_type = Text)]
    pairing_code: String,
    #[diesel(sql_type = Jsonb)]
    new_device_pubkey: serde_json::Value,
    #[diesel(sql_type = Text)]
    client_nonce: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    device_metadata: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    gate_audience_uri: String,
    #[diesel(sql_type = Text)]
    server_nonce: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    account_id: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    target_proof: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    finalize_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Bytea>)]
    finalize_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    admission_state: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    admission_approving_account_id: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    admission_approving_device_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    admission_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Bytea>)]
    admission_request_bytes: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Bytea>)]
    admission_authorize_event_bytes: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    admission_authorize_event_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    admission_target_station_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    admission_target_authority_generation: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    admission_target_stream_head: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Bytea>)]
    admission_recorded_commit_bytes: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    admission_recorded_commit_digest: Option<String>,
    #[diesel(sql_type = Nullable<Bytea>)]
    admission_terminal_outcome_bytes: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    authorized_device_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    authorized_event_ref: Option<serde_json::Value>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct DevicePairingFailureCandidateRow {
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Text>)]
    admission_state: Option<String>,
}

#[derive(QueryableByName)]
struct DevicePairingStageReplayRow {
    #[diesel(sql_type = Text)]
    stage_request_digest: String,
    #[diesel(sql_type = Bytea)]
    stage_outcome: Vec<u8>,
}

fn classify_device_pairing_stage_replay(
    existing_digest: &str,
    existing_outcome: &[u8],
    requested_digest: &arkret_identifiers::Hash,
) -> DevicePairingStageInsert {
    if existing_digest == requested_digest.as_str() {
        DevicePairingStageInsert::Replay(existing_outcome.to_vec())
    } else {
        DevicePairingStageInsert::DuplicateConflict
    }
}

#[derive(QueryableByName)]
struct DevicePairingFailureCountRow {
    #[diesel(sql_type = SmallInt)]
    failure_count: i16,
}

#[derive(QueryableByName)]
struct DevicePairingRequestIdRow {
    #[diesel(sql_type = Text)]
    device_pairing_request_id: String,
}

fn device_pairing_pending_from_row(
    row: DevicePairingPendingRow,
) -> Result<DevicePairingPendingRecord, DatabaseError> {
    let state = match row.state.as_str() {
        "staged" => arkret_models_collaboration::device_pairing::DevicePairingState::Staged,
        "ready_for_claim" => {
            arkret_models_collaboration::device_pairing::DevicePairingState::ReadyForClaim
        }
        "authorized" => arkret_models_collaboration::device_pairing::DevicePairingState::Authorized,
        "expired" => arkret_models_collaboration::device_pairing::DevicePairingState::Expired,
        _ => return Err(DatabaseError::invalid_operation()),
    };
    let admission = match row.admission_state.as_deref() {
        None => None,
        Some(raw_state) => {
            let state = match raw_state {
                "submission_pending" => DevicePairingAdmissionState::SubmissionPending,
                "commit_recorded" => DevicePairingAdmissionState::CommitRecorded,
                "completed" => DevicePairingAdmissionState::Completed,
                _ => return Err(DatabaseError::invalid_operation()),
            };
            let generation = row
                .admission_target_authority_generation
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(DatabaseError::invalid_operation)?;
            Some(DevicePairingAdmissionRecord {
                state,
                approving_account_id: serde_json::from_value(
                    row.admission_approving_account_id
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )?,
                approving_device_id: arkret_identifiers::DeviceId::new(
                    row.admission_approving_device_id
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )?,
                canonical_request_digest: arkret_identifiers::Hash::new(
                    row.admission_request_digest
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )?,
                canonical_request_bytes: row
                    .admission_request_bytes
                    .ok_or_else(DatabaseError::invalid_operation)?,
                authorize_event_bytes: row
                    .admission_authorize_event_bytes
                    .ok_or_else(DatabaseError::invalid_operation)?,
                authorize_event_id: arkret_identifiers::EventId::new(
                    row.admission_authorize_event_id
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )?,
                target_station_id: arkret_identifiers::DidCoreId::new(
                    row.admission_target_station_id
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )?,
                target_authority_generation: generation,
                target_stream_head: serde_json::from_value(
                    row.admission_target_stream_head
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )?,
                recorded_commit_bytes: row.admission_recorded_commit_bytes,
                recorded_commit_digest: row
                    .admission_recorded_commit_digest
                    .map(arkret_identifiers::Hash::new)
                    .transpose()?,
                terminal_outcome_bytes: row.admission_terminal_outcome_bytes,
            })
        }
    };
    Ok(DevicePairingPendingRecord {
        device_pairing_request_id:
            arkret_models_collaboration::device_pairing::DevicePairingRequestId::new(
                row.device_pairing_request_id,
            )
            .map_err(|_| DatabaseError::invalid_operation())?,
        pairing_code: arkret_models_collaboration::device_pairing::DevicePairingCode::new(
            row.pairing_code,
        )
        .map_err(|_| DatabaseError::invalid_operation())?,
        new_device_pubkey: serde_json::from_value(row.new_device_pubkey)?,
        client_nonce: arkret_models_collaboration::device_pairing::DevicePairingNonce::new(
            row.client_nonce,
        )
        .map_err(|_| DatabaseError::invalid_operation())?,
        display_name: row
            .display_name
            .map(arkret_wire::NonEmptyString::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        device_metadata: row
            .device_metadata
            .map(serde_json::from_value)
            .transpose()?,
        gate_audience_uri: row.gate_audience_uri,
        server_nonce: arkret_models_collaboration::device_pairing::DevicePairingNonce::new(
            row.server_nonce,
        )
        .map_err(|_| DatabaseError::invalid_operation())?,
        state,
        account_id: row.account_id.map(serde_json::from_value).transpose()?,
        target_proof: row.target_proof.map(serde_json::from_value).transpose()?,
        finalize_request_digest: row
            .finalize_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()?,
        finalize_outcome: row.finalize_outcome,
        admission,
        authorized_device_id: row
            .authorized_device_id
            .map(arkret_identifiers::DeviceId::new)
            .transpose()?,
        authorized_event_ref: row
            .authorized_event_ref
            .map(serde_json::from_value)
            .transpose()?,
        expires_at: row.expires_at,
    })
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
        canonical_intent_digest: arkret_identifiers::Hash::new(row.canonical_intent_digest)?,
        principal_id: row.principal_id,
        agent_authority_id: row.agent_authority_id,
        canonical_outcome: row.canonical_outcome,
        outcome_digest: row
            .outcome_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()?,
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
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)?,
        canonical_intent_digest: arkret_identifiers::Hash::new(row.canonical_intent_digest)?,
        canonical_intent: row.canonical_intent,
        holder_jkt: row.holder_jkt,
        issuer: row.issuer,
        client_id: row.client_id,
        authorization_code_digest: arkret_identifiers::Hash::new(row.authorization_code_digest)?,
        dpop_jti_digest: arkret_identifiers::Hash::new(row.dpop_jti_digest)?,
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
            .transpose()?,
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
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)?,
        local_account_id: Ulid::from(row.local_account_id),
        browser_session_id: row.browser_session_id.map(Ulid::from),
        audience_id: row.audience_id,
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
    local_account_id: Uuid,
    #[diesel(sql_type = Text)]
    audience_id: String,
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
    reserved_registration_anchor_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    principal_registration_anchor: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    registry_receipt: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    log_head_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    registration_did_evidence: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    pcr_genesis_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pcr_genesis_outcome: Option<serde_json::Value>,
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
        row.reserved_registration_anchor_digest,
        row.principal_registration_anchor,
    ) {
        (None, None, None) => None,
        (Some(principal_id), Some(registration_anchor_digest), Some(anchor)) => {
            let anchor = serde_json::from_value(anchor)?;
            let reserved = arkret_models_identity::ReservedIdentityCreation::from_anchor(anchor)
                .map_err(|_| DatabaseError::invalid_operation())?;
            if reserved.principal_id != principal_id
                || reserved.registration_anchor_digest.as_str() != registration_anchor_digest
            {
                return Err(DatabaseError::invalid_operation());
            }
            Some(reserved)
        }
        _ => return Err(DatabaseError::invalid_operation()),
    };
    let (register_reservation, register_ledger) = match (
        row.register_handoff_grant_id,
        row.register_challenge_id,
        row.register_request_digest,
        row.register_outcome,
    ) {
        (None, None, None, None) => (None, None),
        (Some(handoff_grant_id), Some(challenge_id), Some(request_digest), None) => {
            let reservation = IdentityCreationRegisterReservation {
                handoff_grant_id: Ulid::from(handoff_grant_id),
                challenge_id,
                request_digest: arkret_identifiers::Hash::new(request_digest)?,
            };
            (Some(reservation), None)
        }
        (Some(handoff_grant_id), Some(challenge_id), Some(request_digest), Some(outcome)) => {
            let reservation = IdentityCreationRegisterReservation {
                handoff_grant_id: Ulid::from(handoff_grant_id),
                challenge_id: challenge_id.clone(),
                request_digest: arkret_identifiers::Hash::new(request_digest.clone())?,
            };
            (
                Some(reservation),
                Some(IdentityCreationRegisterLedger {
                    handoff_grant_id: Ulid::from(handoff_grant_id),
                    challenge_id,
                    request_digest: arkret_identifiers::Hash::new(request_digest)?,
                    outcome: serde_json::from_value(outcome)?,
                }),
            )
        }
        _ => return Err(DatabaseError::invalid_operation()),
    };
    Ok(IdentityCreationLeaseRecord {
        local_account_id: Ulid::from(row.local_account_id),
        audience_id: row.audience_id,
        lease_id: row.lease_id,
        holder_jkt: row.holder_jkt,
        fence: u64::try_from(row.fence)?,
        expires_at: row.expires_at,
        reserved_identity,
        state: IdentityCreationLeaseState::try_from(row.state.as_str())
            .map_err(|_| DatabaseError::invalid_operation())?,
        registry_receipt: row
            .registry_receipt
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        log_head_digest: row
            .log_head_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()?,
        registration_did_evidence: row
            .registration_did_evidence
            .map(serde_json::from_value)
            .transpose()?,
        pcr_genesis_request_digest: row
            .pcr_genesis_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()?,
        pcr_genesis_outcome: row
            .pcr_genesis_outcome
            .map(serde_json::from_value)
            .transpose()?,
        binding_receipt: row
            .binding_receipt
            .map(serde_json::from_value)
            .transpose()?,
        register_reservation,
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
    local_account_id: Uuid,
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
    registration_anchor_digest: String,
    #[diesel(sql_type = Text)]
    did_version_id: String,
    #[diesel(sql_type = Text)]
    method_history_head: String,
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
    audience_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    origin: arkret_identifiers::WebOrigin,
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
    local_account_id: Uuid,
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
    audience_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    origin: arkret_identifiers::WebOrigin,
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
    let did = arkret_identifiers::Did::new(row.did)?;
    ensure_did_projects_to_principal(&did, &row.principal_id)?;
    Ok(DidBindingChallengeRecord {
        input: DidBindingChallengeInput {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                row.request_id
            ))?,
            request_digest: arkret_identifiers::Hash::new(row.request_digest)?,
            issuing_handoff_grant_id: Ulid::from(row.issuing_handoff_grant_id),
            local_account_id: Ulid::from(row.local_account_id),
            account_subject: arkret_identifiers::Hash::new(row.account_subject)?,
            principal_id: row.principal_id,
            did,
            did_version_id: row.did_version_id,
            log_head_digest: arkret_identifiers::Hash::new(row.log_head_digest)?,
            control_key_digest: arkret_identifiers::Hash::new(row.control_key_digest)?,
            witness_evidence: row.witness_evidence,
            challenge_id: row.challenge_id,
            challenge: row.challenge,
            dpop_jkt: row.dpop_jkt,
            audience_id: row.audience_id,
            origin: row.origin,
            trust_domain: arkret_identifiers::TrustDomainId::new(row.trust_domain)?,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
        },
        consumed_at: row.consumed_at,
        register_request_digest: row
            .register_request_digest
            .map(arkret_identifiers::Hash::new)
            .transpose()?,
        register_outcome: row
            .register_outcome
            .map(serde_json::from_value)
            .transpose()?
            .map(Box::new),
    })
}

#[derive(QueryableByName)]
struct AbandonmentRow {
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = SqlUuid)]
    local_account_id: Uuid,
    #[diesel(sql_type = Text)]
    audience_id: String,
    #[diesel(sql_type = Text)]
    holder_jkt: String,
    #[diesel(sql_type = Jsonb)]
    outcome: serde_json::Value,
}

fn challenge_from_row(row: ChallengeRow) -> Result<IdentityBindingChallengeRecord, DatabaseError> {
    if row.purpose != "account_binding_and_pcr_genesis" {
        return Err(DatabaseError::invalid_operation());
    }
    let did = arkret_identifiers::Did::new(row.did)?;
    ensure_did_projects_to_principal(&did, &row.principal_id)?;
    Ok(IdentityBindingChallengeRecord {
        request_id: arkret_identifiers::RequestId::new(format!("ak:request:{}", row.request_id))?,
        request_digest: arkret_identifiers::Hash::new(row.request_digest)?,
        local_account_id: Ulid::from(row.local_account_id),
        challenge_id: row.challenge_id,
        challenge: row.challenge,
        purpose: arkret_models_identity::IdentityBindingPurpose::AccountBindingAndPcrGenesis,
        account_subject: arkret_identifiers::Hash::new(row.account_subject)?,
        principal_id: row.principal_id,
        did,
        registration_anchor_digest: arkret_identifiers::Hash::new(row.registration_anchor_digest)?,
        did_version_id: row.did_version_id,
        method_history_head: arkret_identifiers::Hash::new(row.method_history_head)?,
        control_key_digest: arkret_identifiers::Hash::new(row.control_key_digest)?,
        pcr_realm_id: arkret_identifiers::RealmId::new(row.pcr_realm_id)?,
        realm_create_payload_digest: arkret_identifiers::Hash::new(
            row.realm_create_payload_digest,
        )?,
        founding_authorize_payload_digest: arkret_identifiers::Hash::new(
            row.founding_authorize_payload_digest,
        )?,
        initial_session_request_digest: arkret_identifiers::Hash::new(
            row.initial_session_request_digest,
        )?,
        lease_id: row.lease_id,
        lease_fence: u64::try_from(row.lease_fence)?,
        dpop_jkt: row.dpop_jkt,
        audience_id: row.audience_id,
        origin: row.origin,
        trust_domain: arkret_identifiers::TrustDomainId::new(row.trust_domain)?,
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
        && challenge.local_account_id == context.grant.local_account_id
        && challenge.challenge_id == expected.challenge_id
        && challenge.challenge == expected.challenge
        && challenge.purpose == expected.purpose
        && challenge.account_subject == expected.account_subject
        && challenge.principal_id == expected.principal_id
        && challenge.did == expected.did
        && challenge.registration_anchor_digest == expected.registration_anchor_digest
        && challenge.did_version_id == expected.did_version_id
        && challenge.method_history_head == expected.method_history_head
        && challenge.control_key_digest == expected.control_key_digest
        && challenge.pcr_realm_id == expected.pcr_realm_id
        && challenge.realm_create_payload_digest == expected.realm_create_payload_digest
        && challenge.founding_authorize_payload_digest == expected.founding_authorize_payload_digest
        && challenge.initial_session_request_digest == expected.initial_session_request_digest
        && challenge.lease_id == context.lease.lease_id
        && challenge.lease_fence == context.lease.fence
        && challenge.dpop_jkt == context.grant.cnf_jkt
        && challenge.audience_id.as_str() == context.grant.audience_id
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
        .bind::<Jsonb, _>(serde_json::to_value(checkpoint)?)
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
            "SELECT id, request_id, request_digest, local_account_id, browser_session_id, \
             audience_id, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
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
            "SELECT id, request_id, request_digest, local_account_id, browser_session_id, \
             audience_id, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
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

    async fn insert_device_pairing_stage(
        &mut self,
        input: NewDevicePairingPendingRecord,
    ) -> Result<DevicePairingStageInsert, Self::Error> {
        if input.stage_idempotency_key.trim().is_empty()
            || input.stage_idempotency_key.len() > 128
            || !input
                .stage_idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~:-".contains(&byte))
            || !canonical_json_digest_matches(
                &input.stage_outcome,
                &arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                    &input.stage_outcome,
                ))
                .map_err(|_| DatabaseError::invalid_operation())?,
            )
        {
            return Err(DatabaseError::invalid_operation());
        }
        let existing = diesel::sql_query(
            "SELECT stage_request_digest, stage_outcome FROM device_pairing_pending \
             WHERE stage_idempotency_key = $1 FOR UPDATE",
        )
        .bind::<Text, _>(&input.stage_idempotency_key)
        .get_result::<DevicePairingStageReplayRow>(self.conn)
        .await
        .optional()?;
        if let Some(existing) = existing {
            return Ok(classify_device_pairing_stage_replay(
                &existing.stage_request_digest,
                &existing.stage_outcome,
                &input.stage_request_digest,
            ));
        }
        let inserted = diesel::sql_query(
            "INSERT INTO device_pairing_pending \
             (device_pairing_request_id, stage_idempotency_key, stage_request_digest, \
              stage_outcome, pairing_code, new_device_pubkey, client_nonce, \
              display_name, device_metadata, gate_audience_uri, server_nonce, state, \
              expires_at, retained_until, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'staged',$12,$13,$14) \
             ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(input.device_pairing_request_id.as_str())
        .bind::<Text, _>(&input.stage_idempotency_key)
        .bind::<Text, _>(input.stage_request_digest.as_str())
        .bind::<Bytea, _>(&input.stage_outcome)
        .bind::<Text, _>(input.pairing_code.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&input.new_device_pubkey)?)
        .bind::<Text, _>(input.client_nonce.as_str())
        .bind::<Nullable<Text>, _>(
            input
                .display_name
                .as_ref()
                .map(arkret_wire::NonEmptyString::as_str),
        )
        .bind::<Nullable<Jsonb>, _>(
            input
                .device_metadata
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        )
        .bind::<Text, _>(&input.gate_audience_uri)
        .bind::<Text, _>(input.server_nonce.as_str())
        .bind::<Timestamptz, _>(input.expires_at)
        .bind::<Timestamptz, _>(input.retained_until)
        .bind::<Timestamptz, _>(input.created_at)
        .execute(self.conn)
        .await?;
        if inserted == 1 {
            // Housekeeping follows the accepted stage write. A duplicate-key
            // conflict returns before this point, preserving its zero-write
            // contract even when unrelated tombstones are eligible to expire.
            diesel::sql_query(
                "DELETE FROM device_pairing_pending \
                 WHERE retained_until <= $1 AND admission_state IS NULL",
            )
            .bind::<Timestamptz, _>(input.created_at)
            .execute(self.conn)
            .await?;
            return Ok(DevicePairingStageInsert::Inserted);
        }
        // A concurrent transaction may have won on the idempotency key after
        // the preflight read. Distinguish that durable replay/conflict from a
        // random request-id or pairing-code collision.
        let existing = diesel::sql_query(
            "SELECT stage_request_digest, stage_outcome FROM device_pairing_pending \
             WHERE stage_idempotency_key = $1 FOR UPDATE",
        )
        .bind::<Text, _>(&input.stage_idempotency_key)
        .get_result::<DevicePairingStageReplayRow>(self.conn)
        .await
        .optional()?;
        Ok(match existing {
            Some(existing) => classify_device_pairing_stage_replay(
                &existing.stage_request_digest,
                &existing.stage_outcome,
                &input.stage_request_digest,
            ),
            None => DevicePairingStageInsert::IdentifierCollision,
        })
    }

    async fn get_device_pairing_stage(
        &mut self,
        request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
    ) -> Result<Option<DevicePairingPendingRecord>, Self::Error> {
        let row = diesel::sql_query(
            "SELECT device_pairing_request_id, pairing_code, new_device_pubkey, client_nonce, \
             display_name, device_metadata, gate_audience_uri, server_nonce, state, account_id, \
             target_proof, finalize_request_digest, finalize_outcome, admission_state, \
             admission_approving_account_id, admission_approving_device_id, admission_request_digest, \
             admission_request_bytes, admission_authorize_event_bytes, admission_authorize_event_id, \
             admission_target_station_id, admission_target_authority_generation, admission_target_stream_head, \
             admission_recorded_commit_bytes, admission_recorded_commit_digest, \
             admission_terminal_outcome_bytes, authorized_device_id, authorized_event_ref, expires_at \
             FROM device_pairing_pending WHERE device_pairing_request_id = $1",
        )
        .bind::<Text, _>(request_id.as_str())
        .get_result::<DevicePairingPendingRow>(self.conn)
        .await
        .optional()?;
        row.map(device_pairing_pending_from_row).transpose()
    }

    async fn get_device_pairing_by_code(
        &mut self,
        pairing_code: &arkret_models_collaboration::device_pairing::DevicePairingCode,
        now: DateTime<Utc>,
    ) -> Result<Option<DevicePairingPendingRecord>, Self::Error> {
        let row = diesel::sql_query(
            "SELECT device_pairing_request_id, pairing_code, new_device_pubkey, client_nonce, \
             display_name, device_metadata, gate_audience_uri, server_nonce, state, account_id, \
             target_proof, finalize_request_digest, finalize_outcome, admission_state, \
             admission_approving_account_id, admission_approving_device_id, admission_request_digest, \
             admission_request_bytes, admission_authorize_event_bytes, admission_authorize_event_id, \
             admission_target_station_id, admission_target_authority_generation, admission_target_stream_head, \
             admission_recorded_commit_bytes, admission_recorded_commit_digest, \
             admission_terminal_outcome_bytes, authorized_device_id, authorized_event_ref, expires_at \
             FROM device_pairing_pending WHERE pairing_code = $1 AND retained_until > $2 FOR UPDATE",
        )
        .bind::<Text, _>(pairing_code.as_str())
        .bind::<Timestamptz, _>(now)
        .get_result::<DevicePairingPendingRow>(self.conn)
        .await
        .optional()?;
        row.map(device_pairing_pending_from_row).transpose()
    }

    async fn record_device_pairing_failure(
        &mut self,
        request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
        now: DateTime<Utc>,
    ) -> Result<DevicePairingFailureRecord, Self::Error> {
        let candidate = diesel::sql_query(
            "SELECT state, admission_state FROM device_pairing_pending \
             WHERE device_pairing_request_id=$1 AND retained_until>$2 FOR UPDATE",
        )
        .bind::<Text, _>(request_id.as_str())
        .bind::<Timestamptz, _>(now)
        .get_result::<DevicePairingFailureCandidateRow>(self.conn)
        .await
        .optional()?;
        let Some(candidate) = candidate else {
            return Ok(DevicePairingFailureRecord::NotCounted);
        };
        if candidate.state == "authorized" || candidate.admission_state.is_some() {
            return Ok(DevicePairingFailureRecord::NotCounted);
        }

        let count = diesel::sql_query(
            "INSERT INTO device_pairing_abuse_ledger \
             (device_pairing_request_id, failure_count, updated_at) VALUES ($1,1,$2) \
             ON CONFLICT (device_pairing_request_id) DO UPDATE \
             SET failure_count=LEAST(device_pairing_abuse_ledger.failure_count + 1, 10), \
                 updated_at=EXCLUDED.updated_at \
             RETURNING failure_count",
        )
        .bind::<Text, _>(request_id.as_str())
        .bind::<Timestamptz, _>(now)
        .get_result::<DevicePairingFailureCountRow>(self.conn)
        .await?
        .failure_count;

        if count < 10 {
            return Ok(DevicePairingFailureRecord::Counted);
        }
        diesel::sql_query(
            "UPDATE device_pairing_pending \
             SET state='expired', code_consumed_at=COALESCE(code_consumed_at,$2), \
                 abuse_locked_at=COALESCE(abuse_locked_at,$2) \
             WHERE device_pairing_request_id=$1 AND state IN ('staged','ready_for_claim') \
             AND admission_state IS NULL",
        )
        .bind::<Text, _>(request_id.as_str())
        .bind::<Timestamptz, _>(now)
        .execute(self.conn)
        .await?;
        Ok(DevicePairingFailureRecord::Locked)
    }

    async fn record_device_pairing_code_failure(
        &mut self,
        pairing_code: &arkret_models_collaboration::device_pairing::DevicePairingCode,
        now: DateTime<Utc>,
    ) -> Result<DevicePairingFailureRecord, Self::Error> {
        let located = diesel::sql_query(
            "SELECT device_pairing_request_id FROM device_pairing_pending \
             WHERE pairing_code=$1 AND retained_until>$2",
        )
        .bind::<Text, _>(pairing_code.as_str())
        .bind::<Timestamptz, _>(now)
        .get_result::<DevicePairingRequestIdRow>(self.conn)
        .await
        .optional()?;
        let Some(located) = located else {
            return Ok(DevicePairingFailureRecord::NotCounted);
        };
        let request_id = arkret_models_collaboration::device_pairing::DevicePairingRequestId::new(
            located.device_pairing_request_id,
        )
        .map_err(|_| DatabaseError::invalid_operation())?;
        self.record_device_pairing_failure(&request_id, now).await
    }

    async fn finalize_device_pairing(
        &mut self,
        request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
        pairing_code: &arkret_models_collaboration::device_pairing::DevicePairingCode,
        account_id: &arkret_wire::AccountId,
        target_proof: &arkret_models_collaboration::device_pairing::DevicePairingTargetProof,
        request_digest: &arkret_identifiers::Hash,
        canonical_outcome: &[u8],
        now: DateTime<Utc>,
    ) -> Result<DevicePairingFinalizeCommit, Self::Error> {
        self.lock_device_pairing_account(account_id).await?;
        let row = diesel::sql_query(
            "SELECT device_pairing_request_id, pairing_code, new_device_pubkey, client_nonce, \
             display_name, device_metadata, gate_audience_uri, server_nonce, state, account_id, \
             target_proof, finalize_request_digest, finalize_outcome, admission_state, \
             admission_approving_account_id, admission_approving_device_id, admission_request_digest, \
             admission_request_bytes, admission_authorize_event_bytes, admission_authorize_event_id, \
             admission_target_station_id, admission_target_authority_generation, admission_target_stream_head, \
             admission_recorded_commit_bytes, admission_recorded_commit_digest, \
             admission_terminal_outcome_bytes, authorized_device_id, authorized_event_ref, expires_at \
             FROM device_pairing_pending WHERE device_pairing_request_id = $1 FOR UPDATE",
        )
        .bind::<Text, _>(request_id.as_str())
        .get_result::<DevicePairingPendingRow>(self.conn)
        .await
        .optional()?;
        let Some(record) = row.map(device_pairing_pending_from_row).transpose()? else {
            return Ok(DevicePairingFinalizeCommit::NotFound);
        };
        if record.finalize_request_digest.as_ref() == Some(request_digest)
            && record.account_id.as_ref() == Some(account_id)
        {
            return record
                .finalize_outcome
                .map(DevicePairingFinalizeCommit::Replay)
                .ok_or_else(DatabaseError::invalid_operation);
        }
        if record.state
            == arkret_models_collaboration::device_pairing::DevicePairingState::Authorized
            || record.admission.is_some()
        {
            return Ok(DevicePairingFinalizeCommit::NotFound);
        }
        if record.pairing_code != *pairing_code {
            self.record_device_pairing_failure(request_id, now).await?;
            return Ok(DevicePairingFinalizeCommit::NotFound);
        }
        if record.state != arkret_models_collaboration::device_pairing::DevicePairingState::Staged {
            self.record_device_pairing_failure(request_id, now).await?;
            return Ok(if record.finalize_request_digest.is_some() {
                DevicePairingFinalizeCommit::DuplicateConflict
            } else {
                DevicePairingFinalizeCommit::NotFound
            });
        }
        if record.expires_at <= now {
            self.record_device_pairing_failure(request_id, now).await?;
            return Ok(DevicePairingFinalizeCommit::NotFound);
        }
        if target_proof.account_id != *account_id {
            self.record_device_pairing_failure(request_id, now).await?;
            return Ok(DevicePairingFinalizeCommit::DuplicateConflict);
        }

        let account_id_json = serde_json::to_value(account_id)?;
        diesel::sql_query(
            "UPDATE device_pairing_pending SET state='expired', superseded_at=$1, \
             code_consumed_at=COALESCE(code_consumed_at,$1) \
             WHERE state='ready_for_claim' AND account_id=$2 AND admission_state IS NULL \
             AND device_pairing_request_id<>$3",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<Jsonb, _>(&account_id_json)
        .bind::<Text, _>(request_id.as_str())
        .execute(self.conn)
        .await?;

        let updated = diesel::sql_query(
            "UPDATE device_pairing_pending SET state='ready_for_claim', account_id=$1, \
             target_proof=$2, finalize_request_digest=$3, finalize_outcome=$4, finalized_at=$5 \
             WHERE device_pairing_request_id=$6 AND pairing_code=$7 AND state='staged' \
             AND expires_at>$5",
        )
        .bind::<Jsonb, _>(account_id_json)
        .bind::<Jsonb, _>(serde_json::to_value(target_proof)?)
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Bytea, _>(canonical_outcome)
        .bind::<Timestamptz, _>(now)
        .bind::<Text, _>(request_id.as_str())
        .bind::<Text, _>(pairing_code.as_str())
        .execute(self.conn)
        .await?;
        Ok(if updated == 1 {
            DevicePairingFinalizeCommit::Committed(canonical_outcome.to_vec())
        } else {
            DevicePairingFinalizeCommit::NotFound
        })
    }

    async fn reserve_device_pairing_admission(
        &mut self,
        input: NewDevicePairingAdmission,
        now: DateTime<Utc>,
    ) -> Result<DevicePairingAdmissionReserve, Self::Error> {
        if !canonical_json_digest_matches(
            &input.canonical_request_bytes,
            &input.canonical_request_digest,
        ) || input.authorize_event_bytes.is_empty()
        {
            return Err(DatabaseError::invalid_operation());
        }
        self.lock_device_pairing_account(&input.approving_account_id)
            .await?;
        let existing = self
            .get_device_pairing_stage(&input.device_pairing_request_id)
            .await?;
        let Some(existing) = existing else {
            return Ok(DevicePairingAdmissionReserve::NotFound);
        };
        if let Some(admission) = existing.admission {
            if admission.canonical_request_digest != input.canonical_request_digest
                || admission.approving_account_id != input.approving_account_id
                || admission.approving_device_id != input.approving_device_id
            {
                return Ok(DevicePairingAdmissionReserve::DuplicateConflict);
            }
            return Ok(match admission.state {
                DevicePairingAdmissionState::Completed => admission
                    .terminal_outcome_bytes
                    .map(DevicePairingAdmissionReserve::Replay)
                    .ok_or_else(DatabaseError::invalid_operation)?,
                DevicePairingAdmissionState::SubmissionPending
                | DevicePairingAdmissionState::CommitRecorded => {
                    DevicePairingAdmissionReserve::Resume(admission)
                }
            });
        }
        if existing.state
            != arkret_models_collaboration::device_pairing::DevicePairingState::ReadyForClaim
            || existing.expires_at <= now
            || existing.pairing_code != input.pairing_code
            || existing.account_id.as_ref() != Some(&input.approving_account_id)
        {
            self.record_device_pairing_failure(&input.device_pairing_request_id, now)
                .await?;
            return Ok(DevicePairingAdmissionReserve::NotFound);
        }

        let generation = i64::try_from(input.target_authority_generation)
            .map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE device_pairing_pending SET \
             admission_state='submission_pending', admission_approving_account_id=$1, \
             admission_approving_device_id=$2, admission_request_digest=$3, \
             admission_request_bytes=$4, admission_authorize_event_bytes=$5, \
             admission_authorize_event_id=$6, admission_target_station_id=$7, \
             admission_target_authority_generation=$8, admission_target_stream_head=$9, \
             admission_submission_started_at=$10 \
             WHERE device_pairing_request_id=$11 AND pairing_code=$12 \
             AND state='ready_for_claim' AND account_id=$1 AND expires_at>$10 \
             AND admission_state IS NULL",
        )
        .bind::<Jsonb, _>(serde_json::to_value(&input.approving_account_id)?)
        .bind::<Text, _>(input.approving_device_id.as_str())
        .bind::<Text, _>(input.canonical_request_digest.as_str())
        .bind::<Bytea, _>(&input.canonical_request_bytes)
        .bind::<Bytea, _>(&input.authorize_event_bytes)
        .bind::<Text, _>(input.authorize_event_id.as_str())
        .bind::<Text, _>(input.target_station_id.as_str())
        .bind::<BigInt, _>(generation)
        .bind::<Jsonb, _>(serde_json::to_value(&input.target_stream_head)?)
        .bind::<Timestamptz, _>(now)
        .bind::<Text, _>(input.device_pairing_request_id.as_str())
        .bind::<Text, _>(input.pairing_code.as_str())
        .execute(self.conn)
        .await?;
        if updated != 1 {
            let raced = self
                .get_device_pairing_stage(&input.device_pairing_request_id)
                .await?
                .and_then(|record| record.admission);
            return Ok(match raced {
                Some(admission)
                    if admission.canonical_request_digest == input.canonical_request_digest
                        && admission.approving_account_id == input.approving_account_id
                        && admission.approving_device_id == input.approving_device_id =>
                {
                    match admission.state {
                        DevicePairingAdmissionState::Completed => admission
                            .terminal_outcome_bytes
                            .map(DevicePairingAdmissionReserve::Replay)
                            .ok_or_else(DatabaseError::invalid_operation)?,
                        DevicePairingAdmissionState::SubmissionPending
                        | DevicePairingAdmissionState::CommitRecorded => {
                            DevicePairingAdmissionReserve::Resume(admission)
                        }
                    }
                }
                Some(_) => DevicePairingAdmissionReserve::DuplicateConflict,
                None => DevicePairingAdmissionReserve::NotFound,
            });
        }
        let record = self
            .get_device_pairing_stage(&input.device_pairing_request_id)
            .await?
            .and_then(|record| record.admission)
            .ok_or_else(DatabaseError::invalid_operation)?;
        Ok(DevicePairingAdmissionReserve::Started(record))
    }

    async fn record_device_pairing_commit(
        &mut self,
        request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
        request_digest: &arkret_identifiers::Hash,
        realm_commit_bytes: &[u8],
        realm_commit_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        if realm_commit_bytes.is_empty()
            || !canonical_json_digest_matches(realm_commit_bytes, realm_commit_digest)
        {
            return Err(DatabaseError::invalid_operation());
        }
        let updated = diesel::sql_query(
            "UPDATE device_pairing_pending SET admission_state='commit_recorded', \
             admission_recorded_commit_bytes=$1, admission_recorded_commit_digest=$2, \
             admission_commit_recorded_at=$3 \
             WHERE device_pairing_request_id=$4 AND admission_state='submission_pending' \
             AND admission_request_digest=$5",
        )
        .bind::<Bytea, _>(realm_commit_bytes)
        .bind::<Text, _>(realm_commit_digest.as_str())
        .bind::<Timestamptz, _>(now)
        .bind::<Text, _>(request_id.as_str())
        .bind::<Text, _>(request_digest.as_str())
        .execute(self.conn)
        .await?;
        if updated == 1 {
            return Ok(true);
        }
        let record = self.get_device_pairing_stage(request_id).await?;
        Ok(record.is_some_and(|record| {
            record.admission.is_some_and(|admission| {
                admission.canonical_request_digest == *request_digest
                    && matches!(
                        admission.state,
                        DevicePairingAdmissionState::CommitRecorded
                            | DevicePairingAdmissionState::Completed
                    )
                    && admission.recorded_commit_digest.as_ref() == Some(realm_commit_digest)
            })
        }))
    }

    async fn complete_device_pairing_admission(
        &mut self,
        request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
        request_digest: &arkret_identifiers::Hash,
        device_id: &arkret_identifiers::DeviceId,
        authorized_event_ref: &arkret_wire::CommittedEventRef,
        canonical_outcome: &[u8],
        now: DateTime<Utc>,
    ) -> Result<DevicePairingAdmissionCommit, Self::Error> {
        if !canonical_json_digest_matches(
            canonical_outcome,
            &arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(canonical_outcome))?,
        ) {
            return Err(DatabaseError::invalid_operation());
        }
        let existing = self
            .get_device_pairing_stage(request_id)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if let Some(admission) = &existing.admission
            && admission.state == DevicePairingAdmissionState::Completed
        {
            return Ok(if admission.canonical_request_digest == *request_digest {
                DevicePairingAdmissionCommit::Replay(
                    admission
                        .terminal_outcome_bytes
                        .clone()
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )
            } else {
                DevicePairingAdmissionCommit::DuplicateConflict
            });
        }
        let updated = diesel::sql_query(
            "UPDATE device_pairing_pending SET state='authorized', \
             code_consumed_at=COALESCE(code_consumed_at,$1), admission_state='completed', \
             admission_terminal_outcome_bytes=$2, admission_completed_at=$1, \
             authorized_device_id=$3, authorized_event_ref=$4 \
             WHERE device_pairing_request_id=$5 AND state='ready_for_claim' \
             AND admission_state='commit_recorded' AND admission_request_digest=$6",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<Bytea, _>(canonical_outcome)
        .bind::<Text, _>(device_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(authorized_event_ref)?)
        .bind::<Text, _>(request_id.as_str())
        .bind::<Text, _>(request_digest.as_str())
        .execute(self.conn)
        .await?;
        if updated == 1 {
            return Ok(DevicePairingAdmissionCommit::Completed(
                canonical_outcome.to_vec(),
            ));
        }
        let raced = self.get_device_pairing_stage(request_id).await?;
        Ok(match raced.and_then(|record| record.admission) {
            Some(admission)
                if admission.state == DevicePairingAdmissionState::Completed
                    && admission.canonical_request_digest == *request_digest =>
            {
                DevicePairingAdmissionCommit::Replay(
                    admission
                        .terminal_outcome_bytes
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )
            }
            Some(admission) if admission.state == DevicePairingAdmissionState::Completed => {
                DevicePairingAdmissionCommit::DuplicateConflict
            }
            _ => DevicePairingAdmissionCommit::NotReady,
        })
    }

    async fn abandon_pending_device_pairing_admission(
        &mut self,
        request_id: &arkret_models_collaboration::device_pairing::DevicePairingRequestId,
        request_digest: &arkret_identifiers::Hash,
    ) -> Result<bool, Self::Error> {
        let updated = diesel::sql_query(
            "UPDATE device_pairing_pending SET admission_state=NULL, \
             admission_approving_account_id=NULL, admission_approving_device_id=NULL, \
             admission_request_digest=NULL, admission_request_bytes=NULL, \
             admission_authorize_event_bytes=NULL, admission_authorize_event_id=NULL, \
             admission_target_station_id=NULL, admission_target_authority_generation=NULL, \
             admission_target_stream_head=NULL, admission_submission_started_at=NULL \
             WHERE device_pairing_request_id=$1 AND admission_state='submission_pending' \
             AND admission_request_digest=$2",
        )
        .bind::<Text, _>(request_id.as_str())
        .bind::<Text, _>(request_digest.as_str())
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }

    async fn create_with_lease(
        &mut self,
        input: AccountHandoffGrantInput,
    ) -> Result<AccountHandoffCreation, Self::Error> {
        diesel::sql_query(
            "INSERT INTO account_handoff_grants \
             (id, request_id, request_digest, local_account_id, browser_session_id, audience_id, \
              cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.id))
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
        .bind::<Nullable<SqlUuid>, _>(input.browser_session_id.map(Uuid::from))
        .bind::<Text, _>(&input.audience_id)
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
            || grant.local_account_id != input.local_account_id
            || grant.audience_id != input.audience_id
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
            .bound_principal(Uuid::from(input.local_account_id), &input.audience_id)
            .await?
        {
            let incomplete_lease = self
                .lease_for_account(
                    Uuid::from(input.local_account_id),
                    input.audience_id.as_str(),
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
                .account_risk_allows_identity_creation(Uuid::from(input.local_account_id))
                .await?
        {
            return Ok(AccountHandoffCreation::RiskRejected { grant });
        }

        self.lock_lease_quota(&input.account_subject, input.audience_id.as_str())
            .await?;
        let server_now = self.server_now().await?;
        let existing_lease = self
            .lease_for_account(
                Uuid::from(input.local_account_id),
                input.audience_id.as_str(),
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
                input.audience_id.as_str(),
                &input.cnf_jkt,
                server_now,
            )
            .await?
        } else {
            self.consume_holder_quota(
                input.request_id.uuid(),
                &input.account_subject,
                &input.audience_id,
                &input.cnf_jkt,
                "renewal",
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
                 (local_account_id, audience_id, lease_id, holder_jkt, fence, expires_at, state, \
                  created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, 1, $5, 'active', $6, $6)",
            )
            .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
            .bind::<Text, _>(&input.audience_id)
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
                 WHERE local_account_id = $1 AND audience_id = $2",
            )
            .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
            .bind::<Text, _>(&input.audience_id)
            .bind::<Text, _>(&input.lease_id)
            .bind::<Text, _>(&input.cnf_jkt)
            .bind::<Timestamptz, _>(input.lease_expires_at)
            .bind::<Timestamptz, _>(input.issued_at)
            .execute(self.conn)
            .await?;
        } else {
            diesel::sql_query(
                "UPDATE identity_creation_leases SET expires_at = GREATEST(expires_at, $3), \
                 updated_at = $4 WHERE local_account_id = $1 AND audience_id = $2 \
                 AND holder_jkt = $5",
            )
            .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
            .bind::<Text, _>(&input.audience_id)
            .bind::<Timestamptz, _>(input.lease_expires_at)
            .bind::<Timestamptz, _>(input.issued_at)
            .bind::<Text, _>(&input.cnf_jkt)
            .execute(self.conn)
            .await?;
        }
        let lease = self
            .lease_for_account(
                Uuid::from(input.local_account_id),
                &input.audience_id,
                false,
            )
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
            .lease_for_account(
                Uuid::from(grant.local_account_id),
                &grant.audience_id,
                false,
            )
            .await?;
        let Some(lease) = lease else {
            return if let Some((principal_id, did)) = self
                .bound_principal(Uuid::from(grant.local_account_id), &grant.audience_id)
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
        ensure_did_projects_to_principal(&input.did, &input.principal_id)?;
        if input.challenge_ttl <= Duration::zero() || input.challenge_ttl > Duration::seconds(300) {
            return Err(DatabaseError::invalid_operation());
        }
        self.lock_lease_quota(&input.account_subject, input.audience_id.as_str())
            .await?;
        if !self
            .account_risk_allows_identity_creation(Uuid::from(input.local_account_id))
            .await?
        {
            return Ok(IdentityBindingChallengeIssue::RiskRejected);
        }
        let grant = diesel::sql_query(
            "SELECT id, request_id, request_digest, local_account_id, browser_session_id, \
             audience_id, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
             revoked_at, consumed_at FROM account_handoff_grants WHERE id = $1 FOR SHARE",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.handoff_grant_id))
        .get_result::<HandoffRow>(self.conn).await.optional()?;
        let Some(grant) = grant.map(handoff_from_row).transpose()? else {
            return Ok(IdentityBindingChallengeIssue::LeaseMismatch);
        };
        let lease = self
            .lease_for_account(
                Uuid::from(input.local_account_id),
                input.audience_id.as_str(),
                true,
            )
            .await?;
        let Some(lease) = lease else {
            return Ok(IdentityBindingChallengeIssue::LeaseMismatch);
        };
        let server_now = self.server_now().await?;
        let issued_at = arkret_canonical::normalize_timestamp_canonical(server_now);
        let expires_at =
            arkret_canonical::normalize_timestamp_canonical(issued_at + input.challenge_ttl);
        if expires_at <= issued_at {
            return Err(DatabaseError::invalid_operation());
        }
        if grant.local_account_id != input.local_account_id
            || grant.audience_id != input.audience_id.as_str()
            || grant.cnf_jkt != input.holder_jkt
            || grant.expires_at <= server_now
            || grant.revoked_at.is_some()
            || grant.consumed_at.is_some()
        {
            return Ok(IdentityBindingChallengeIssue::LeaseMismatch);
        }
        if lease.lease_id != input.lease_id
            || lease.fence != input.lease_fence
            || lease.holder_jkt != input.holder_jkt
            || lease.expires_at <= server_now
            || matches!(
                lease.state,
                IdentityCreationLeaseState::AccountBound | IdentityCreationLeaseState::Completed
            )
        {
            return Ok(IdentityBindingChallengeIssue::LeaseMismatch);
        }

        if let Some(existing) = self.challenge_by_request(input.request_id.uuid()).await? {
            if existing.request_digest != input.request_digest
                || existing.local_account_id != input.local_account_id
                || existing.account_subject != input.account_subject
                || existing.audience_id != input.audience_id
                || existing.dpop_jkt != input.holder_jkt
                || existing.lease_id != input.lease_id
                || existing.lease_fence != input.lease_fence
            {
                return Ok(IdentityBindingChallengeIssue::DuplicateConflict);
            }
            if existing.consumed_at.is_some() {
                return Ok(IdentityBindingChallengeIssue::Consumed);
            }
            if existing.expires_at <= server_now {
                return Ok(IdentityBindingChallengeIssue::Expired);
            }
            if existing.replaced_at.is_some() {
                return Ok(IdentityBindingChallengeIssue::StaleRequest);
            }
            return Ok(IdentityBindingChallengeIssue::Replay(existing));
        }

        let reserved = arkret_models_identity::ReservedIdentityCreation::from_anchor(
            input.principal_registration_anchor.clone(),
        )
        .map_err(|_| DatabaseError::invalid_operation())?;
        if reserved.registration_anchor_digest != input.registration_anchor_digest
            || reserved.principal_id != input.principal_id
        {
            return Ok(IdentityBindingChallengeIssue::ReservationConflict);
        }
        // Compare the reservation by its canonical identity, as every other
        // lease fence here does. Structural equality is not stable across the
        // JSONB round trip: the typed anchor keeps the received DID Document
        // form in `raw_properties`, which the stored normalized projection
        // re-reads differently while its canonical digest is unchanged.
        if let Some(existing) = lease.reserved_identity.as_ref()
            && (existing.principal_id != reserved.principal_id
                || existing.registration_anchor_digest != reserved.registration_anchor_digest)
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
            .consume_holder_quota(
                input.request_id.uuid(),
                &input.account_subject,
                input.audience_id.as_str(),
                &input.holder_jkt,
                "challenge_issuance",
                server_now,
            )
            .await?
        {
            return Ok(IdentityBindingChallengeIssue::RateLimited { retry_after_ms });
        }

        diesel::sql_query(
            "UPDATE identity_creation_leases SET reserved_principal_id = $3, \
             reserved_registration_anchor_digest = $4, principal_registration_anchor = $5, \
             state = CASE WHEN state <> 'active' THEN state ELSE 'reserved' END, \
             updated_at = $6 \
             WHERE local_account_id = $1 AND audience_id = $2 AND lease_id = $7 \
             AND fence = $8 AND holder_jkt = $9 \
             AND state IN ('active', 'reserved', 'did_published', 'pcr_accepted', 'account_bound')",
        )
        .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
        .bind::<Text, _>(input.audience_id.as_str())
        .bind::<Text, _>(reserved.principal_id.as_str())
        .bind::<Text, _>(reserved.registration_anchor_digest.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(
            &reserved.principal_registration_anchor,
        )?)
        .bind::<Timestamptz, _>(issued_at)
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(i64::try_from(input.lease_fence)?)
        .bind::<Text, _>(&input.holder_jkt)
        .execute(self.conn)
        .await?;

        diesel::sql_query(
            "UPDATE identity_binding_challenges SET replaced_at = $1 \
             WHERE local_account_id = $2 AND audience_id = $3 AND lease_id = $4 \
             AND lease_fence = $5 AND registration_anchor_digest = $6 \
             AND consumed_at IS NULL AND replaced_at IS NULL AND expires_at > $1",
        )
        .bind::<Timestamptz, _>(issued_at)
        .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
        .bind::<Text, _>(input.audience_id.as_str())
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(i64::try_from(input.lease_fence)?)
        .bind::<Text, _>(input.registration_anchor_digest.as_str())
        .execute(self.conn)
        .await?;

        diesel::sql_query(
            "INSERT INTO identity_binding_challenges \
             (request_id, request_digest, local_account_id, challenge_id, challenge, purpose, \
              account_subject, principal_id, did, registration_anchor_digest, did_version_id, method_history_head, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
              founding_authorize_payload_digest, initial_session_request_digest, lease_id, lease_fence, dpop_jkt, audience_id, origin, \
              trust_domain, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'account_binding_and_pcr_genesis', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
        .bind::<Text, _>(&input.challenge_id)
        .bind::<Text, _>(&input.challenge)
        .bind::<Text, _>(input.account_subject.as_str())
        .bind::<Text, _>(reserved.principal_id.as_str())
        .bind::<Text, _>(input.did.as_str())
        .bind::<Text, _>(input.registration_anchor_digest.as_str())
        .bind::<Text, _>(&input.did_version_id)
        .bind::<Text, _>(input.method_history_head.as_str())
        .bind::<Text, _>(input.control_key_digest.as_str())
        .bind::<Text, _>(input.pcr_realm_id.as_str())
        .bind::<Text, _>(input.realm_create_payload_digest.as_str())
        .bind::<Text, _>(input.founding_authorize_payload_digest.as_str())
        .bind::<Text, _>(input.initial_session_request_digest.as_str())
        .bind::<Text, _>(&input.lease_id)
        .bind::<BigInt, _>(i64::try_from(input.lease_fence)?)
        .bind::<Text, _>(&input.holder_jkt)
        .bind::<Text, _>(input.audience_id.as_str())
        .bind::<Text, _>(&input.origin)
        .bind::<Text, _>(input.trust_domain.as_str())
        .bind::<Timestamptz, _>(issued_at)
        .bind::<Timestamptz, _>(expires_at)
        .execute(self.conn)
        .await?;
        let challenge = self
            .challenge_by_request(input.request_id.uuid())
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if challenge.request_digest != input.request_digest
            || challenge.local_account_id != input.local_account_id
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
        ensure_did_projects_to_principal(&input.did, &input.principal_id)?;
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
             (request_id, request_digest, issuing_handoff_grant_id, local_account_id, \
              account_subject, principal_id, did, did_version_id, log_head_digest, \
              control_key_digest, witness_evidence, challenge_id, challenge, dpop_jkt, audience_id, \
              origin, trust_domain, issued_at, expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(input.issuing_handoff_grant_id))
        .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
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
        .bind::<Text, _>(input.audience_id.as_str())
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
        local_account_id: Ulid,
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
        if record.input.local_account_id != local_account_id
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
            || input.local_account_id != grant.local_account_id
            || input.dpop_jkt != grant.cnf_jkt
            || input.audience_id.as_str() != grant.audience_id
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
        outcome: &arkret_models_collaboration::account_operations::AccountRegisterOutcome,
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
        .bind::<Jsonb, _>(serde_json::to_value(outcome)?)
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

    async fn abandon_identity_creation(
        &mut self,
        input: IdentityAbandonmentCommitInput,
    ) -> Result<IdentityAbandonmentCommit, Self::Error> {
        // Share the account/authority lock with reservation and renewal. The
        // terminal ledger is read after serialization, including exact retries.
        self.lock_lease_quota(&input.account_subject, input.audience_id.as_str())
            .await?;
        if !self
            .account_risk_allows_identity_creation(Uuid::from(input.local_account_id))
            .await?
        {
            return Ok(IdentityAbandonmentCommit::AuthenticationRequired);
        }
        let current = diesel::sql_query(
            "SELECT id, request_id, request_digest, local_account_id, browser_session_id, \
             audience_id, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
             revoked_at, consumed_at FROM account_handoff_grants WHERE id = $1 FOR SHARE",
        ).bind::<SqlUuid, _>(Uuid::from(input.confirming_handoff_grant_id))
            .get_result::<HandoffRow>(self.conn).await.optional()?;
        let Some(grant) = current.map(handoff_from_row).transpose()? else {
            return Ok(IdentityAbandonmentCommit::AuthenticationRequired);
        };
        let now = self.server_now().await?;
        if grant.local_account_id != input.local_account_id
            || grant.audience_id != input.audience_id.as_str()
            || grant.cnf_jkt != input.holder_jkt
            || grant.expires_at <= now
            || grant.revoked_at.is_some()
            || grant.consumed_at.is_some()
        {
            return Ok(IdentityAbandonmentCommit::AuthenticationRequired);
        }
        if let Some(existing) = diesel::sql_query(
            "SELECT request_digest, local_account_id, audience_id, holder_jkt, outcome \
             FROM identity_abandonments WHERE request_id = $1",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .get_result::<AbandonmentRow>(self.conn)
        .await
        .optional()?
        {
            if existing.request_digest == input.request_digest.as_str()
                && existing.local_account_id == Uuid::from(input.local_account_id)
                && existing.audience_id == input.audience_id.as_str()
                && existing.holder_jkt == input.holder_jkt
            {
                return Ok(IdentityAbandonmentCommit::Replay(serde_json::from_value(
                    existing.outcome,
                )?));
            }
            return Ok(IdentityAbandonmentCommit::DuplicateConflict);
        }
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(input.local_account_id),
                input.audience_id.as_str(),
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
        if !matches!(
            lease.state,
            IdentityCreationLeaseState::Reserved | IdentityCreationLeaseState::DidPublished
        ) {
            return Ok(IdentityAbandonmentCommit::CheckpointMismatch);
        }
        let Some(reserved) = lease.reserved_identity.as_ref() else {
            return Ok(IdentityAbandonmentCommit::CheckpointMismatch);
        };
        if !reserved_identity_matches_abandonment_checkpoint(
            reserved,
            &input.principal_id,
            &input.did_version_id,
        ) {
            return Ok(IdentityAbandonmentCommit::CheckpointMismatch);
        }
        let dispatch_attempted = diesel::sql_query(
            "SELECT (pcr_dispatch_request_digest IS NOT NULL) AS present FROM identity_creation_leases WHERE lease_id = $1",
        ).bind::<Text, _>(&input.lease_id).get_result::<ExistsRow>(self.conn).await?.present;
        if dispatch_attempted {
            return Ok(IdentityAbandonmentCommit::DispatchUncertain);
        }
        let Some(session_id) = grant.browser_session_id else {
            return Ok(IdentityAbandonmentCommit::AuthenticationRequired);
        };
        let active_session = diesel::sql_query(
            "SELECT true AS present FROM user_sessions WHERE id = $1 AND user_id = $2 AND finished_at IS NULL FOR SHARE",
        ).bind::<SqlUuid, _>(Uuid::from(session_id)).bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
            .get_result::<ExistsRow>(self.conn).await.optional()?.is_some();
        // The first immutable binding challenge was inserted in the same
        // transaction that froze this exact operation. Renewal does not move
        // this boundary. Token issuance/code exchange is not authentication.
        let fresh_auth = diesel::sql_query(
            "SELECT EXISTS (SELECT 1 FROM user_session_authentications a \
             WHERE a.user_session_id = $1 AND a.created_at <= $2 \
             AND a.created_at > (SELECT min(issued_at) FROM identity_binding_challenges \
             WHERE local_account_id = $3 AND lease_id = $4 AND registration_anchor_digest = $5)) AS present",
        )
        .bind::<SqlUuid, _>(Uuid::from(session_id))
        .bind::<Timestamptz, _>(grant.issued_at)
        .bind::<SqlUuid, _>(Uuid::from(input.local_account_id))
        .bind::<Text, _>(&input.lease_id)
        .bind::<Text, _>(reserved.registration_anchor_digest.as_str())
        .get_result::<ExistsRow>(self.conn)
        .await?
        .present;
        if !active_session || !fresh_auth {
            return Ok(IdentityAbandonmentCommit::AuthenticationRequired);
        }
        // The outcome is persisted as canonical (millisecond) JSON and replayed
        // from it, so the first response must carry the same canonical instant.
        let abandoned_at = arkret_canonical::normalize_timestamp_canonical(now);
        let outcome = arkret_models_identity::IdentityAbandonmentOutcome {
            request_id: input.request_id.clone(),
            account_subject: input.account_subject.clone(),
            principal_id: input.principal_id.clone(),
            did_version_id: input.did_version_id.clone(),
            abandoned_at,
        };
        let inserted = diesel::sql_query(
            "INSERT INTO identity_orphan_anchor_tombstones \
             (principal_id, did_version_id, account_subject, abandonment_request_id, abandoned_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(&input.did_version_id)
        .bind::<Text, _>(input.account_subject.as_str())
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Timestamptz, _>(abandoned_at)
        .execute(self.conn)
        .await?;
        if inserted != 1 {
            return Err(DatabaseError::invalid_operation());
        }
        diesel::sql_query(
            "INSERT INTO identity_abandonments (request_id, request_digest, local_account_id, audience_id, holder_jkt, outcome) VALUES ($1,$2,$3,$4,$5,$6)",
        ).bind::<SqlUuid, _>(input.request_id.uuid()).bind::<Text, _>(input.request_digest.as_str())
            .bind::<SqlUuid, _>(Uuid::from(input.local_account_id)).bind::<Text, _>(input.audience_id.as_str())
            .bind::<Text, _>(&input.holder_jkt).bind::<Jsonb, _>(serde_json::to_value(&outcome)?)
            .execute(self.conn).await?;
        self.suppress_reserved_identity_checkpoints(
            input.local_account_id,
            &input.lease_id,
            abandoned_at,
        )
        .await?;
        let deleted = diesel::sql_query(
            "DELETE FROM identity_creation_leases WHERE local_account_id = $1 AND audience_id = $2 \
             AND lease_id = $3 AND fence = $4 AND holder_jkt = $5 AND state IN ('reserved','did_published')",
        ).bind::<SqlUuid, _>(Uuid::from(input.local_account_id)).bind::<Text, _>(input.audience_id.as_str())
            .bind::<Text, _>(&input.lease_id).bind::<BigInt, _>(i64::try_from(input.lease_fence)?)
            .bind::<Text, _>(&input.holder_jkt).execute(self.conn).await?;
        if deleted != 1 {
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
    ) -> Result<IdentityCreationRegistrationAdmission, Self::Error> {
        if !self
            .account_risk_allows_identity_creation(Uuid::from(grant.local_account_id))
            .await?
        {
            return Ok(IdentityCreationRegistrationAdmission::AccountInactive);
        }
        let current_grant = diesel::sql_query(
            "SELECT id, request_id, request_digest, local_account_id, browser_session_id, \
             audience_id, cnf_jkt, allowed_operations, account_handoff_grant, issued_at, expires_at, \
             revoked_at, consumed_at FROM account_handoff_grants WHERE id = $1 FOR SHARE",
        ).bind::<SqlUuid, _>(Uuid::from(grant.id))
        .get_result::<HandoffRow>(self.conn).await.optional()?;
        let Some(current_grant) = current_grant.map(handoff_from_row).transpose()? else {
            return Ok(IdentityCreationRegistrationAdmission::ExecutionAuthorityInvalid);
        };
        let Some(lease) = self
            .lease_for_account(Uuid::from(grant.local_account_id), &grant.audience_id, true)
            .await?
        else {
            return Ok(IdentityCreationRegistrationAdmission::ExecutionAuthorityInvalid);
        };
        let now = self.server_now().await?;
        if current_grant.local_account_id != grant.local_account_id
            || current_grant.audience_id != grant.audience_id
            || current_grant.cnf_jkt != grant.cnf_jkt
            || current_grant.expires_at <= now
            || current_grant.revoked_at.is_some()
            || current_grant.consumed_at.is_some()
        {
            return Ok(IdentityCreationRegistrationAdmission::ExecutionAuthorityInvalid);
        }
        if lease.lease_id != lease_id
            || lease.fence != lease_fence
            || lease.holder_jkt != grant.cnf_jkt
            || lease.expires_at <= now
        {
            return Ok(IdentityCreationRegistrationAdmission::ExecutionAuthorityInvalid);
        }
        let Some(challenge) = self.challenge_by_id(challenge_id, false).await? else {
            return Ok(IdentityCreationRegistrationAdmission::ChallengeMismatch);
        };
        if challenge.local_account_id != grant.local_account_id
            || challenge.audience_id.as_str() != grant.audience_id
            || challenge.lease_id != lease_id
            || challenge.lease_fence != lease_fence
            || challenge.dpop_jkt != grant.cnf_jkt
        {
            return Ok(IdentityCreationRegistrationAdmission::ChallengeMismatch);
        }
        if challenge.replaced_at.is_some() {
            return Ok(IdentityCreationRegistrationAdmission::ChallengeReplaced);
        }
        if !registration_challenge_state_is_usable(lease.state, challenge.consumed_at.is_some()) {
            return Ok(if challenge.consumed_at.is_some() {
                IdentityCreationRegistrationAdmission::ChallengeConsumed
            } else {
                IdentityCreationRegistrationAdmission::ChallengeMismatch
            });
        }
        let dispatch_is_frozen = lease
            .register_reservation
            .as_ref()
            .is_some_and(|reservation| {
                reservation.handoff_grant_id == grant.id
                    && reservation.challenge_id == challenge.challenge_id
            });
        if challenge.expires_at <= now && !dispatch_is_frozen {
            return Ok(IdentityCreationRegistrationAdmission::ChallengeExpired);
        }
        Ok(IdentityCreationRegistrationAdmission::Ready(Box::new(
            IdentityCreationRegistrationContext {
                grant: grant.clone(),
                lease,
                challenge,
            },
        )))
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
            .lease_for_account(Uuid::from(grant.local_account_id), &grant.audience_id, true)
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

    async fn reserve_registration_dispatch(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        request_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<IdentityCreationRegisterReserve, Self::Error> {
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(context.grant.local_account_id),
                &context.grant.audience_id,
                true,
            )
            .await?
        else {
            return Ok(IdentityCreationRegisterReserve::Stale);
        };
        if lease.lease_id != context.lease.lease_id
            || lease.fence != context.lease.fence
            || lease.holder_jkt != context.grant.cnf_jkt
            || lease.reserved_identity.as_ref().is_none_or(|reserved| {
                reserved.registration_anchor_digest != context.challenge.registration_anchor_digest
            })
        {
            return Ok(IdentityCreationRegisterReserve::Stale);
        }
        let expected = IdentityCreationRegisterReservation {
            handoff_grant_id: context.grant.id,
            challenge_id: context.challenge.challenge_id.clone(),
            request_digest: request_digest.clone(),
        };
        if let Some(existing) = lease.register_reservation.as_ref() {
            return Ok(if existing == &expected {
                IdentityCreationRegisterReserve::Replay
            } else {
                IdentityCreationRegisterReserve::DuplicateConflict
            });
        }
        if lease.state != IdentityCreationLeaseState::Reserved {
            return Ok(IdentityCreationRegisterReserve::Stale);
        }
        let Some(challenge) = self
            .challenge_by_id(&context.challenge.challenge_id, true)
            .await?
        else {
            return Ok(IdentityCreationRegisterReserve::Stale);
        };
        if !challenge_matches_context(&challenge, context)
            || challenge.consumed_at.is_some()
            || challenge.replaced_at.is_some()
            || challenge.expires_at <= now
        {
            return Ok(IdentityCreationRegisterReserve::Stale);
        }
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET register_handoff_grant_id = $1, \
             register_challenge_id = $2, register_request_digest = $3, updated_at = $4 \
             WHERE local_account_id = $5 AND audience_id = $6 AND lease_id = $7 AND fence = $8 \
             AND holder_jkt = $9 AND state = 'reserved' \
             AND register_handoff_grant_id IS NULL AND register_challenge_id IS NULL \
             AND register_request_digest IS NULL AND register_outcome IS NULL",
        )
        .bind::<SqlUuid, _>(Uuid::from(context.grant.id))
        .bind::<Text, _>(&context.challenge.challenge_id)
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.local_account_id))
        .bind::<Text, _>(&context.grant.audience_id)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(i64::try_from(context.lease.fence)?)
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .execute(self.conn)
        .await?;
        Ok(if updated == 1 {
            IdentityCreationRegisterReserve::Reserved
        } else {
            IdentityCreationRegisterReserve::Stale
        })
    }

    async fn mark_did_published(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        registry_receipt: &arkret_models_identity::DidOperationSubmitOutcome,
        log_head_digest: &arkret_identifiers::Hash,
        registration_did_evidence: &arkret_wire::RegistrationDidEvidence,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(context.grant.local_account_id),
                &context.grant.audience_id,
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
                reserved.registration_anchor_digest != context.challenge.registration_anchor_digest
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
            || lease
                .register_reservation
                .as_ref()
                .is_none_or(|reservation| {
                    reservation.handoff_grant_id != context.grant.id
                        || reservation.challenge_id != context.challenge.challenge_id
                })
        {
            return Ok(false);
        }
        if lease.state == IdentityCreationLeaseState::DidPublished {
            let stored = lease
                .registry_receipt
                .as_ref()
                .and_then(|receipt| arkret_canonical::canonical_json_bytes(receipt).ok());
            let received = arkret_canonical::canonical_json_bytes(registry_receipt).ok();
            return Ok(challenge.consumed_at.is_some()
                && lease.log_head_digest.as_ref() == Some(log_head_digest)
                && stored.is_some()
                && stored == received);
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
        let registry_receipt = serde_json::to_value(registry_receipt)?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'did_published', registry_receipt = $1, \
             log_head_digest = $2, registration_did_evidence = $3, updated_at = $4 \
             WHERE local_account_id = $5 AND audience_id = $6 AND lease_id = $7 AND fence = $8 \
             AND holder_jkt = $9 AND reserved_registration_anchor_digest = $10 \
             AND state IN ('reserved', 'did_published')",
        )
        .bind::<Jsonb, _>(registry_receipt)
        .bind::<Text, _>(log_head_digest.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(registration_did_evidence)?)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.local_account_id))
        .bind::<Text, _>(&context.grant.audience_id)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(i64::try_from(context.lease.fence)?)
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .bind::<Text, _>(context.challenge.registration_anchor_digest.as_str())
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }

    async fn reserve_pcr_genesis_dispatch(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        request_digest: &arkret_identifiers::Hash,
        registration_request_digest: &arkret_identifiers::Hash,
    ) -> Result<bool, Self::Error> {
        let active = diesel::sql_query(
            "SELECT true AS present FROM account_handoff_grants WHERE id=$1 AND local_account_id=$2 AND audience_id=$3 AND cnf_jkt=$4 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > clock_timestamp() FOR SHARE",
        ).bind::<SqlUuid,_>(Uuid::from(context.grant.id)).bind::<SqlUuid,_>(Uuid::from(context.grant.local_account_id))
            .bind::<Text,_>(&context.grant.audience_id).bind::<Text,_>(&context.grant.cnf_jkt)
            .get_result::<ExistsRow>(self.conn).await.optional()?.is_some();
        if !active {
            return Ok(false);
        }
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET pcr_dispatch_request_digest = $1 \
             WHERE local_account_id = $2 AND audience_id = $3 AND lease_id = $4 AND fence = $5 \
             AND holder_jkt = $6 AND state = 'did_published' AND register_request_digest = $7 \
             AND (pcr_dispatch_request_digest IS NULL OR pcr_dispatch_request_digest = $1) \
             AND expires_at > clock_timestamp()",
        )
        .bind::<Text, _>(request_digest.as_str())
        .bind::<SqlUuid, _>(Uuid::from(context.grant.local_account_id))
        .bind::<Text, _>(&context.grant.audience_id)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(i64::try_from(context.lease.fence)?)
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .bind::<Text, _>(registration_request_digest.as_str())
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }

    async fn mark_pcr_accepted(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        request_digest: &arkret_identifiers::Hash,
        outcome: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(context.grant.local_account_id),
                &context.grant.audience_id,
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
                reserved.registration_anchor_digest != context.challenge.registration_anchor_digest
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
                .pcr_genesis_outcome
                .as_ref()
                .and_then(|stored| arkret_canonical::canonical_json_bytes(stored).ok());
            let received = arkret_canonical::canonical_json_bytes(outcome).ok();
            return Ok(
                lease.pcr_genesis_request_digest.as_ref() == Some(request_digest)
                    && stored.is_some()
                    && stored == received,
            );
        }
        let outcome = serde_json::to_value(outcome)?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'pcr_accepted', \
             pcr_genesis_request_digest = $1, pcr_genesis_outcome = $2, updated_at = $3 \
             WHERE local_account_id = $4 AND audience_id = $5 AND lease_id = $6 AND fence = $7 \
             AND holder_jkt = $8 AND state = 'did_published' AND pcr_dispatch_request_digest = $1",
        )
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Jsonb, _>(outcome)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.local_account_id))
        .bind::<Text, _>(&context.grant.audience_id)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(i64::try_from(context.lease.fence)?)
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
                Uuid::from(context.grant.local_account_id),
                &context.grant.audience_id,
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
            || lease.pcr_genesis_outcome.is_none()
        {
            return Ok(false);
        }
        if binding_receipt.identity_creation_lease_id.as_deref() != Some(lease.lease_id.as_str())
            || binding_receipt.lease_fence != Some(lease.fence)
            || binding_receipt.registration_anchor_digest
                != context.challenge.registration_anchor_digest
            || lease.log_head_digest.as_ref() != Some(&context.challenge.method_history_head)
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
        let receipt = serde_json::to_value(binding_receipt)?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'account_bound', binding_receipt = $1, \
             updated_at = $2 WHERE local_account_id = $3 AND audience_id = $4 \
             AND lease_id = $5 AND fence = $6 AND holder_jkt = $7 \
             AND reserved_registration_anchor_digest = $8 AND state = 'pcr_accepted'",
        )
        .bind::<Jsonb, _>(receipt)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.local_account_id))
        .bind::<Text, _>(&context.grant.audience_id)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(i64::try_from(context.lease.fence)?)
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .bind::<Text, _>(context.challenge.registration_anchor_digest.as_str())
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }

    async fn mark_completed(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        request_digest: &arkret_identifiers::Hash,
        outcome: &arkret_models_collaboration::account_operations::AccountRegisterOutcome,
        now: DateTime<Utc>,
    ) -> Result<IdentityCreationBindingCommit, Self::Error> {
        let Some(lease) = self
            .lease_for_account(
                Uuid::from(context.grant.local_account_id),
                &context.grant.audience_id,
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
                reserved.registration_anchor_digest != context.challenge.registration_anchor_digest
            })
            || lease
                .register_reservation
                .as_ref()
                .is_none_or(|reservation| {
                    reservation.handoff_grant_id != context.grant.id
                        || reservation.challenge_id != context.challenge.challenge_id
                        || reservation.request_digest != *request_digest
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

        let outcome = serde_json::to_value(outcome)?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'completed', \
             register_handoff_grant_id = $1, register_challenge_id = $2, \
             register_request_digest = $3, register_outcome = $4, updated_at = $5 \
             WHERE local_account_id = $6 AND audience_id = $7 \
             AND lease_id = $8 AND fence = $9 AND holder_jkt = $10 \
             AND reserved_registration_anchor_digest = $11 AND state = 'account_bound' \
             AND register_handoff_grant_id = $1 AND register_challenge_id = $2 \
             AND register_request_digest = $3 AND register_outcome IS NULL",
        )
        .bind::<SqlUuid, _>(Uuid::from(context.grant.id))
        .bind::<Text, _>(&context.challenge.challenge_id)
        .bind::<Text, _>(request_digest.as_str())
        .bind::<Jsonb, _>(outcome)
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.local_account_id))
        .bind::<Text, _>(&context.grant.audience_id)
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(i64::try_from(context.lease.fence)?)
        .bind::<Text, _>(&context.grant.cnf_jkt)
        .bind::<Text, _>(context.challenge.registration_anchor_digest.as_str())
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
    use chrono::{Duration, TimeZone as _, Utc};
    use coauth_data::Ulid;

    use super::{
        ExistingDidBindingChallengeDisposition, PrincipalRow, classify_device_pairing_stage_replay,
        classify_existing_did_binding_challenge, ensure_did_projects_to_principal,
        lease_quota_advisory_key, principal_from_row,
        reserved_identity_matches_abandonment_checkpoint,
    };

    #[test]
    fn device_pairing_stage_idempotency_replays_only_equal_canonical_body_digest() {
        let digest = arkret_identifiers::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let other = arkret_identifiers::Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap();
        let outcome = br#"{"device_pairing_request_id":"device_pairing_request:01999999-0000-7000-8000-00000000feed"}"#;

        assert_eq!(
            classify_device_pairing_stage_replay(digest.as_str(), outcome, &digest),
            coauth_data::DevicePairingStageInsert::Replay(outcome.to_vec())
        );
        assert_eq!(
            classify_device_pairing_stage_replay(digest.as_str(), outcome, &other),
            coauth_data::DevicePairingStageInsert::DuplicateConflict
        );
    }

    #[test]
    fn lease_quota_advisory_key_is_postgres_text_safe() {
        let account_subject = arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("valid account subject");
        let audience_id = "ak:did_core:webvh:QmExample";

        let key = lease_quota_advisory_key(&account_subject, audience_id);

        assert_eq!(
            key,
            format!("71:{}{audience_id}", account_subject.as_str(),)
        );
        assert!(!key.contains('\0'));
    }

    #[test]
    fn abandonment_checkpoint_matches_projected_principal_not_did() {
        let anchor = crate::test_utils::principal_registration_anchor_fixture(
            "abandonment-checkpoint",
            [9; 32],
        );
        let validated = arkret_identity::validate_principal_registration_anchor(&anchor)
            .expect("valid registration anchor");
        let principal_id = validated.principal_id.clone();
        assert_ne!(validated.did.as_str(), principal_id.as_str());
        let reserved = arkret_models_identity::ReservedIdentityCreation::from_anchor(anchor)
            .expect("valid reservation");

        assert!(reserved_identity_matches_abandonment_checkpoint(
            &reserved,
            &principal_id,
            &validated.did_version_id,
        ));
        assert!(!reserved_identity_matches_abandonment_checkpoint(
            &reserved,
            &principal_id,
            "2-QmWrongWebvhVersion",
        ));
    }

    #[test]
    fn account_handoff_bound_principal_row_rejects_cross_binding_mismatch() {
        let row = PrincipalRow {
            principal_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:webvh:expected".to_owned(),
            )
            .unwrap(),
            verified_did: "did:webvh:other:principal.example".to_owned(),
        };

        assert!(principal_from_row(row).is_err());

        let did =
            arkret_identifiers::Did::new("did:webvh:other:principal.example".to_owned()).unwrap();
        let principal_id =
            arkret_identifiers::DidCoreId::new("ak:did_core:webvh:expected".to_owned()).unwrap();
        assert!(ensure_did_projects_to_principal(&did, &principal_id).is_err());
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

#[cfg(test)]
mod challenge_tests;
