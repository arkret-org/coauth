//! PostgreSQL account-handoff state machine.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::account_handoff::{
    AccountHandoffCreation, AccountHandoffCreationAttempt, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffCreationAttemptState, AccountHandoffGrant,
    AccountHandoffGrantInput, ControllerGateAttestationCommit, ControllerGateAttestationIssuance,
    ControllerGateAttestationReserve, DidBindingChallengeInput, DidBindingChallengeIssue,
    DidBindingChallengeRecord, IdentityAbandonmentChallengeInput,
    IdentityAbandonmentChallengeIssue, IdentityAbandonmentChallengeRecord,
    IdentityAbandonmentCommit, IdentityAbandonmentCommitInput, IdentityBindingChallengeInput,
    IdentityBindingChallengeIssue, IdentityBindingChallengeRecord, IdentityCreationBindingCommit,
    IdentityCreationLeaseRecord, IdentityCreationLeaseRiskDecision, IdentityCreationRegisterLedger,
    IdentityCreationRegisterReplay, IdentityCreationRegistrationContext, IdentityCreationSagaState,
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
    "ak.gate.account.command.issue_did_binding_challenge",
    "ak.gate.account.command.issue_identity_binding_challenge",
    "ak.gate.account.command.issue_identity_abandonment_challenge",
    "ak.gate.account.command.abandon_identity_creation",
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

    async fn controller_gate_issuance(
        &mut self,
        request_id: Uuid,
        for_update: bool,
    ) -> Result<Option<ControllerGateAttestationIssuance>, DatabaseError> {
        let suffix = if for_update { " FOR UPDATE" } else { "" };
        let query = format!(
            "SELECT request_id, canonical_intent_digest, principal_id, \
             agent_authority_service_id, canonical_outcome, outcome_digest, \
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
    ) -> Result<Option<(arkret_identifiers::CoreId, arkret_identifiers::FullId)>, DatabaseError>
    {
        let row = diesel::sql_query(
            "SELECT owners.principal_id, owners.verified_full_id \
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
                arkret_identifiers::CoreId::new(row.principal_id)
                    .map_err(|_| DatabaseError::invalid_operation())?,
                arkret_identifiers::FullId::new(
                    row.verified_full_id
                        .ok_or_else(DatabaseError::invalid_operation)?,
                )
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
             purpose, account_subject, principal_id, full_id, operation_digest, did_version_id, log_head_digest, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
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
             purpose, account_subject, principal_id, full_id, operation_digest, did_version_id, log_head_digest, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
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
             account_subject, principal_id, full_id, did_version_id, log_head_digest, \
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
             account_subject, principal_id, full_id, did_version_id, log_head_digest, \
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
        // Serialize the no-row acquisition case as well as renewal. The lock
        // key contains only the salted account-subject digest and audience.
        let key = format!("{}\0{audience}", account_subject.as_str());
        let _ = diesel::sql_query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0)) IS NULL AS locked",
        )
        .bind::<Text, _>(key)
        .get_result::<AdvisoryLockRow>(self.conn)
        .await?;
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
    #[allow(dead_code)]
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
    principal_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    verified_full_id: Option<String>,
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
    principal_id: String,
    #[diesel(sql_type = Text)]
    agent_authority_service_id: String,
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
        principal_id: arkret_identifiers::PrincipalId::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        agent_authority_service_id: arkret_identifiers::ServiceId::new(
            row.agent_authority_service_id,
        )
        .map_err(|_| DatabaseError::invalid_operation())?,
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
            let did_operation = serde_json::from_value(did_operation)
                .map_err(|_| DatabaseError::invalid_operation())?;
            let reserved =
                arkret_models_identity::ReservedIdentityCreation::from_operation(did_operation)
                    .map_err(|_| DatabaseError::invalid_operation())?;
            if reserved.principal_id.as_str() != principal_id
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
        state: IdentityCreationSagaState::try_from(row.state.as_str())
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
    principal_id: String,
    #[diesel(sql_type = Text)]
    full_id: String,
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
    principal_id: String,
    #[diesel(sql_type = Text)]
    full_id: String,
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
            principal_id: arkret_identifiers::CoreId::new(row.principal_id)
                .map_err(|_| DatabaseError::invalid_operation())?,
            full_id: arkret_identifiers::FullId::new(row.full_id)
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
            audience: arkret_identifiers::ServiceId::new(row.audience)
                .map_err(|_| DatabaseError::invalid_operation())?,
            origin: row.origin,
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(row.trust_domain)
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
    audience: String,
    #[diesel(sql_type = Text)]
    account_subject: String,
    #[diesel(sql_type = Text)]
    holder_jkt: String,
    #[diesel(sql_type = Text)]
    lease_id: String,
    #[diesel(sql_type = BigInt)]
    lease_fence: i64,
    #[diesel(sql_type = Text)]
    principal_id: String,
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
        audience: arkret_identifiers::ServiceId::new(row.audience)
            .map_err(|_| DatabaseError::invalid_operation())?,
        account_subject: arkret_identifiers::Hash::new(row.account_subject)
            .map_err(|_| DatabaseError::invalid_operation())?,
        holder_jkt: row.holder_jkt,
        lease_id: row.lease_id,
        lease_fence: u64::try_from(row.lease_fence)
            .map_err(|_| DatabaseError::invalid_operation())?,
        principal_id: arkret_identifiers::CoreId::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        did_version_id: row.did_version_id,
        challenge_id: row.challenge_id,
        challenge: row.challenge,
        origin: row.origin,
        trust_domain: arkret_identifiers::TypedTrustDomainId::new(row.trust_domain)
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
        principal_id: arkret_identifiers::CoreId::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        full_id: arkret_identifiers::FullId::new(row.full_id)
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
        audience: arkret_identifiers::ServiceId::new(row.audience)
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
        && challenge.account_subject == expected.account_subject
        && challenge.principal_id == expected.principal_id
        && challenge.full_id == expected.full_id
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
              agent_authority_service_id, retained_until, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(input.request_id.uuid())
        .bind::<Text, _>(input.canonical_intent_digest.as_str())
        .bind::<Text, _>(input.principal_id.as_str())
        .bind::<Text, _>(input.agent_authority_service_id.as_str())
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
            || issuance.agent_authority_service_id != input.agent_authority_service_id
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

        if let Some((principal_id, full_id)) = self
            .bound_principal(Uuid::from(input.service_account_id), &input.audience)
            .await?
        {
            return Ok(AccountHandoffCreation::Bound {
                grant,
                principal_id,
                full_id,
            });
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
            if matches!(
                lease.state,
                IdentityCreationSagaState::AccountBound | IdentityCreationSagaState::Completed
            ) {
                let reserved = lease
                    .reserved_identity
                    .as_ref()
                    .ok_or_else(DatabaseError::invalid_operation)?;
                return Ok(AccountHandoffCreation::Bound {
                    grant,
                    principal_id: reserved.principal_id.clone(),
                    full_id: reserved.full_id.clone(),
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
            .map_or(true, |lease| lease.expires_at <= input.issued_at);
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
        if grant.expires_at <= now || grant.revoked_at.is_some() || grant.consumed_at.is_some() {
            return Ok(AccountHandoffCreation::ExpiredReplay);
        }
        if let Some((principal_id, full_id)) = self
            .bound_principal(Uuid::from(grant.service_account_id), &grant.audience)
            .await?
        {
            return Ok(AccountHandoffCreation::Bound {
                grant: grant.clone(),
                principal_id,
                full_id,
            });
        }
        let lease = self
            .lease_for_account(Uuid::from(grant.service_account_id), &grant.audience, false)
            .await?;
        let Some(lease) = lease else {
            return Ok(AccountHandoffCreation::ExpiredReplay);
        };
        if matches!(
            lease.state,
            IdentityCreationSagaState::AccountBound | IdentityCreationSagaState::Completed
        ) {
            let reserved = lease
                .reserved_identity
                .as_ref()
                .ok_or_else(DatabaseError::invalid_operation)?;
            return Ok(AccountHandoffCreation::Bound {
                grant: grant.clone(),
                principal_id: reserved.principal_id.clone(),
                full_id: reserved.full_id.clone(),
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
              account_subject, principal_id, full_id, operation_digest, did_version_id, log_head_digest, control_key_digest, pcr_realm_id, realm_create_payload_digest, \
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
        .bind::<Text, _>(input.full_id.as_str())
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
            if existing.input.request_digest != input.request_digest
                || existing.input.issuing_handoff_grant_id != input.issuing_handoff_grant_id
            {
                return Ok(DidBindingChallengeIssue::DuplicateConflict);
            }
            if existing.consumed_at.is_some() || existing.input.expires_at <= input.issued_at {
                return Ok(DidBindingChallengeIssue::StaleRequest);
            }
            return Ok(DidBindingChallengeIssue::Replay(existing));
        }
        diesel::sql_query(
            "INSERT INTO did_binding_challenges \
             (request_id, request_digest, issuing_handoff_grant_id, service_account_id, \
              account_subject, principal_id, full_id, did_version_id, log_head_digest, \
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
        .bind::<Text, _>(input.full_id.as_str())
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
        Ok(PublishedDidRegisterReplay::Pending(record))
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
            IdentityCreationSagaState::PcrAccepted
                | IdentityCreationSagaState::AccountBound
                | IdentityCreationSagaState::Completed
        ) {
            return Ok(IdentityAbandonmentChallengeIssue::AlreadyAccepted);
        }
        if lease.state != IdentityCreationSagaState::DidPublished {
            return Ok(IdentityAbandonmentChallengeIssue::CheckpointMismatch);
        }
        let Some(reserved) = lease.reserved_identity.as_ref() else {
            return Ok(IdentityAbandonmentChallengeIssue::CheckpointMismatch);
        };
        let reserved_version = reserved
            .did_operation
            .operation
            .get("versionId")
            .and_then(serde_json::Value::as_str);
        if reserved.full_id.as_str() != input.principal_id.as_str()
            || reserved_version != Some(input.did_version_id.as_str())
        {
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
            IdentityCreationSagaState::PcrAccepted
                | IdentityCreationSagaState::AccountBound
                | IdentityCreationSagaState::Completed
        ) {
            return Ok(IdentityAbandonmentCommit::AlreadyAccepted);
        }
        if lease.state != IdentityCreationSagaState::DidPublished {
            return Ok(IdentityAbandonmentCommit::ChallengeMismatch);
        }
        let Some(reserved) = lease.reserved_identity.as_ref() else {
            return Ok(IdentityAbandonmentCommit::ChallengeMismatch);
        };
        let reserved_version = reserved
            .did_operation
            .operation
            .get("versionId")
            .and_then(serde_json::Value::as_str);
        if reserved.full_id.as_str() != input.principal_id.as_str()
            || reserved_version != Some(input.did_version_id.as_str())
        {
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
            account_subject: arkret_identifiers::Hash::new(format!(
                "sha256:{:x}",
                sha2::Sha256::digest(service_account_id.to_string().as_bytes())
            ))
            .unwrap(),
            risk_decision: IdentityCreationLeaseRiskDecision::Allowed,
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
    async fn lease_quota_is_durable_exact_replay_safe_and_uses_closed_windows() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool);
        let mut repo = factory.create().await.unwrap();
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let user = repo
            .user()
            .add(&mut rng, &clock, format!("lease-quota-{label}"))
            .await
            .unwrap();

        let first = handoff_input(&mut rng, user.id, now, &"Q".repeat(43), &unique_lease_id());
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(first.clone())
                .await
                .unwrap(),
            AccountHandoffCreation::Active { .. }
        ));
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(first)
                .await
                .unwrap(),
            AccountHandoffCreation::Active { .. }
        ));

        // Commit and reopen through a new repository instance. The following
        // renewal must observe the durable quota event, not process memory.
        repo.save().await.unwrap();
        let mut repo = factory.create().await.unwrap();

        let renewal = handoff_input(
            &mut rng,
            user.id,
            now + Duration::minutes(1),
            &"Q".repeat(43),
            &unique_lease_id(),
        );
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(renewal)
                .await
                .unwrap(),
            AccountHandoffCreation::Active { .. }
        ));
        let too_soon = handoff_input(
            &mut rng,
            user.id,
            now + Duration::minutes(2),
            &"Q".repeat(43),
            &unique_lease_id(),
        );
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(too_soon)
                .await
                .unwrap(),
            AccountHandoffCreation::RateLimited { .. }
        ));

        // Five acquisitions in the server's ten-minute window are accepted;
        // exact replay above did not consume a second slot.
        for index in 1..5 {
            let issued_at = now + Duration::minutes(i64::from(index) * 16);
            let input = handoff_input(
                &mut rng,
                user.id,
                issued_at,
                &"Q".repeat(43),
                &unique_lease_id(),
            );
            assert!(matches!(
                repo.account_handoff()
                    .create_with_lease(input)
                    .await
                    .unwrap(),
                AccountHandoffCreation::Active { .. }
            ));
        }
        let sixth = handoff_input(
            &mut rng,
            user.id,
            now + Duration::minutes(80),
            &"Q".repeat(43),
            &unique_lease_id(),
        );
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(sixth)
                .await
                .unwrap(),
            AccountHandoffCreation::RateLimited { .. }
        ));
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn lease_acquisition_quota_serializes_cross_instance_concurrency() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let mut setup = factory.create().await.unwrap();
        let mut users = Vec::new();
        for index in 0..6 {
            users.push(
                setup
                    .user()
                    .add(
                        &mut rng,
                        &clock,
                        format!("lease-concurrent-{label}-{index}"),
                    )
                    .await
                    .unwrap(),
            );
        }
        setup.save().await.unwrap();

        // Separate service accounts model independent acquisition requests,
        // while the shared salted subject and audience exercise the protocol
        // quota key. Each future owns a distinct database transaction.
        let shared_subject = arkret_identifiers::Hash::new(format!(
            "sha256:{:x}",
            sha2::Sha256::digest(format!("shared-{label}").as_bytes())
        ))
        .unwrap();
        let attempts = users.into_iter().map(|user| {
            let mut input =
                handoff_input(&mut rng, user.id, now, &"C".repeat(43), &unique_lease_id());
            input.account_subject = shared_subject.clone();
            let factory = factory.clone();
            async move {
                let mut repo = factory.create().await.unwrap();
                let result = repo
                    .account_handoff()
                    .create_with_lease(input)
                    .await
                    .unwrap();
                let accepted = matches!(&result, AccountHandoffCreation::Active { .. });
                if accepted {
                    repo.save().await.unwrap();
                } else {
                    assert!(matches!(result, AccountHandoffCreation::RateLimited { .. }));
                    repo.cancel().await.unwrap();
                }
                accepted
            }
        });
        let results = futures_util::future::join_all(attempts).await;
        assert_eq!(results.iter().filter(|accepted| **accepted).count(), 5);
        assert_eq!(results.iter().filter(|accepted| !**accepted).count(), 1);
    }

    #[tokio::test]
    async fn lease_renewal_enforces_the_durable_hour_window() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool.clone());
        let clock = MockClock::default();
        let now = clock.now();
        let mut rng = test_rng();
        let label = Uuid::now_v7().simple().to_string();
        let mut repo = factory.create().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &clock, format!("lease-hour-{label}"))
            .await
            .unwrap();
        let first = handoff_input(&mut rng, user.id, now, &"H".repeat(43), &unique_lease_id());
        let account_subject = first.account_subject.clone();
        let audience = first.audience.clone();
        let created = repo
            .account_handoff()
            .create_with_lease(first)
            .await
            .unwrap();
        let AccountHandoffCreation::Active { lease, .. } = created else {
            panic!("identity creation must acquire an active lease");
        };
        let lease_id = lease.lease_id.clone();
        repo.save().await.unwrap();

        // Seed twelve prior server-timestamped renewals outside the one-minute
        // window but inside the hour. The next renewal must be rejected by the
        // independent 12/hour ceiling.
        let mut conn = pool.get().await.unwrap();
        for _ in 0..12 {
            diesel::sql_query(
                "INSERT INTO identity_creation_lease_rate_limit_events \
                 (request_id, account_subject, audience, lease_id, action, occurred_at) \
                 VALUES ($1, $2, $3, $4, 'renewal', CURRENT_TIMESTAMP - INTERVAL '2 minutes')",
            )
            .bind::<SqlUuid, _>(Uuid::now_v7())
            .bind::<Text, _>(account_subject.as_str())
            .bind::<Text, _>(&audience)
            .bind::<Text, _>(&lease_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        drop(conn);

        let renewal = handoff_input(
            &mut rng,
            user.id,
            now + Duration::minutes(1),
            &"H".repeat(43),
            &unique_lease_id(),
        );
        let mut repo = factory.create().await.unwrap();
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(renewal)
                .await
                .unwrap(),
            AccountHandoffCreation::RateLimited { .. }
        ));
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn lease_acquisition_rechecks_current_account_risk_in_the_same_transaction() {
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
            .add(&mut rng, &clock, format!("lease-risk-{label}"))
            .await
            .unwrap();
        let user = repo.user().lock(&clock, user).await.unwrap();
        assert!(!user.is_valid());

        let input = handoff_input(&mut rng, user.id, now, &"R".repeat(43), &unique_lease_id());
        assert!(matches!(
            repo.account_handoff()
                .create_with_lease(input)
                .await
                .unwrap(),
            AccountHandoffCreation::RiskRejected { .. }
        ));
        repo.cancel().await.unwrap();
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
        assert_eq!(
            serde_json::to_value(recovered.lease.registry_receipt).unwrap(),
            serde_json::to_value(Some(registry_receipt)).unwrap()
        );
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

#[cfg(test)]
mod abandonment_tests {
    use std::collections::BTreeMap;

    use chrono::Duration;
    use coauth_data::account_handoff::{
        AccountHandoffAuthorizationCheckpoint, AccountHandoffCreation,
        AccountHandoffCreationAttemptCommit, AccountHandoffCreationAttemptReserve,
        AccountHandoffGrantInput, IdentityAbandonmentChallengeInput,
        IdentityAbandonmentChallengeIssue, IdentityAbandonmentCommit,
        IdentityAbandonmentCommitInput, IdentityBindingChallengeInput,
        IdentityBindingChallengeIssue, IdentityCreationLeaseRiskDecision,
        NewAccountHandoffCreationAttempt,
    };
    use coauth_data::clock::MockClock;
    use coauth_data::user::UserRepository as _;
    use coauth_data::{
        AccountHandoffRepository as _, Clock as _, RepositoryAccess as _, RepositoryFactory as _,
        new_id,
    };
    use diesel::sql_types::{Bytea, Jsonb};
    use diesel_async::pooled_connection::deadpool::Pool;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use sha2::Digest as _;

    use super::*;
    use crate::PgRepositoryFactory;

    const AUDIENCE: &str = "did:web:principal.example";
    const HOLDER_JKT: &str = "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH";
    const PCR_REALM_ID: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";

    fn hash(fill: char) -> arkret_identifiers::Hash {
        arkret_identifiers::Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn request_id() -> arkret_identifiers::RequestId {
        arkret_identifiers::RequestId::new(format!("ak:request:{}", Uuid::now_v7())).unwrap()
    }

    fn test_rng() -> ChaChaRng {
        let bytes = Uuid::now_v7().into_bytes();
        let high = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let low = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        ChaChaRng::seed_from_u64(high ^ low)
    }

    fn did_operation(
        label: &str,
        did_version_id: &str,
    ) -> arkret_models_identity::DidOperationSubmitRequestBody {
        let did = arkret_identifiers::Did::new(format!("did:webvh:z{label}:example.com")).unwrap();
        arkret_models_identity::DidOperationSubmitRequestBody {
            did: did.clone(),
            did_method: "webvh".to_owned(),
            seq: Some(0),
            prev_event_digest: None,
            operation: BTreeMap::from([
                (
                    "state".to_owned(),
                    serde_json::json!({ "id": did.as_str() }),
                ),
                (
                    "versionId".to_owned(),
                    serde_json::Value::String(did_version_id.to_owned()),
                ),
            ]),
        }
    }

    fn handoff_input(
        rng: &mut ChaChaRng,
        service_account_id: Ulid,
        now: DateTime<Utc>,
        account_subject: arkret_identifiers::Hash,
    ) -> AccountHandoffGrantInput {
        AccountHandoffGrantInput {
            id: new_id(now, rng),
            request_id: request_id(),
            request_digest: hash('1'),
            service_account_id,
            browser_session_id: None,
            audience: AUDIENCE.to_owned(),
            account_subject,
            risk_decision: IdentityCreationLeaseRiskDecision::Allowed,
            cnf_jkt: HOLDER_JKT.to_owned(),
            account_handoff_grant: format!("{}{}", Uuid::now_v7().simple(), "G".repeat(11)),
            issued_at: now,
            expires_at: now + Duration::minutes(30),
            lease_id: format!("{}{}", Uuid::now_v7().simple(), "L".repeat(11)),
            lease_expires_at: now + Duration::minutes(15),
        }
    }

    #[derive(Clone)]
    struct PublishedFixture {
        pool: Pool<AsyncPgConnection>,
        grant: coauth_data::account_handoff::AccountHandoffGrant,
        lease: coauth_data::account_handoff::IdentityCreationLeaseRecord,
        reserved: arkret_models_identity::ReservedIdentityCreation,
        account_subject: arkret_identifiers::Hash,
        did_version_id: String,
        issued: coauth_data::account_handoff::IdentityAbandonmentChallengeRecord,
        now: DateTime<Utc>,
    }

    impl PublishedFixture {
        async fn create(challenge_offset: Duration) -> Option<Self> {
            let pool = crate::test_utils::setup_test_pool().await?;
            let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
            let clock = MockClock::new(now);
            let mut rng = test_rng();
            let label = Uuid::now_v7().simple().to_string();
            let account_subject = arkret_identifiers::Hash::new(format!(
                "sha256:{:x}",
                sha2::Sha256::digest(format!("abandon-subject-{label}").as_bytes())
            ))
            .unwrap();
            let did_version_id = format!("1-{label}");

            let mut repo = PgRepositoryFactory::new(pool.clone())
                .create()
                .await
                .unwrap();
            let user = repo
                .user()
                .add(&mut rng, &clock, format!("abandon-{label}"))
                .await
                .unwrap();
            let created = repo
                .account_handoff()
                .create_with_lease(handoff_input(
                    &mut rng,
                    user.id,
                    clock.now(),
                    account_subject.clone(),
                ))
                .await
                .unwrap();
            let AccountHandoffCreation::Active { grant, lease } = created else {
                panic!("fixture must acquire an identity-creation lease");
            };
            repo.save().await.unwrap();

            let operation = did_operation(&label, &did_version_id);
            let reserved =
                arkret_models_identity::ReservedIdentityCreation::from_operation(operation)
                    .unwrap();
            let head_digest = hash('3');
            let registry_receipt = arkret_models_identity::DidOperationSubmitOutcome {
                status: arkret_models_identity::DidOperationSubmitStatus::Accepted,
                did: reserved.full_id.clone(),
                seq: Some(0),
                head_event_digest: Some(head_digest.clone()),
                operation_ref: None,
                receipts: Vec::new(),
            };
            let mut conn = pool.get().await.unwrap();
            diesel::sql_query(
                "UPDATE identity_creation_leases SET reserved_principal_id = $1, \
                 reserved_operation_digest = $2, did_operation = $3, state = 'did_published', \
                 registry_receipt = $4, head_event_digest = $5, updated_at = $6 \
                 WHERE service_account_id = $7 AND audience = $8 AND lease_id = $9",
            )
            .bind::<Text, _>(reserved.principal_id.as_str())
            .bind::<Text, _>(reserved.operation_digest.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&reserved.did_operation).unwrap())
            .bind::<Jsonb, _>(serde_json::to_value(registry_receipt).unwrap())
            .bind::<Text, _>(head_digest.as_str())
            .bind::<Timestamptz, _>(now)
            .bind::<SqlUuid, _>(Uuid::from(user.id))
            .bind::<Text, _>(AUDIENCE)
            .bind::<Text, _>(&lease.lease_id)
            .execute(&mut *conn)
            .await
            .unwrap();
            drop(conn);

            let challenge_issued_at = now + challenge_offset;
            let challenge_input = IdentityAbandonmentChallengeInput {
                request_id: request_id(),
                request_digest: hash('4'),
                issuing_handoff_grant_id: grant.id,
                service_account_id: user.id,
                audience: AUDIENCE.to_owned(),
                account_subject: account_subject.clone(),
                holder_jkt: HOLDER_JKT.to_owned(),
                lease_id: lease.lease_id.clone(),
                lease_fence: lease.fence,
                principal_id: reserved.full_id.clone(),
                did_version_id: did_version_id.clone(),
                challenge_id: format!("{}{}", Uuid::now_v7().simple(), "I".repeat(11)),
                challenge: format!("{}{}", Uuid::now_v7().simple(), "C".repeat(11)),
                origin: "https://account.example".to_owned(),
                trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                    "ak:trust_domain:example.net",
                )
                .unwrap(),
                issued_at: challenge_issued_at,
                expires_at: challenge_issued_at + Duration::minutes(5),
            };
            let mut repo = PgRepositoryFactory::new(pool.clone())
                .create()
                .await
                .unwrap();
            let issued = match repo
                .account_handoff()
                .issue_identity_abandonment_challenge(challenge_input)
                .await
                .unwrap()
            {
                IdentityAbandonmentChallengeIssue::Issued(challenge) => challenge,
                other => panic!("fixture challenge was not issued: {other:?}"),
            };
            repo.save().await.unwrap();

            Some(Self {
                pool,
                grant,
                lease: *lease,
                reserved,
                account_subject,
                did_version_id,
                issued,
                now,
            })
        }

        fn commit_input(&self, now: DateTime<Utc>) -> IdentityAbandonmentCommitInput {
            IdentityAbandonmentCommitInput {
                request_id: request_id(),
                request_digest: hash('5'),
                confirming_handoff_grant_id: Ulid::from(Uuid::now_v7()),
                service_account_id: self.grant.service_account_id,
                audience: self.grant.audience.clone(),
                holder_jkt: self.grant.cnf_jkt.clone(),
                challenge_id: self.issued.challenge_id.clone(),
                challenge: self.issued.challenge.clone(),
                lease_id: self.lease.lease_id.clone(),
                lease_fence: self.lease.fence,
                principal_id: self.reserved.full_id.clone(),
                did_version_id: self.did_version_id.clone(),
                now,
            }
        }

        async fn seed_committed_checkpoint(&self) -> arkret_identifiers::RequestId {
            let request_id = request_id();
            let canonical_intent = br#"{"issuer":"https://issuer.example"}"#.to_vec();
            let canonical_intent_digest = arkret_identifiers::Hash::new(format!(
                "sha256:{:x}",
                sha2::Sha256::digest(&canonical_intent)
            ))
            .unwrap();
            let attempt = NewAccountHandoffCreationAttempt {
                request_id: request_id.clone(),
                request_digest: hash('6'),
                canonical_intent_digest: canonical_intent_digest.clone(),
                canonical_intent,
                holder_jkt: HOLDER_JKT.to_owned(),
                issuer: "https://issuer.example".to_owned(),
                client_id: "arkret-test".to_owned(),
                authorization_code_digest: hash('7'),
                dpop_jti_digest: hash('8'),
                retained_until: self.now + Duration::days(7),
                now: self.now,
            };
            let checkpoint = AccountHandoffAuthorizationCheckpoint {
                service_account_id: self.grant.service_account_id.to_string(),
                browser_session_id: None,
                audience: self.grant.audience.clone(),
                account_handle: "alice:example.com".to_owned(),
                preferred_locale: None,
            };
            let outcome = arkret_models_identity::AccountHandoffOutcome {
                request_id: request_id.clone(),
                account_handle: arkret_models_identity::Handle::parse("alice:example.com").unwrap(),
                account_subject: self.account_subject.clone(),
                preferred_locale: None,
                account_handoff_grant: "checkpoint-grant-value-that-is-long-enough".to_owned(),
                expires_at: self.grant.expires_at,
                allowed_operations: arkret_models_identity::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
                binding: arkret_models_identity::AccountHandoffBinding::IdentityCreationActive {
                    identity_creation_lease: arkret_models_identity::IdentityCreationLease {
                        identity_creation_lease_id: self.lease.lease_id.clone(),
                        fence: self.lease.fence,
                        expires_at: self.lease.expires_at,
                        reserved_identity: Some(self.reserved.clone()),
                    },
                },
            };
            let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome).unwrap();
            let outcome_digest = arkret_identifiers::Hash::new(format!(
                "sha256:{:x}",
                sha2::Sha256::digest(&canonical_outcome)
            ))
            .unwrap();

            let mut repo = PgRepositoryFactory::new(self.pool.clone())
                .create()
                .await
                .unwrap();
            assert!(matches!(
                repo.account_handoff()
                    .reserve_creation_attempt(attempt)
                    .await
                    .unwrap(),
                AccountHandoffCreationAttemptReserve::Reserved(_)
            ));
            assert!(matches!(
                repo.account_handoff()
                    .checkpoint_creation_authorization(
                        &request_id,
                        &canonical_intent_digest,
                        &checkpoint,
                        self.now + Duration::seconds(1),
                    )
                    .await
                    .unwrap(),
                AccountHandoffCreationAttemptCommit::Committed(_)
            ));
            assert!(matches!(
                repo.account_handoff()
                    .commit_creation_attempt(
                        &request_id,
                        &canonical_intent_digest,
                        &canonical_outcome,
                        &outcome_digest,
                        self.now + Duration::seconds(2),
                    )
                    .await
                    .unwrap(),
                AccountHandoffCreationAttemptCommit::Committed(_)
            ));
            repo.save().await.unwrap();
            request_id
        }

        async fn mark_pcr_accepted(&self) {
            let pcr_receipt = serde_json::json!({
                "principal_id": self.reserved.principal_id.as_str(),
                "pcr_realm_id": PCR_REALM_ID,
                "accepted_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "receipt": {
                    "schema": "ak.schema.event_batch_receipt.v1",
                    "receipt_id": "ak:receipt:01904100-0000-7000-8000-000000000001",
                    "issuer": AUDIENCE,
                    "scope": {
                        "kind": "pcr_genesis_unit",
                        "principal_id": self.reserved.principal_id.as_str(),
                        "realm_id": PCR_REALM_ID,
                        "did_version_id": self.did_version_id.as_str(),
                        "log_head_digest": hash('a'),
                        "control_key_digest": hash('b'),
                        "create_digest": hash('c'),
                        "founding_authorize_digest": hash('d'),
                        "accepted_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                        "device_key_digest": hash('e'),
                        "hpke_key_digest": hash('f'),
                        "accepted_at": self.now,
                        "audience": AUDIENCE
                    },
                    "frontier": { "actor_seq": 1 },
                    "events": [],
                    "created_at": self.now,
                    "proofs": []
                }
            });
            let _: arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome =
                serde_json::from_value(pcr_receipt.clone()).unwrap();
            let mut conn = self.pool.get().await.unwrap();
            diesel::sql_query(
                "UPDATE identity_creation_leases SET state = 'pcr_accepted', \
                 pcr_genesis_request_digest = $1, pcr_genesis_receipt = $2, updated_at = $3 \
                 WHERE service_account_id = $4 AND audience = $5 AND lease_id = $6",
            )
            .bind::<Text, _>(hash('9').as_str())
            .bind::<Jsonb, _>(pcr_receipt)
            .bind::<Timestamptz, _>(self.now)
            .bind::<SqlUuid, _>(Uuid::from(self.grant.service_account_id))
            .bind::<Text, _>(&self.grant.audience)
            .bind::<Text, _>(&self.lease.lease_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn abandonment_rejects_reused_grant_expiry_and_pcr_accept_race() {
        let Some(fresh) = PublishedFixture::create(Duration::zero()).await else {
            return;
        };
        let mut reused = fresh.commit_input(fresh.now + Duration::seconds(1));
        reused.confirming_handoff_grant_id = fresh.grant.id;
        let mut repo = PgRepositoryFactory::new(fresh.pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .abandon_identity_creation(reused)
                .await
                .unwrap(),
            IdentityAbandonmentCommit::GrantReused
        ));
        repo.cancel().await.unwrap();

        let Some(expired) = PublishedFixture::create(-Duration::minutes(10)).await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(expired.pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .abandon_identity_creation(expired.commit_input(expired.now))
                .await
                .unwrap(),
            IdentityAbandonmentCommit::ChallengeExpired
        ));
        repo.cancel().await.unwrap();

        let Some(accepted) = PublishedFixture::create(Duration::zero()).await else {
            return;
        };
        accepted.mark_pcr_accepted().await;
        let mut repo = PgRepositoryFactory::new(accepted.pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .abandon_identity_creation(
                    accepted.commit_input(accepted.now + Duration::seconds(1))
                )
                .await
                .unwrap(),
            IdentityAbandonmentCommit::AlreadyAccepted
        ));
        repo.cancel().await.unwrap();

        let mut conn = accepted.pool.get().await.unwrap();
        assert_eq!(
            diesel::sql_query(
                "SELECT EXISTS(SELECT 1 FROM identity_orphan_anchor_tombstones \
                 WHERE principal_id = $1) AS present",
            )
            .bind::<Text, _>(accepted.reserved.principal_id.as_str())
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .unwrap()
            .present,
            false
        );
    }

    #[tokio::test]
    async fn abandonment_exact_concurrent_replay_consumes_once_and_suppresses_checkpoint() {
        let Some(fixture) = PublishedFixture::create(Duration::zero()).await else {
            return;
        };
        let checkpoint_request_id = fixture.seed_committed_checkpoint().await;
        let input = fixture.commit_input(fixture.now + Duration::seconds(3));
        let attempts = (0..2).map(|_| {
            let pool = fixture.pool.clone();
            let input = input.clone();
            async move {
                let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
                let outcome = repo
                    .account_handoff()
                    .abandon_identity_creation(input)
                    .await
                    .unwrap();
                repo.save().await.unwrap();
                outcome
            }
        });
        let outcomes = futures_util::future::join_all(attempts).await;
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, IdentityAbandonmentCommit::Abandoned(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, IdentityAbandonmentCommit::Replay(_)))
                .count(),
            1
        );

        let mut different = input.clone();
        different.request_id = request_id();
        different.request_digest = hash('0');
        let mut repo = PgRepositoryFactory::new(fixture.pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .abandon_identity_creation(different)
                .await
                .unwrap(),
            IdentityAbandonmentCommit::ChallengeConsumed
        ));
        repo.cancel().await.unwrap();

        #[derive(QueryableByName)]
        struct CheckpointRow {
            #[diesel(sql_type = Bytea)]
            canonical_outcome: Vec<u8>,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let stored = diesel::sql_query(
            "SELECT canonical_outcome FROM account_handoff_creation_attempts WHERE request_id = $1",
        )
        .bind::<SqlUuid, _>(checkpoint_request_id.uuid())
        .get_result::<CheckpointRow>(&mut *conn)
        .await
        .unwrap();
        let outcome: arkret_models_identity::AccountHandoffOutcome =
            serde_json::from_slice(&stored.canonical_outcome).unwrap();
        let arkret_models_identity::AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } = outcome.binding
        else {
            panic!("checkpoint binding changed variant");
        };
        assert!(identity_creation_lease.reserved_identity.is_none());
        assert_eq!(
            identity_creation_lease.expires_at,
            arkret_canonical::normalize_timestamp_canonical(input.now)
        );
        assert_eq!(
            diesel::sql_query(
                "SELECT EXISTS(SELECT 1 FROM identity_creation_leases \
                 WHERE service_account_id = $1 AND audience = $2) AS present",
            )
            .bind::<SqlUuid, _>(Uuid::from(fixture.grant.service_account_id))
            .bind::<Text, _>(&fixture.grant.audience)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .unwrap()
            .present,
            false
        );
        assert!(
            diesel::sql_query(
                "SELECT EXISTS(SELECT 1 FROM identity_orphan_anchor_tombstones \
                 WHERE principal_id = $1 AND abandonment_request_id = $2) AS present",
            )
            .bind::<Text, _>(fixture.reserved.principal_id.as_str())
            .bind::<SqlUuid, _>(input.request_id.uuid())
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .unwrap()
            .present,
            "both exact concurrent confirmations must converge on one durable tombstone"
        );
    }

    #[tokio::test]
    async fn abandoned_orphan_anchor_is_permanently_rejected_by_reservation_gate() {
        let Some(fixture) = PublishedFixture::create(Duration::zero()).await else {
            return;
        };
        let input = fixture.commit_input(fixture.now + Duration::seconds(1));
        let mut repo = PgRepositoryFactory::new(fixture.pool.clone())
            .create()
            .await
            .unwrap();
        assert!(matches!(
            repo.account_handoff()
                .abandon_identity_creation(input)
                .await
                .unwrap(),
            IdentityAbandonmentCommit::Abandoned(_)
        ));
        repo.save().await.unwrap();

        let mut rng = test_rng();
        let renewed_at = fixture.now + Duration::seconds(2);
        let mut repo = PgRepositoryFactory::new(fixture.pool.clone())
            .create()
            .await
            .unwrap();
        let replacement = repo
            .account_handoff()
            .create_with_lease(handoff_input(
                &mut rng,
                fixture.grant.service_account_id,
                renewed_at,
                fixture.account_subject.clone(),
            ))
            .await
            .unwrap();
        let AccountHandoffCreation::Active { lease, .. } = replacement else {
            panic!("a fresh lease must be available after explicit abandonment");
        };
        let binding_input = IdentityBindingChallengeInput {
            request_id: request_id(),
            request_digest: hash('a'),
            service_account_id: fixture.grant.service_account_id,
            audience: fixture.grant.audience.clone(),
            lease_id: lease.lease_id.clone(),
            lease_fence: lease.fence,
            holder_jkt: lease.holder_jkt.clone(),
            did_operation: fixture.reserved.did_operation.clone(),
            principal_id: fixture.reserved.principal_id.clone(),
            full_id: fixture.reserved.full_id.clone(),
            operation_digest: fixture.reserved.operation_digest.clone(),
            account_subject: fixture.account_subject,
            did_version_id: fixture.did_version_id,
            log_head_digest: hash('b'),
            control_key_digest: hash('c'),
            pcr_realm_id: arkret_identifiers::RealmId::new(PCR_REALM_ID).unwrap(),
            realm_create_payload_digest: hash('d'),
            founding_authorize_payload_digest: hash('e'),
            initial_session_request_digest: hash('f'),
            challenge_id: format!("{}{}", Uuid::now_v7().simple(), "J".repeat(11)),
            challenge: format!("{}{}", Uuid::now_v7().simple(), "K".repeat(11)),
            origin: "https://account.example".to_owned(),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:example.net",
            )
            .unwrap(),
            issued_at: renewed_at,
            expires_at: renewed_at + Duration::minutes(5),
            lease_expires_at: lease.expires_at,
        };
        assert!(matches!(
            repo.account_handoff()
                .reserve_and_issue_challenge(binding_input)
                .await
                .unwrap(),
            IdentityBindingChallengeIssue::ReservationConflict
        ));
        repo.cancel().await.unwrap();
    }
}
