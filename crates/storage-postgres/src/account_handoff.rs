//! PostgreSQL account-handoff state machine.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::account_handoff::{
    AccountHandoffCreation, AccountHandoffGrant, AccountHandoffGrantInput,
    IdentityBindingChallengeInput, IdentityBindingChallengeIssue, IdentityBindingChallengeRecord,
    IdentityCreationLeaseRecord, IdentityCreationRegistrationContext, IdentityCreationSagaState,
};
use coauth_data::{AccountHandoffRepository, Ulid};
use diesel::OptionalExtension as _;
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use crate::DatabaseError;

const ALLOWED_OPERATIONS: [&str; 3] = [
    "ak.gate.account.command.issue_identity_binding_challenge",
    "ak.gate.account.command.register",
    "ak.gate.account.command.issue_session_grant",
];

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
             registry_receipt, head_event_digest, binding_receipt, created_at, updated_at \
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
    ) -> Result<Option<arkret_core::Did>, DatabaseError> {
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
        row.map(|row| arkret_core::Did::new(row.principal_id))
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
    ) -> Result<Option<IdentityBindingChallengeRecord>, DatabaseError> {
        let row = diesel::sql_query(
            "SELECT request_id, request_digest, service_account_id, challenge_id, challenge, \
             purpose, principal_id, operation_digest, lease_id, lease_fence, dpop_jkt, audience, \
             origin, trust_domain, issued_at, expires_at, consumed_at, replaced_at \
             FROM identity_binding_challenges WHERE challenge_id = $1",
        )
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
        request_id: arkret_core::RequestId::new(format!("ak:request:{}", row.request_id))
            .map_err(|_| DatabaseError::invalid_operation())?,
        request_digest: arkret_core::Hash::new(row.request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        service_account_id: Ulid::from(row.service_account_id),
        browser_session_id: row.browser_session_id.map(Ulid::from),
        audience: row.audience,
        cnf_jkt: row.cnf_jkt,
        allowed_operations: arkret_core::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
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
            Some(arkret_core::ReservedIdentityCreation {
                principal_id: arkret_core::Did::new(principal_id)
                    .map_err(|_| DatabaseError::invalid_operation())?,
                operation_digest: arkret_core::Hash::new(operation_digest)
                    .map_err(|_| DatabaseError::invalid_operation())?,
                did_operation: serde_json::from_value(did_operation)
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
            .map(arkret_core::Hash::new)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
        binding_receipt: row
            .binding_receipt
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| DatabaseError::invalid_operation())?,
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
        request_id: arkret_core::RequestId::new(format!("ak:request:{}", row.request_id))
            .map_err(|_| DatabaseError::invalid_operation())?,
        request_digest: arkret_core::Hash::new(row.request_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        service_account_id: Ulid::from(row.service_account_id),
        challenge_id: row.challenge_id,
        challenge: row.challenge,
        purpose: arkret_core::IdentityBindingPurpose::AccountBinding,
        principal_id: arkret_core::Did::new(row.principal_id)
            .map_err(|_| DatabaseError::invalid_operation())?,
        operation_digest: arkret_core::Hash::new(row.operation_digest)
            .map_err(|_| DatabaseError::invalid_operation())?,
        lease_id: row.lease_id,
        lease_fence: u64::try_from(row.lease_fence)
            .map_err(|_| DatabaseError::invalid_operation())?,
        dpop_jkt: row.dpop_jkt,
        audience: arkret_core::Did::new(row.audience)
            .map_err(|_| DatabaseError::invalid_operation())?,
        origin: row.origin,
        trust_domain: arkret_core::TypedTrustDomainId::new(row.trust_domain)
            .map_err(|_| DatabaseError::invalid_operation())?,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        consumed_at: row.consumed_at,
        replaced_at: row.replaced_at,
    })
}

fn retry_after_ms(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    u64::try_from((expires_at - now).num_milliseconds().max(1)).unwrap_or(u64::MAX)
}

#[async_trait]
impl AccountHandoffRepository for PgAccountHandoffRepository<'_> {
    type Error = DatabaseError;

    async fn get_by_request_id(
        &mut self,
        request_id: &arkret_core::RequestId,
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

        let reserved =
            arkret_core::ReservedIdentityCreation::from_operation(input.did_operation.clone())
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
        let Some(challenge) = self.challenge_by_id(challenge_id).await? else {
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

    async fn mark_published(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        registry_receipt: &serde_json::Value,
        head_event_digest: &arkret_core::Hash,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        diesel::sql_query(
            "UPDATE identity_binding_challenges SET consumed_at = COALESCE(consumed_at, $1) \
             WHERE challenge_id = $2 AND service_account_id = $3 AND lease_id = $4 \
             AND lease_fence = $5 AND replaced_at IS NULL",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<Text, _>(&context.challenge.challenge_id)
        .bind::<SqlUuid, _>(Uuid::from(context.grant.service_account_id))
        .bind::<Text, _>(&context.lease.lease_id)
        .bind::<BigInt, _>(
            i64::try_from(context.lease.fence).map_err(|_| DatabaseError::invalid_operation())?,
        )
        .execute(self.conn)
        .await?;
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
        binding_receipt: &arkret_core::AccountBindingReceipt,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let receipt = serde_json::to_value(binding_receipt)
            .map_err(|_| DatabaseError::invalid_operation())?;
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET state = 'bound', binding_receipt = $1, \
             updated_at = $2 WHERE service_account_id = $3 AND audience = $4 \
             AND lease_id = $5 AND fence = $6 AND holder_jkt = $7 \
             AND reserved_operation_digest = $8 AND state IN ('published', 'bound')",
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

    async fn claim_first_device_enrollment(
        &mut self,
        service_account_id: Ulid,
        audience: &str,
        principal_id: &arkret_core::Did,
        device_id: &arkret_core::DeviceId,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let updated = diesel::sql_query(
            "UPDATE identity_creation_leases SET first_device_id = $1, \
             first_device_enrolled_at = $2, updated_at = $2 \
             WHERE service_account_id = $3 AND audience = $4 AND state = 'bound' \
             AND binding_receipt IS NOT NULL AND reserved_principal_id = $5 \
             AND first_device_id IS NULL AND first_device_enrolled_at IS NULL",
        )
        .bind::<Text, _>(device_id.as_str())
        .bind::<Timestamptz, _>(now)
        .bind::<SqlUuid, _>(Uuid::from(service_account_id))
        .bind::<Text, _>(audience)
        .bind::<Text, _>(principal_id.as_str())
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
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

    use chrono::Duration;
    use coauth_data::clock::MockClock;
    use coauth_data::user::UserRepository as _;
    use coauth_data::{Clock as _, RepositoryAccess as _, RepositoryFactory as _, new_id};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

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
            request_id: arkret_core::RequestId::new(format!("ak:request:{}", Uuid::now_v7()))
                .unwrap(),
            request_digest: arkret_core::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
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

    fn did_operation(label: &str) -> arkret_core::DidOperationSubmitRequestBody {
        let did = arkret_core::Did::new(format!("did:webvh:z{label}:example.com")).unwrap();
        arkret_core::DidOperationSubmitRequestBody {
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
        let mut rng = ChaChaRng::seed_from_u64(0xacce_5510);
        let label = Uuid::now_v7().simple().to_string();
        let holder_one = "A".repeat(43);
        let holder_two = "B".repeat(43);
        let holder_three = "C".repeat(43);
        let lease_one = "D".repeat(32);
        let lease_two = "E".repeat(32);
        let renewal_lease = "F".repeat(32);
        let lease_three = "G".repeat(32);
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
            arkret_core::ReservedIdentityCreation::from_operation(operation.clone()).unwrap();
        let first_challenge = IdentityBindingChallengeInput {
            request_id: arkret_core::RequestId::new(format!("ak:request:{}", Uuid::now_v7()))
                .unwrap(),
            request_digest: arkret_core::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
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
            trust_domain: arkret_core::TypedTrustDomainId::new("ak:trust_domain:example.net")
                .unwrap(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
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
        repo.save().await.unwrap();

        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        assert!(matches!(
            repo.account_handoff()
                .reserve_and_issue_challenge(first_challenge.clone())
                .await
                .unwrap(),
            IdentityBindingChallengeIssue::Replay(_)
        ));
        let conflicting_replay = IdentityBindingChallengeInput {
            request_digest: arkret_core::Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap(),
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
            request_id: arkret_core::RequestId::new(format!("ak:request:{}", Uuid::now_v7()))
                .unwrap(),
            request_digest: arkret_core::Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
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
}
