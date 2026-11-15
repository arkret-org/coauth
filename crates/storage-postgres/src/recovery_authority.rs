//! PostgreSQL projection of the existing recovery-completion issuer operation.
use async_trait::async_trait;
use coauth_data::recovery_authority::{
    NewRecoveryCompletionGrantIssuance, RecoveryCompletionGrantIssuance,
};
use coauth_data::storage::recovery_authority::RecoveryAuthorityRepository;
use diesel::prelude::*;
use horme::{OptionalExtension, RunQueryDsl};

use crate::schema::recovery_completion_grant_issuances;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL projection of a committed recovery-completion issuer outcome.
pub struct PgRecoveryAuthorityRepository<'c, P = diesel_async::AsyncPgConnection> {
    conn: &'c mut P,
}
impl<'c, P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    PgRecoveryAuthorityRepository<'c, P>
{
    /// Borrow the caller's existing repository transaction.
    pub fn new(conn: &'c mut P) -> Self {
        Self { conn }
    }
}

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = recovery_completion_grant_issuances)]
struct RecoveryCompletionGrantIssuanceRow {
    issuer_id: arkret_identifiers::DidCoreId,
    principal_id: arkret_identifiers::DidCoreId,
    account_station_id: arkret_identifiers::DidCoreId,
    transaction_id: String,
    terminal_receipt_digest: String,
    local_account_id: uuid::Uuid,
    reanchor_ref: serde_json::Value,
    device_authorization_ref: serde_json::Value,
    new_model_generation_ref: i64,
    canonical_request_digest: String,
    canonical_request: Vec<u8>,
    session_grant_operation_id: uuid::Uuid,
    canonical_outcome: Vec<u8>,
    issued_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RecoveryCompletionGrantIssuanceRow> for RecoveryCompletionGrantIssuance {
    type Error = DatabaseInconsistencyError;
    fn try_from(row: RecoveryCompletionGrantIssuanceRow) -> Result<Self, Self::Error> {
        let inconsistent = |column, reason: String| {
            DatabaseInconsistencyError::on("recovery_completion_grant_issuances")
                .column(column)
                .source(std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
        };
        Ok(Self {
            issuer_id: row.issuer_id,
            account_id: arkret_wire::AccountId::new(row.principal_id, row.account_station_id),
            transaction_id: row.transaction_id.parse().map_err(
                |error: arkret_identifiers::IdentifierError| {
                    inconsistent("transaction_id", error.to_string())
                },
            )?,
            terminal_receipt_digest: row.terminal_receipt_digest.parse().map_err(
                |error: arkret_identifiers::IdentifierError| {
                    inconsistent("terminal_receipt_digest", error.to_string())
                },
            )?,
            local_account_id: row.local_account_id.into(),
            reanchor_ref: serde_json::from_value(row.reanchor_ref)
                .map_err(|error| inconsistent("reanchor_ref", error.to_string()))?,
            device_authorization_ref: serde_json::from_value(row.device_authorization_ref)
                .map_err(|error| inconsistent("device_authorization_ref", error.to_string()))?,
            new_model_generation_ref: u64::try_from(row.new_model_generation_ref)
                .map_err(|error| inconsistent("new_model_generation_ref", error.to_string()))?,
            canonical_request_digest: row.canonical_request_digest.parse().map_err(
                |error: arkret_identifiers::IdentifierError| {
                    inconsistent("canonical_request_digest", error.to_string())
                },
            )?,
            canonical_request: row.canonical_request,
            session_grant_operation_id: row.session_grant_operation_id.into(),
            canonical_outcome: row.canonical_outcome,
            issued_at: row.issued_at,
        })
    }
}

#[async_trait]
impl<P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    RecoveryAuthorityRepository for PgRecoveryAuthorityRepository<'_, P>
{
    type Error = DatabaseError;
    async fn lock_completion_business_key(
        &mut self,
        issuer_id: &arkret_identifiers::DidCoreId,
        account_id: &arkret_wire::AccountId,
        transaction_id: &arkret_identifiers::TransactionId,
    ) -> Result<(), Self::Error> {
        let identity = arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "issuer_id": issuer_id,
            "operation": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_RECOVERY_COMPLETION_GRANT_V1,
            "account_id": account_id, "transaction_id": transaction_id,
        }))?;
        let key = crate::advisory_lock::advisory_lock_key(&format!(
            "coauth:recovery-completion:{}",
            arkret_canonical::sha256_digest(identity)
        ));
        diesel::sql_query("SELECT pg_advisory_xact_lock($1), true AS acquired")
            .bind::<diesel::sql_types::BigInt, _>(key)
            .get_result::<crate::advisory_lock::AdvisoryLockResult>(self.conn)
            .await?;
        Ok(())
    }

    #[tracing::instrument(name = "db.recovery_completion.lookup_issuance", skip_all, err)]
    async fn lookup_completion_issuance(
        &mut self,
        issuer_id: &arkret_identifiers::DidCoreId,
        account_id: &arkret_wire::AccountId,
        transaction_id: &arkret_identifiers::TransactionId,
    ) -> Result<Option<RecoveryCompletionGrantIssuance>, Self::Error> {
        recovery_completion_grant_issuances::table
            .filter(recovery_completion_grant_issuances::issuer_id.eq(issuer_id))
            .filter(recovery_completion_grant_issuances::principal_id.eq(&account_id.principal_id))
            .filter(
                recovery_completion_grant_issuances::account_station_id.eq(&account_id.station_id),
            )
            .filter(recovery_completion_grant_issuances::transaction_id.eq(transaction_id.as_str()))
            .select(RecoveryCompletionGrantIssuanceRow::as_select())
            .first::<RecoveryCompletionGrantIssuanceRow>(self.conn)
            .await
            .optional()?
            .map(RecoveryCompletionGrantIssuance::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.recovery_completion.insert_issuance", skip_all, err)]
    async fn insert_completion_issuance(
        &mut self,
        input: NewRecoveryCompletionGrantIssuance,
    ) -> Result<bool, Self::Error> {
        let request: arkret_models_identity::RecoveryCompletionGrantRequestBody =
            serde_json::from_slice(&input.canonical_request)?;
        request
            .validate_structural()
            .map_err(|_| DatabaseError::invalid_operation())?;
        let receipt = &request.terminal_receipt;
        if input.issuer_id != receipt.session_grant_ref.issuer_id
            || input.account_id != receipt.account_id
            || input.transaction_id != receipt.transaction_id
            || input.terminal_receipt_digest
                != receipt
                    .receipt_digest()
                    .map_err(|_| DatabaseError::invalid_operation())?
            || input.canonical_request_digest != request.canonical_request_digest
            || arkret_canonical::canonical_json_bytes(&request)? != input.canonical_request
            || input.new_model_generation_ref != receipt.new_model_generation_ref
            || input.reanchor_ref.event_id != receipt.recovery_unit.events[0].event.event_id
            || input.device_authorization_ref.event_id
                != receipt.recovery_unit.events[1].event.event_id
        {
            return Err(DatabaseError::invalid_operation());
        }
        arkret_wire::validate_recovery_commit_pair(
            &input.reanchor_ref,
            &input.device_authorization_ref,
        )
        .map_err(|_| DatabaseError::invalid_operation())?;
        let outcome: arkret_models_identity::IssueRecoveryCompletionGrantResponseBody =
            serde_json::from_slice(&input.canonical_outcome)?;
        let operation: (
            arkret_identifiers::DidCoreId,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<uuid::Uuid>,
            String,
            String,
        ) = crate::schema::oauth_session_grant_operations::table
            .find(uuid::Uuid::from(input.session_grant_operation_id))
            .select((
                crate::schema::oauth_session_grant_operations::issuer_id,
                crate::schema::oauth_session_grant_operations::canonical_intent,
                crate::schema::oauth_session_grant_operations::canonical_outcome,
                crate::schema::oauth_session_grant_operations::result_grant_id,
                crate::schema::oauth_session_grant_operations::state,
                crate::schema::oauth_session_grant_operations::operation_kind,
            ))
            .first(self.conn)
            .await?;
        if operation.0 != input.issuer_id
            || operation.1.as_deref() != Some(input.canonical_request.as_slice())
            || operation.2.as_deref() != Some(input.canonical_outcome.as_slice())
            || operation.3 != Some(outcome.issued_session.session_grant_id.uuid())
            || operation.4 != "committed"
            || operation.5 != "issue"
            || outcome.transaction_id != input.transaction_id
            || outcome.issued_session.issuer_id != input.issuer_id
            || outcome.issued_session.account_id != input.account_id
            || outcome.issued_at != input.issued_at
            || arkret_canonical::canonical_json_bytes(&outcome)? != input.canonical_outcome
        {
            return Err(DatabaseError::invalid_operation());
        }
        let row = RecoveryCompletionGrantIssuanceRow {
            issuer_id: input.issuer_id,
            principal_id: input.account_id.principal_id,
            account_station_id: input.account_id.station_id,
            transaction_id: input.transaction_id.into_string(),
            terminal_receipt_digest: input.terminal_receipt_digest.to_string(),
            local_account_id: input.local_account_id.into(),
            reanchor_ref: serde_json::to_value(input.reanchor_ref)?,
            device_authorization_ref: serde_json::to_value(input.device_authorization_ref)?,
            new_model_generation_ref: i64::try_from(input.new_model_generation_ref)?,
            canonical_request_digest: input.canonical_request_digest.to_string(),
            canonical_request: input.canonical_request,
            session_grant_operation_id: input.session_grant_operation_id.into(),
            canonical_outcome: input.canonical_outcome,
            issued_at: input.issued_at,
        };
        Ok(
            diesel::insert_into(recovery_completion_grant_issuances::table)
                .values(row)
                .on_conflict_do_nothing()
                .execute(self.conn)
                .await?
                == 1,
        )
    }
}
