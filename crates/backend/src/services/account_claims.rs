use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::QueryableByName;
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid};
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;

pub type AccountClaimsServiceHandle = Arc<dyn AccountClaimsService>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountClaimStatus {
    Active,
    Revoked,
    Expired,
}

impl AccountClaimStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountClaimRecord {
    pub id: Ulid,
    pub account_id: Option<Ulid>,
    pub claim_kind: String,
    pub subject: String,
    pub issuer: String,
    pub verifier_did: String,
    pub represented_organization: String,
    /// Verifier-owned claim document. `claim_kind` selects the verifier and
    /// its registered schema; lifecycle `status` does not select this shape.
    pub payload: Value,
    pub status: AccountClaimStatus,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IssueAccountClaim {
    pub account_id: Option<Ulid>,
    pub claim_kind: String,
    pub subject: String,
    pub issuer: String,
    pub verifier_did: String,
    pub represented_organization: String,
    /// Claim document already validated by the verifier selected by
    /// `claim_kind`; it is an open verifier boundary, not lifecycle data.
    pub payload: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default)]
pub struct AccountClaimFilter {
    pub account_id: Option<Ulid>,
    pub subject: Option<String>,
    pub claim_kind: Option<String>,
    pub status: Option<AccountClaimStatus>,
    pub limit: Option<i64>,
}

impl AccountClaimFilter {
    #[must_use]
    pub fn for_account(account_id: Ulid) -> Self {
        Self {
            account_id: Some(account_id),
            limit: Some(100),
            ..Self::default()
        }
    }
}

#[derive(Debug, Error)]
pub enum AccountClaimsError {
    #[error("account claim storage failed: {0}")]
    Storage(#[from] anyhow::Error),
}

#[async_trait]
pub trait AccountClaimsService: Send + Sync {
    async fn issue(
        &self,
        input: IssueAccountClaim,
    ) -> Result<AccountClaimRecord, AccountClaimsError>;

    async fn list(
        &self,
        filter: AccountClaimFilter,
        now: DateTime<Utc>,
    ) -> Result<Vec<AccountClaimRecord>, AccountClaimsError>;

    async fn revoke(
        &self,
        id: Ulid,
        reason: String,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<AccountClaimRecord>, AccountClaimsError>;
}

pub struct PgAccountClaimsService {
    pool: DieselPool<AsyncPgConnection>,
}

#[derive(Debug, QueryableByName)]
struct AccountClaimRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = Nullable<DieselUuid>)]
    account_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    claim_kind: String,
    #[diesel(sql_type = Text)]
    subject: String,
    #[diesel(sql_type = Text)]
    issuer: String,
    #[diesel(sql_type = Text)]
    verifier_did: String,
    #[diesel(sql_type = Text)]
    represented_organization: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    revoked_reason: Option<String>,
}

impl AccountClaimRow {
    fn into_record(self, now: DateTime<Utc>) -> AccountClaimRecord {
        let status = if self.revoked_at.is_some() {
            AccountClaimStatus::Revoked
        } else if self.expires_at.is_some_and(|expires_at| expires_at <= now) {
            AccountClaimStatus::Expired
        } else {
            AccountClaimStatus::Active
        };

        AccountClaimRecord {
            id: Ulid::from(self.id),
            account_id: self.account_id.map(Ulid::from),
            claim_kind: self.claim_kind,
            subject: self.subject,
            issuer: self.issuer,
            verifier_did: self.verifier_did,
            represented_organization: self.represented_organization,
            payload: self.payload,
            status,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            revoked_reason: self.revoked_reason,
        }
    }
}

#[async_trait]
impl AccountClaimsService for PgAccountClaimsService {
    async fn issue(
        &self,
        input: IssueAccountClaim,
    ) -> Result<AccountClaimRecord, AccountClaimsError> {
        self.issue_inner(input)
            .await
            .map_err(AccountClaimsError::from)
    }

    async fn list(
        &self,
        filter: AccountClaimFilter,
        now: DateTime<Utc>,
    ) -> Result<Vec<AccountClaimRecord>, AccountClaimsError> {
        self.list_inner(filter, now)
            .await
            .map_err(AccountClaimsError::from)
    }

    async fn revoke(
        &self,
        id: Ulid,
        reason: String,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<AccountClaimRecord>, AccountClaimsError> {
        self.revoke_inner(id, reason, revoked_at)
            .await
            .map_err(AccountClaimsError::from)
    }
}

impl PgAccountClaimsService {
    fn new(pool: DieselPool<AsyncPgConnection>) -> Self {
        Self { pool }
    }

    async fn issue_inner(&self, input: IssueAccountClaim) -> anyhow::Result<AccountClaimRecord> {
        let id = Uuid::now_v7();
        let account_id = input.account_id.map(Uuid::from);
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            INSERT INTO account_claims (
                id,
                account_id,
                claim_kind,
                subject,
                issuer,
                verifier_did,
                represented_organization,
                payload,
                issued_at,
                expires_at,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $9, $9)
            RETURNING
                id,
                account_id,
                claim_kind,
                subject,
                issuer,
                verifier_did,
                represented_organization,
                payload,
                issued_at,
                expires_at,
                revoked_at,
                revoked_reason
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<Nullable<DieselUuid>, _>(account_id)
        .bind::<Text, _>(input.claim_kind)
        .bind::<Text, _>(input.subject)
        .bind::<Text, _>(input.issuer)
        .bind::<Text, _>(input.verifier_did)
        .bind::<Text, _>(input.represented_organization)
        .bind::<Jsonb, _>(input.payload)
        .bind::<Timestamptz, _>(input.issued_at)
        .bind::<Nullable<Timestamptz>, _>(input.expires_at)
        .get_results::<AccountClaimRow>(&mut *conn)
        .await?;

        rows.into_iter()
            .next()
            .map(|row| row.into_record(input.issued_at))
            .ok_or_else(|| anyhow::anyhow!("claim insert returned no row"))
    }

    async fn list_inner(
        &self,
        filter: AccountClaimFilter,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Vec<AccountClaimRecord>> {
        let account_id = filter.account_id.map(Uuid::from);
        let status = filter.status.map(|status| status.as_str().to_owned());
        let limit = filter.limit.unwrap_or(100).clamp(1, 1000);
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            SELECT
                id,
                account_id,
                claim_kind,
                subject,
                issuer,
                verifier_did,
                represented_organization,
                payload,
                issued_at,
                expires_at,
                revoked_at,
                revoked_reason
            FROM account_claims
            WHERE ($1::UUID IS NULL OR account_id = $1)
              AND ($2::TEXT IS NULL OR subject = $2)
              AND ($3::TEXT IS NULL OR claim_kind = $3)
              AND (
                    $4::TEXT IS NULL
                    OR ($4 = 'active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $5))
                    OR ($4 = 'revoked' AND revoked_at IS NOT NULL)
                    OR ($4 = 'expired' AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= $5)
              )
            ORDER BY issued_at DESC, id DESC
            LIMIT $6
            ",
        )
        .bind::<Nullable<DieselUuid>, _>(account_id)
        .bind::<Nullable<Text>, _>(filter.subject)
        .bind::<Nullable<Text>, _>(filter.claim_kind)
        .bind::<Nullable<Text>, _>(status)
        .bind::<Timestamptz, _>(now)
        .bind::<BigInt, _>(limit)
        .get_results::<AccountClaimRow>(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(|row| row.into_record(now)).collect())
    }

    async fn revoke_inner(
        &self,
        id: Ulid,
        reason: String,
        revoked_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<AccountClaimRecord>> {
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r"
            UPDATE account_claims
            SET
                revoked_at = COALESCE(revoked_at, $2),
                revoked_reason = COALESCE(revoked_reason, $3),
                updated_at = $2
            WHERE id = $1
            RETURNING
                id,
                account_id,
                claim_kind,
                subject,
                issuer,
                verifier_did,
                represented_organization,
                payload,
                issued_at,
                expires_at,
                revoked_at,
                revoked_reason
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(id))
        .bind::<Timestamptz, _>(revoked_at)
        .bind::<Text, _>(reason)
        .get_results::<AccountClaimRow>(&mut *conn)
        .await?;

        Ok(rows
            .into_iter()
            .next()
            .map(|row| row.into_record(revoked_at)))
    }
}

#[must_use]
pub fn account_claims_service(pool: DieselPool<AsyncPgConnection>) -> AccountClaimsServiceHandle {
    Arc::new(PgAccountClaimsService::new(pool))
}
