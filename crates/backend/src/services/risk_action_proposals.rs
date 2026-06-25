//! Durable storage for risk-action proposals.
//!
//! Persists proposal records to the `risk_action_proposals` table. Approval
//! proofs (admin DID + detached JWS approval proof + recorded-at timestamp)
//! are stored as a JSON array in the `approval_proofs` column. The HTTP
//! handler verifies each JWS against the approver DID before calling this
//! service. High-risk actions require `CokretConfig::high_risk_threshold`
//! distinct admin DIDs to approve before the proposal transitions to
//! `approved`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension as _, QueryableByName};
use diesel::sql_types::{Int4, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid};
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;

pub type RiskActionProposalsServiceHandle = Arc<dyn RiskActionProposalsService>;

/// Lifecycle states for a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalState {
    Draft,
    Approved,
    Executed,
    Cancelled,
    Rejected,
}

impl ProposalState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Approved => "approved",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(Self::Draft),
            "approved" => Some(Self::Approved),
            "executed" => Some(Self::Executed),
            "cancelled" => Some(Self::Cancelled),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalProof {
    /// Admin DID that signed the approval.
    pub admin_did: String,
    /// Detached approval JWS. The admin handler validates it before storage.
    pub signature: String,
    /// Free-form approval note for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When the approval was recorded.
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RiskActionProposalRecord {
    pub id: Ulid,
    pub account_id: Ulid,
    pub action: String,
    pub proposer_did: String,
    pub reason: String,
    pub ticket: Option<String>,
    pub state: ProposalState,
    pub approval_proofs: Vec<ApprovalProof>,
    pub required_approvals: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub executed_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct CreateProposal {
    pub account_id: Ulid,
    pub action: String,
    pub proposer_did: String,
    pub reason: String,
    pub ticket: Option<String>,
    pub required_approvals: u32,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum RiskActionProposalsError {
    #[error("proposal storage failed: {0}")]
    Storage(#[from] anyhow::Error),

    #[error("proposal not found")]
    NotFound,

    #[error("proposal is not in draft state")]
    NotDraft,

    #[error("admin {0} has already approved this proposal")]
    DuplicateApproval(String),

    #[error("proposal not yet approved (got {got}, need {need})")]
    NotApproved { got: u32, need: u32 },

    #[error("proposal already executed")]
    AlreadyExecuted,

    #[error("proposal already cancelled")]
    AlreadyCancelled,
}

#[async_trait]
pub trait RiskActionProposalsService: Send + Sync {
    async fn create(
        &self,
        input: CreateProposal,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError>;

    async fn get(
        &self,
        id: Ulid,
    ) -> Result<Option<RiskActionProposalRecord>, RiskActionProposalsError>;

    async fn list_for_account(
        &self,
        account_id: Ulid,
    ) -> Result<Vec<RiskActionProposalRecord>, RiskActionProposalsError>;

    /// Append an approval. When the resulting count reaches
    /// `required_approvals`, transitions the proposal from `draft` →
    /// `approved` and stamps `approved_at`.
    async fn approve(
        &self,
        id: Ulid,
        proof: ApprovalProof,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError>;

    /// Mark an approved proposal as `executed`. Returns
    /// [`RiskActionProposalsError::NotApproved`] if the proposal has not
    /// reached `approved` yet.
    async fn mark_executed(
        &self,
        id: Ulid,
        executed_at: DateTime<Utc>,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError>;

    async fn cancel(
        &self,
        id: Ulid,
        cancelled_at: DateTime<Utc>,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError>;
}

/// PostgreSQL-backed implementation.
pub struct PgRiskActionProposalsService {
    pool: DieselPool<AsyncPgConnection>,
}

#[derive(Debug, QueryableByName)]
struct ProposalRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = DieselUuid)]
    account_id: Uuid,
    #[diesel(sql_type = Text)]
    action: String,
    #[diesel(sql_type = Text)]
    proposer_did: String,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = Nullable<Text>)]
    ticket: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Jsonb)]
    approval_proofs: Value,
    #[diesel(sql_type = Int4)]
    required_approvals: i32,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    approved_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    executed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    cancelled_at: Option<DateTime<Utc>>,
}

impl ProposalRow {
    fn into_record(self) -> RiskActionProposalRecord {
        let approvals: Vec<ApprovalProof> =
            serde_json::from_value(self.approval_proofs).unwrap_or_default();
        RiskActionProposalRecord {
            id: Ulid::from(self.id),
            account_id: Ulid::from(self.account_id),
            action: self.action,
            proposer_did: self.proposer_did,
            reason: self.reason,
            ticket: self.ticket,
            state: ProposalState::parse(&self.state).unwrap_or(ProposalState::Draft),
            approval_proofs: approvals,
            required_approvals: u32::try_from(self.required_approvals.max(1)).unwrap_or(1),
            created_at: self.created_at,
            updated_at: self.updated_at,
            approved_at: self.approved_at,
            executed_at: self.executed_at,
            cancelled_at: self.cancelled_at,
        }
    }
}

impl PgRiskActionProposalsService {
    fn new(pool: DieselPool<AsyncPgConnection>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RiskActionProposalsService for PgRiskActionProposalsService {
    async fn create(
        &self,
        input: CreateProposal,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError> {
        let id = Uuid::now_v7();
        let required = i32::try_from(input.required_approvals.max(1)).unwrap_or(1);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        let row = diesel::sql_query(
            r"
            INSERT INTO risk_action_proposals (
                id, account_id, action, proposer_did, reason, ticket,
                state, approval_proofs, required_approvals,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', '[]'::jsonb, $7, $8, $8)
            RETURNING
                id, account_id, action, proposer_did, reason, ticket,
                state, approval_proofs, required_approvals,
                created_at, updated_at, approved_at, executed_at, cancelled_at
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<DieselUuid, _>(Uuid::from(input.account_id))
        .bind::<Text, _>(input.action)
        .bind::<Text, _>(input.proposer_did)
        .bind::<Text, _>(input.reason)
        .bind::<Nullable<Text>, _>(input.ticket)
        .bind::<Int4, _>(required)
        .bind::<Timestamptz, _>(input.now)
        .get_result::<ProposalRow>(&mut *conn)
        .await
        .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;

        Ok(row.into_record())
    }

    async fn get(
        &self,
        id: Ulid,
    ) -> Result<Option<RiskActionProposalRecord>, RiskActionProposalsError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        let row = diesel::sql_query(
            r"
            SELECT id, account_id, action, proposer_did, reason, ticket,
                   state, approval_proofs, required_approvals,
                   created_at, updated_at, approved_at, executed_at, cancelled_at
            FROM risk_action_proposals
            WHERE id = $1
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(id))
        .get_results::<ProposalRow>(&mut *conn)
        .await
        .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        Ok(row.into_iter().next().map(ProposalRow::into_record))
    }

    async fn list_for_account(
        &self,
        account_id: Ulid,
    ) -> Result<Vec<RiskActionProposalRecord>, RiskActionProposalsError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        let rows = diesel::sql_query(
            r"
            SELECT id, account_id, action, proposer_did, reason, ticket,
                   state, approval_proofs, required_approvals,
                   created_at, updated_at, approved_at, executed_at, cancelled_at
            FROM risk_action_proposals
            WHERE account_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT 200
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .get_results::<ProposalRow>(&mut *conn)
        .await
        .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        Ok(rows.into_iter().map(ProposalRow::into_record).collect())
    }

    async fn approve(
        &self,
        id: Ulid,
        proof: ApprovalProof,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError> {
        let existing = self
            .get(id)
            .await?
            .ok_or(RiskActionProposalsError::NotFound)?;

        if existing.state != ProposalState::Draft {
            return Err(RiskActionProposalsError::NotDraft);
        }

        if existing
            .approval_proofs
            .iter()
            .any(|p| p.admin_did == proof.admin_did)
        {
            return Err(RiskActionProposalsError::DuplicateApproval(proof.admin_did));
        }

        let mut proofs = existing.approval_proofs.clone();
        proofs.push(proof.clone());
        let new_state = if proofs.len() as u32 >= existing.required_approvals {
            ProposalState::Approved
        } else {
            ProposalState::Draft
        };
        let approved_at = if new_state == ProposalState::Approved {
            Some(proof.recorded_at)
        } else {
            None
        };
        let proofs_json = serde_json::to_value(&proofs)
            .map_err(|e| RiskActionProposalsError::Storage(e.into()))?;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        let row = diesel::sql_query(
            r"
            UPDATE risk_action_proposals
            SET approval_proofs = $2,
                state = $3,
                approved_at = COALESCE(approved_at, $4),
                updated_at = $5
            WHERE id = $1
            RETURNING
                id, account_id, action, proposer_did, reason, ticket,
                state, approval_proofs, required_approvals,
                created_at, updated_at, approved_at, executed_at, cancelled_at
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(id))
        .bind::<Jsonb, _>(proofs_json)
        .bind::<Text, _>(new_state.as_str())
        .bind::<Nullable<Timestamptz>, _>(approved_at)
        .bind::<Timestamptz, _>(proof.recorded_at)
        .get_result::<ProposalRow>(&mut *conn)
        .await
        .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        Ok(row.into_record())
    }

    async fn mark_executed(
        &self,
        id: Ulid,
        executed_at: DateTime<Utc>,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;

        // Atomic compare-and-set: only the `approved` row transitions to
        // `executed`, and PostgreSQL serialises concurrent UPDATEs on the same
        // row. Exactly one of N concurrent callers carrying the same approved
        // proposal observes `state = 'approved'` and gets the RETURNING row;
        // the others match zero rows. This closes the execute-then-mark TOCTOU
        // (CKP-0007 P2B.5: an N-of-M approved proposal MUST be consumed once).
        let updated = diesel::sql_query(
            r"
            UPDATE risk_action_proposals
            SET state = 'executed',
                executed_at = $2,
                updated_at = $2
            WHERE id = $1 AND state = 'approved'
            RETURNING
                id, account_id, action, proposer_did, reason, ticket,
                state, approval_proofs, required_approvals,
                created_at, updated_at, approved_at, executed_at, cancelled_at
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(id))
        .bind::<Timestamptz, _>(executed_at)
        .get_result::<ProposalRow>(&mut *conn)
        .await
        .optional()
        .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;

        if let Some(row) = updated {
            return Ok(row.into_record());
        }

        // Lost the race (or never eligible). Re-read the committed row to
        // report the precise reason instead of a generic failure.
        let existing = self
            .get(id)
            .await?
            .ok_or(RiskActionProposalsError::NotFound)?;
        match existing.state {
            ProposalState::Executed => Err(RiskActionProposalsError::AlreadyExecuted),
            ProposalState::Cancelled | ProposalState::Rejected => {
                Err(RiskActionProposalsError::AlreadyCancelled)
            }
            ProposalState::Draft => Err(RiskActionProposalsError::NotApproved {
                got: existing.approval_proofs.len() as u32,
                need: existing.required_approvals,
            }),
            // Still `approved` yet our conditional UPDATE matched nothing: the
            // row must have flipped to a non-approved state between the UPDATE
            // and this re-read (another executor won). Treat as already
            // executed — never run the mutation twice.
            ProposalState::Approved => Err(RiskActionProposalsError::AlreadyExecuted),
        }
    }

    async fn cancel(
        &self,
        id: Ulid,
        cancelled_at: DateTime<Utc>,
    ) -> Result<RiskActionProposalRecord, RiskActionProposalsError> {
        let existing = self
            .get(id)
            .await?
            .ok_or(RiskActionProposalsError::NotFound)?;
        if existing.state == ProposalState::Executed {
            return Err(RiskActionProposalsError::AlreadyExecuted);
        }
        if matches!(
            existing.state,
            ProposalState::Cancelled | ProposalState::Rejected
        ) {
            return Err(RiskActionProposalsError::AlreadyCancelled);
        }

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        let row = diesel::sql_query(
            r"
            UPDATE risk_action_proposals
            SET state = 'cancelled',
                cancelled_at = $2,
                updated_at = $2
            WHERE id = $1
            RETURNING
                id, account_id, action, proposer_did, reason, ticket,
                state, approval_proofs, required_approvals,
                created_at, updated_at, approved_at, executed_at, cancelled_at
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(id))
        .bind::<Timestamptz, _>(cancelled_at)
        .get_result::<ProposalRow>(&mut *conn)
        .await
        .map_err(|e| RiskActionProposalsError::Storage(anyhow::anyhow!(e)))?;
        Ok(row.into_record())
    }
}

/// Builds a Pg-backed proposals service.
#[must_use]
pub fn risk_action_proposals_service(
    pool: DieselPool<AsyncPgConnection>,
) -> RiskActionProposalsServiceHandle {
    Arc::new(PgRiskActionProposalsService::new(pool))
}

/// Returns whether `action` is considered "high-risk" — i.e. requires the
/// configured high-risk threshold of admin approvals.
#[must_use]
pub fn is_high_risk_action(action: &str) -> bool {
    matches!(action, "disable" | "erase" | "reset_recovery")
}

/// Compute the required-approvals count for an action given the
/// deployment's high-risk threshold. Low-risk actions need exactly 1
/// approval (the proposer's own).
#[must_use]
pub fn required_approvals_for(action: &str, high_risk_threshold: u32) -> u32 {
    if is_high_risk_action(action) {
        high_risk_threshold.max(1)
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_risk_actions_are_classified_correctly() {
        assert!(is_high_risk_action("disable"));
        assert!(is_high_risk_action("erase"));
        assert!(is_high_risk_action("reset_recovery"));
        assert!(!is_high_risk_action("lock"));
        assert!(!is_high_risk_action("unknown"));
    }

    #[test]
    fn required_approvals_uses_threshold_for_high_risk() {
        assert_eq!(required_approvals_for("disable", 2), 2);
        assert_eq!(required_approvals_for("erase", 3), 3);
        assert_eq!(required_approvals_for("lock", 5), 1);
        // Threshold of 0 is clamped to 1
        assert_eq!(required_approvals_for("disable", 0), 1);
    }

    #[test]
    fn proposal_state_round_trips() {
        for s in [
            ProposalState::Draft,
            ProposalState::Approved,
            ProposalState::Executed,
            ProposalState::Cancelled,
            ProposalState::Rejected,
        ] {
            assert_eq!(ProposalState::parse(s.as_str()), Some(s));
        }
        assert_eq!(ProposalState::parse("garbage"), None);
    }
}
