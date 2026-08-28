//! Accountability grant repository.

use arkret_identifiers::DidCoreId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::Clock;
use rand_core::RngCore;

use crate::accountability::{
    AccountabilityGrant, AccountabilityGrantFanoutState, AccountabilitySubjectKind,
    AccountabilitySubjectRevocation,
};
use crate::repository_impl;

/// Parameters used to create a durable accountability grant.
#[derive(Debug, Clone)]
pub struct NewAccountabilityGrant {
    /// Coauth-local row handle: `ak:local_ref:accountability_grant:<uuid7>`.
    pub accountability_grant_id: String,
    /// Agent principal id covered by this grant.
    pub agent_id: DidCoreId,
    /// Controller DID that accepted accountability for the grant.
    pub controller_id: DidCoreId,
    /// Canonical capability/action set.
    pub capabilities: Vec<String>,
    /// Deterministic digest of controller, agent, and canonical capabilities.
    pub capabilities_digest: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// Grant issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// `sha256:<hex>` digest of the canonical fan-out payload.
    pub raw_payload_digest: String,
    /// Initial soland fan-out state.
    pub soland_fanout_state: AccountabilityGrantFanoutState,
    /// Idempotency key used for soland fan-out and retry jobs.
    pub soland_fanout_idempotency_key: String,
    /// Payload queued for soland fan-out.
    pub soland_fanout_payload: serde_json::Value,
    /// Initial fan-out attempt count.
    pub soland_fanout_attempt: i32,
    /// Next retry timestamp, if a retry is scheduled.
    pub soland_fanout_next_retry_at: Option<DateTime<Utc>>,
    /// Terminal failure reason, if fan-out entered dead-letter state.
    pub soland_fanout_dead_letter_reason: Option<String>,
}

/// Repository for durable accountability grants and their revocation index.
#[async_trait]
pub trait AccountabilityGrantRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Insert a new durable accountability grant.
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountabilityGrant,
    ) -> Result<AccountabilityGrant, Self::Error>;

    /// Look up a grant by its wire typed id.
    async fn lookup_by_grant_id(
        &mut self,
        accountability_grant_id: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error>;

    /// Find an active grant for the same controller, agent, and capability set.
    async fn find_active_by_fingerprint(
        &mut self,
        agent_id: &DidCoreId,
        controller_id: &DidCoreId,
        capabilities_digest: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error>;

    /// List active grants for a controller DID or agent principal id.
    async fn list_active_for_subject(
        &mut self,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
    ) -> Result<Vec<AccountabilityGrant>, Self::Error>;

    /// Revoke every active grant associated with a controller or agent subject.
    async fn revoke_for_subject(
        &mut self,
        clock: &dyn Clock,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
        reason: &str,
    ) -> Result<usize, Self::Error>;

    /// Record a subject-level revocation marker.
    async fn mark_subject_revoked(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
        reason: &str,
    ) -> Result<AccountabilitySubjectRevocation, Self::Error>;

    /// Return whether a subject has an active revocation marker.
    async fn subject_revoked(
        &mut self,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
    ) -> Result<bool, Self::Error>;
}

repository_impl!(AccountabilityGrantRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountabilityGrant,
    ) -> Result<AccountabilityGrant, Self::Error>;
    async fn lookup_by_grant_id(
        &mut self,
        accountability_grant_id: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error>;
    async fn find_active_by_fingerprint(
        &mut self,
        agent_id: &DidCoreId,
        controller_id: &DidCoreId,
        capabilities_digest: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error>;
    async fn list_active_for_subject(
        &mut self,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
    ) -> Result<Vec<AccountabilityGrant>, Self::Error>;
    async fn revoke_for_subject(
        &mut self,
        clock: &dyn Clock,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
        reason: &str,
    ) -> Result<usize, Self::Error>;
    async fn mark_subject_revoked(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
        reason: &str,
    ) -> Result<AccountabilitySubjectRevocation, Self::Error>;
    async fn subject_revoked(
        &mut self,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &DidCoreId,
    ) -> Result<bool, Self::Error>;
);
