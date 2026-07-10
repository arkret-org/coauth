//! Collaboration capability grant repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::Clock;
use coauth_data::collaboration_capability::{
    CollaborationCapabilityAction, CollaborationCapabilityGrant,
};
use rand_core::RngCore;

use crate::repository_impl;

/// Parameters used to create a durable collaboration capability grant.
#[derive(Debug, Clone)]
pub struct NewCollaborationCapabilityGrant {
    /// Standard protocol grant id that soland will materialize.
    pub capability_grant_id: String,
    /// Standard `ak.capability.grant` event id for reducer ingestion.
    pub grant_event_id: String,
    /// Subject (account or DID) that receives the grant.
    pub subject: String,
    /// Realm the grant is scoped to.
    pub realm_id: String,
    /// Capability action authorized by this grant.
    pub action: CollaborationCapabilityAction,
    /// Optional expiry. Required by validation for high-risk actions.
    pub expires_at: Option<DateTime<Utc>>,
    /// Approval evidence binding for high-risk actions.
    pub approval_evidence_ref: Option<String>,
    /// Admin/service actor that created the grant.
    pub granted_by: String,
    /// Canonical digest of the queued fan-out payload.
    pub grant_raw_payload_digest: String,
    /// Idempotency key used for soland fan-out.
    pub grant_fanout_idempotency_key: String,
}

/// Parameters recorded when revocation queues a standard revoke event.
#[derive(Debug, Clone)]
pub struct CollaborationCapabilityRevokeFanout {
    /// Standard `ak.capability.revoke` event id.
    pub revoke_event_id: String,
}

/// Repository for durable collaboration capability grants.
#[async_trait]
pub trait CollaborationCapabilityGrantRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Insert a new non-revoked grant.
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewCollaborationCapabilityGrant,
    ) -> Result<CollaborationCapabilityGrant, Self::Error>;

    /// List all non-revoked grants.
    async fn list_active(&mut self) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error>;

    /// List non-revoked grants for an exact subject/realm/action triple.
    async fn list_active_for_subject_action(
        &mut self,
        subject: &str,
        realm_id: &str,
        action: CollaborationCapabilityAction,
    ) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error>;

    /// Revoke an active grant by row id. Returns `None` when the grant is
    /// absent or already revoked.
    async fn revoke_by_id(
        &mut self,
        clock: &dyn Clock,
        grant_id: &str,
        fanout: CollaborationCapabilityRevokeFanout,
    ) -> Result<Option<CollaborationCapabilityGrant>, Self::Error>;
}

repository_impl!(CollaborationCapabilityGrantRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewCollaborationCapabilityGrant,
    ) -> Result<CollaborationCapabilityGrant, Self::Error>;
    async fn list_active(&mut self) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error>;
    async fn list_active_for_subject_action(
        &mut self,
        subject: &str,
        realm_id: &str,
        action: CollaborationCapabilityAction,
    ) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error>;
    async fn revoke_by_id(
        &mut self,
        clock: &dyn Clock,
        grant_id: &str,
        fanout: CollaborationCapabilityRevokeFanout,
    ) -> Result<Option<CollaborationCapabilityGrant>, Self::Error>;
);
