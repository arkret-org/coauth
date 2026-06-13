//! Circle capability grant repository.

use async_trait::async_trait;
use coauth_data::Clock;
use coauth_data::circle_capability::{CircleCapabilityAction, CircleCapabilityGrant};
use rand_core::RngCore;

use crate::repository_impl;

/// Parameters used to create a durable Circle capability grant.
#[derive(Debug, Clone)]
pub struct NewCircleCapabilityGrant {
    /// Subject (account or DID) that receives the grant.
    pub subject: String,
    /// Realm the grant is scoped to.
    pub realm_id: String,
    /// Capability action authorized by this grant.
    pub action: CircleCapabilityAction,
    /// Canonical sorted/deduplicated Circle IDs allowed by the grant.
    pub allowed_circle_ids: Vec<String>,
    /// Admin/service actor that created the grant.
    pub granted_by: String,
}

/// Repository for durable Circle capability grants.
#[async_trait]
pub trait CircleCapabilityGrantRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Insert a new active grant.
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewCircleCapabilityGrant,
    ) -> Result<CircleCapabilityGrant, Self::Error>;

    /// List all non-revoked grants.
    async fn list_active(&mut self) -> Result<Vec<CircleCapabilityGrant>, Self::Error>;

    /// Revoke an active grant by row id. Returns `None` when the grant is
    /// absent or already revoked.
    async fn revoke_by_id(
        &mut self,
        clock: &dyn Clock,
        grant_id: &str,
    ) -> Result<Option<CircleCapabilityGrant>, Self::Error>;
}

repository_impl!(CircleCapabilityGrantRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewCircleCapabilityGrant,
    ) -> Result<CircleCapabilityGrant, Self::Error>;
    async fn list_active(&mut self) -> Result<Vec<CircleCapabilityGrant>, Self::Error>;
    async fn revoke_by_id(
        &mut self,
        clock: &dyn Clock,
        grant_id: &str,
    ) -> Result<Option<CircleCapabilityGrant>, Self::Error>;
);
