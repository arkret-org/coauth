//! Read-only access to the retained collaboration capability review records.
//!
//! These local records are not accepted Realm authorization evidence. New
//! grants and revocations must use principal-signed protocol Events.

use coauth_data::collaboration_capability::CollaborationCapabilityGrant;

use crate::repository_impl;

repository_impl! {
    /// Read-only repository for local collaboration capability review records.
    pub trait CollaborationCapabilityGrantRepository {
        /// Backend error type.
        type Error;

        /// List all non-revoked local review records.
        async fn list_active(&mut self) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error>;
    }
}
