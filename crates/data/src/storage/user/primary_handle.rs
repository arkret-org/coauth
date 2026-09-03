//! Versioned holder preference repository for DID `metadata.primary_handle`.

use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, NewUserPrimaryHandlePreference, UserPrimaryHandlePreference, VerifiedUserHandleClaim,
};
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

repository_impl! {
    /// Repository for primary-handle holder preferences.
    pub trait UserPrimaryHandlePreferenceRepository {
        /// Backend error type.
        type Error;

        /// Return the current preference version for a user, if any.
        async fn current(
            &mut self,
            user_id: Ulid,
        ) -> Result<Option<UserPrimaryHandlePreference>, Self::Error>;

        /// Return the preference version that was effective at `as_of`, if any.
        async fn at(
            &mut self,
            user_id: Ulid,
            as_of: DateTime<Utc>,
        ) -> Result<Option<UserPrimaryHandlePreference>, Self::Error>;

        /// Find active verified claim evidence for `handle` owned by `user_id`.
        async fn verified_handle_claim(
            &mut self,
            user_id: Ulid,
            handle: &str,
            as_of: DateTime<Utc>,
        ) -> Result<Option<VerifiedUserHandleClaim>, Self::Error>;

        /// Replace the current preference with a new version.
        async fn set(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            params: NewUserPrimaryHandlePreference,
        ) -> Result<UserPrimaryHandlePreference, Self::Error>;
    }
}
