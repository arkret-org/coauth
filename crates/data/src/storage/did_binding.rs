//! Durable accepted-DID-binding repository
//! (`did-usage-and-verification.md` §5).
//!
//! # Why this port speaks in columns, not in SDK types
//!
//! The value that is persisted is an `arkret_identity::AcceptedDidBinding`
//! (a verified binding **plus** the DID document it pins). That type lives in
//! `arkret-identity`, which this crate deliberately does not depend on: the
//! data layer is a persistence port, and the *validating* decode — recomputing
//! the pinned document's canonical digest and rejecting a row whose document
//! was edited after it was written — belongs on the service side, next to the
//! acceptance logic it protects.
//!
//! So the row carries the acceptance as opaque JSON plus the columns the store
//! actually has to filter on:
//!
//! | column group | why it is a column and not just JSON |
//! | --- | --- |
//! | the five [`VerifiedDidBindingKeyColumns`] dimensions | they are the store key; §5 requires exact lookup and exact invalidation along each of them |
//! | `history_head` | §5 invalidation dimension (witness fork), not a key dimension |
//! | `expires_at` | hard expiry must be enforced **in the query**, so an expired row is never handed to a caller |
//!
//! # Absent key dimensions
//!
//! `verification_method` is an optional dimension of the store key, but a
//! PostgreSQL primary key cannot contain `NULL`. The backend stores it as the
//! empty string when absent; a DID URL can never be empty, so the encoding is
//! unambiguous. That translation is the storage backend's job — this port keeps
//! it as an `Option<String>`.
//!
//! `version_id` is deliberately **not** here. §5.2 makes it a product of the
//! resolution, so a caller cannot know it before looking the entry up; keying on
//! it made every lookup miss and filed every rotation as a parallel row nobody
//! could reach. It stays a binding field inside the payload.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::repository_impl;

/// The six-dimension accepted-binding store key
/// (`did-usage-and-verification.md` §5).
///
/// Mirrors `arkret_identity::VerifiedDidBindingKey` field for field. Exact
/// invalidation along any one of these dimensions is a hard requirement, which
/// is why all six are columns.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifiedDidBindingKeyColumns {
    /// The bound DID.
    pub did: String,
    /// The local trust domain the acceptance was made in.
    pub trust_domain: String,
    /// Closed acceptance purpose token.
    pub purpose: String,
    /// Resolver / Realm policy digest in force at acceptance time.
    pub policy_digest: String,
    /// The concrete verification method the acceptance pins, when it pins one.
    pub verification_method: Option<String>,
}

/// One durable acceptance row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDidBindingRow {
    /// Store key.
    pub key: VerifiedDidBindingKeyColumns,
    /// Pinned history head, when the method publishes one. Invalidation
    /// dimension only.
    pub history_head: Option<String>,
    /// Hard expiry. `None` means the acceptance never hard-expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// The serialized `AcceptedDidBinding`. Opaque to this layer.
    pub accepted: Value,
}

/// Conjunctive invalidation selector, mirroring
/// `arkret_identity::BindingInvalidation`.
///
/// Every populated dimension is an **AND** constraint, and an entirely empty
/// selector matches nothing. That is what stops "rotate this key" from
/// degenerating into "wipe the table": there is deliberately no catch-all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedDidBindingInvalidation {
    /// Match the bound DID.
    pub did: Option<String>,
    /// Match the pinned verification method (key rotation).
    pub verification_method: Option<String>,
    /// Match the pinned history head (witness fork).
    pub history_head: Option<String>,
    /// Match the local trust domain.
    pub trust_domain: Option<String>,
    /// Match the acceptance purpose.
    pub purpose: Option<String>,
    /// Match the resolver / Realm policy digest (policy revision).
    pub policy_digest: Option<String>,
}

impl VerifiedDidBindingInvalidation {
    /// Whether no dimension is constrained. An unconstrained selector matches
    /// nothing and MUST delete nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.did.is_none()
            && self.verification_method.is_none()
            && self.history_head.is_none()
            && self.trust_domain.is_none()
            && self.purpose.is_none()
            && self.policy_digest.is_none()
    }
}

repository_impl! {
    /// Repository for durable accepted DID bindings.
    pub trait VerifiedDidBindingRepository {
        /// Backend error type.
        type Error;

        /// Look up one acceptance, honouring hard expiry.
        ///
        /// A row whose `expires_at` has passed MUST NOT be returned: hard-expired
        /// acceptances stop existing for readers (`did-usage-and-verification.md`
        /// §5), independently of when the row is physically removed.
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails.
        async fn get(
            &mut self,
            key: &VerifiedDidBindingKeyColumns,
            now: DateTime<Utc>,
        ) -> Result<Option<VerifiedDidBindingRow>, Self::Error>;

        /// Insert or replace one acceptance, and opportunistically drop rows that
        /// are already hard-expired at `now`.
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails.
        async fn upsert(
            &mut self,
            row: VerifiedDidBindingRow,
            now: DateTime<Utc>,
        ) -> Result<(), Self::Error>;

        /// Delete the one row filed under `key`; returns whether it existed.
        ///
        /// This is intentionally distinct from [`Self::invalidate`]. A current
        /// admission rule may reject one historical row whose optional
        /// `verification_method` dimension is absent. The invalidation selector
        /// uses `None` to mean "unconstrained", so it cannot express that exact
        /// key without over-deleting sibling rows.
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails.
        async fn delete_exact(
            &mut self,
            key: &VerifiedDidBindingKeyColumns,
        ) -> Result<bool, Self::Error>;

        /// Delete every acceptance matching `selector`; returns the number removed.
        /// An empty selector removes nothing and returns `0`.
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails.
        async fn invalidate(
            &mut self,
            selector: &VerifiedDidBindingInvalidation,
        ) -> Result<usize, Self::Error>;

        /// Remove every hard-expired row; returns the number removed.
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails.
        async fn prune_expired(&mut self, now: DateTime<Utc>) -> Result<usize, Self::Error>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconstrained_selector_matches_nothing() {
        assert!(VerifiedDidBindingInvalidation::default().is_empty());
    }

    #[test]
    fn any_single_dimension_makes_the_selector_non_empty() {
        let dimensions: [fn(&mut VerifiedDidBindingInvalidation); 6] = [
            |selector| selector.did = Some("did:web:alice.example".to_owned()),
            |selector| selector.verification_method = Some("did:web:a.example#k".to_owned()),
            |selector| selector.history_head = Some("sha256:aa".to_owned()),
            |selector| selector.trust_domain = Some("ak:trust_domain:x".to_owned()),
            |selector| selector.purpose = Some("principal".to_owned()),
            |selector| selector.policy_digest = Some("sha256:bb".to_owned()),
        ];
        for set in dimensions {
            let mut selector = VerifiedDidBindingInvalidation::default();
            set(&mut selector);
            assert!(!selector.is_empty());
        }
    }
}
