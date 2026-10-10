//! Deployment-local Station trust enrollment persistence.
//!
//! These records are deployment control-plane state, not Arkret wire types:
//! they persist the Station identity established by full method-native
//! verification for a canonical endpoint, plus the WebVH anti-rollback floor.
//! Public `/_arkret/describe` metadata or a shared secret alone can never
//! create or replace them.

use chrono::{DateTime, Utc};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

/// Where a trust enrollment record came from. Stored as `snake_case` text;
/// the database constrains the same set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StationTrustSource {
    /// Initial or continuity-preserving automatic method-native verification.
    AutomaticVerified,
    /// Explicit high-risk operator replacement of the service identity.
    OperatorReplacement,
}

impl StationTrustSource {
    /// The stored text form of the source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomaticVerified => "automatic_verified",
            Self::OperatorReplacement => "operator_replacement",
        }
    }

    /// Parse the stored text form back into the enum.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "automatic_verified" => Some(Self::AutomaticVerified),
            "operator_replacement" => Some(Self::OperatorReplacement),
            _ => None,
        }
    }
}

/// Audit trail action for the trust enrollment log. Stored as `snake_case`
/// text; the database constrains the same set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StationTrustAuditAction {
    /// A new enrollment pin was accepted and persisted.
    Enrolled,
    /// An enrollment or re-verification attempt failed validation.
    VerificationFailed,
    /// An existing pin was explicitly replaced via expected-old CAS.
    Replaced,
    /// The same service identity proved continuity at a new endpoint.
    EndpointRelocated,
    /// An enrollment pin was explicitly revoked.
    Revoked,
}

impl StationTrustAuditAction {
    /// The stored text form of the action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enrolled => "enrolled",
            Self::VerificationFailed => "verification_failed",
            Self::Replaced => "replaced",
            Self::EndpointRelocated => "endpoint_relocated",
            Self::Revoked => "revoked",
        }
    }

    /// Parse the stored text form back into the enum.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "enrolled" => Some(Self::Enrolled),
            "verification_failed" => Some(Self::VerificationFailed),
            "replaced" => Some(Self::Replaced),
            "endpoint_relocated" => Some(Self::EndpointRelocated),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A persisted Station trust enrollment.
#[derive(Debug, Clone)]
pub struct StationTrustEnrollment {
    /// Operator-facing unique name (matches `stations[].name`).
    pub name: String,
    /// Canonicalized endpoint URL; unique across enrollments.
    pub canonical_endpoint: String,
    /// Accepted stable service core id (the authorization pin).
    pub service_id: arkret_identifiers::DidCoreId,
    /// Service DID verified during enrollment.
    pub did: arkret_identifiers::Did,
    /// Verified WebVH method-history head (anti-rollback floor).
    pub method_history_head: String,
    /// Verified WebVH version id (anti-rollback floor).
    pub version_id: String,
    /// Where this enrollment came from.
    pub source: StationTrustSource,
    /// When the pin was first accepted.
    pub enrolled_at: DateTime<Utc>,
    /// When the pinned identity was last verified online.
    pub last_verified_at: DateTime<Utc>,
}

/// Parameters used to insert a new [`StationTrustEnrollment`].
#[derive(Debug, Clone)]
pub struct NewStationTrustEnrollment {
    /// Operator-facing unique name (matches `stations[].name`).
    pub name: String,
    /// Canonicalized endpoint URL; unique across enrollments.
    pub canonical_endpoint: String,
    /// Accepted stable service core id (the authorization pin).
    pub service_id: arkret_identifiers::DidCoreId,
    /// Service DID verified during enrollment.
    pub did: arkret_identifiers::Did,
    /// Verified WebVH method-history head (anti-rollback floor).
    pub method_history_head: String,
    /// Verified WebVH version id (anti-rollback floor).
    pub version_id: String,
    /// Where this enrollment came from.
    pub source: StationTrustSource,
}

/// Parameters used to append a [`StationTrustAudit`] entry.
#[derive(Debug, Clone)]
pub struct NewStationTrustAudit {
    /// Operator-facing enrollment name the entry refers to.
    pub enrollment_name: String,
    /// What happened.
    pub action: StationTrustAuditAction,
    /// Newly observed or accepted service core id, when applicable.
    pub service_id: Option<arkret_identifiers::DidCoreId>,
    /// Previously pinned service core id, for replacements.
    pub previous_service_id: Option<arkret_identifiers::DidCoreId>,
    /// Bounded human-readable diagnostic. Never carries bearer tokens,
    /// private keys, or raw evidence payloads.
    pub detail: String,
}

/// A persisted trust audit entry.
#[derive(Debug, Clone)]
pub struct StationTrustAudit {
    /// Audit entry id.
    pub id: Ulid,
    /// Operator-facing enrollment name the entry refers to.
    pub enrollment_name: String,
    /// What happened.
    pub action: StationTrustAuditAction,
    /// Newly observed or accepted service core id, when applicable.
    pub service_id: Option<arkret_identifiers::DidCoreId>,
    /// Previously pinned service core id, for replacements.
    pub previous_service_id: Option<arkret_identifiers::DidCoreId>,
    /// Bounded human-readable diagnostic.
    pub detail: String,
    /// When the entry was recorded.
    pub created_at: DateTime<Utc>,
}

repository_impl! {
    /// Repository accessor for Station trust enrollments and their
    /// append-only audit log.
    pub trait StationTrustRepository {
        /// Backend error type.
        type Error;

        /// Look up the enrollment for a canonical endpoint.
        async fn find_by_endpoint(
            &mut self,
            canonical_endpoint: &str,
        ) -> Result<Option<StationTrustEnrollment>, Self::Error>;

        /// Look up an enrollment by its operator-facing name.
        async fn find_by_name(
            &mut self,
            name: &str,
        ) -> Result<Option<StationTrustEnrollment>, Self::Error>;

        /// Insert a new enrollment without overwriting either unique key.
        /// Returns `None` when a concurrent insert won the name or endpoint;
        /// callers must re-read and compare the complete verified tuple.
        async fn enroll(
            &mut self,
            clock: &dyn Clock,
            params: NewStationTrustEnrollment,
        ) -> Result<Option<StationTrustEnrollment>, Self::Error>;

        /// Move a verified binding to a new endpoint while preserving the
        /// service core. The update is a CAS over the old endpoint and history
        /// head so concurrent revalidation cannot overwrite newer state.
        async fn relocate_verified(
            &mut self,
            clock: &dyn Clock,
            name: &str,
            expected_service_id: &arkret_identifiers::DidCoreId,
            expected_canonical_endpoint: &str,
            expected_method_history_head: &str,
            params: NewStationTrustEnrollment,
        ) -> Result<bool, Self::Error>;

        /// Compare-and-swap replacement of an existing enrollment: the update
        /// only applies when the stored `service_id` still equals
        /// `expected_old_service_id`. Returns `false` when the expectation did
        /// not match (concurrent replacement or drift).
        async fn replace(
            &mut self,
            clock: &dyn Clock,
            name: &str,
            expected_old_service_id: &arkret_identifiers::DidCoreId,
            params: NewStationTrustEnrollment,
        ) -> Result<bool, Self::Error>;

        /// Advance the anti-rollback floor and `last_verified_at` after a
        /// successful online re-verification of the pinned identity. The
        /// update is a CAS over name, endpoint and old history head.
        #[expect(
            clippy::too_many_arguments,
            reason = "Keep the expected enrollment identity and new verified anti-rollback floor explicit in this compare-and-swap contract."
        )]
        async fn record_verification(
            &mut self,
            clock: &dyn Clock,
            name: &str,
            canonical_endpoint: &str,
            expected_method_history_head: &str,
            did: &arkret_identifiers::Did,
            method_history_head: &str,
            version_id: &str,
        ) -> Result<bool, Self::Error>;

        /// Delete an enrollment (explicit operator revocation). Returns `false`
        /// when no enrollment with that name exists.
        async fn revoke(&mut self, name: &str) -> Result<bool, Self::Error>;

        /// Append an audit entry. There is no update or delete by design.
        async fn record_audit(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            params: NewStationTrustAudit,
        ) -> Result<StationTrustAudit, Self::Error>;

        /// List audit entries for one enrollment, newest first.
        async fn list_audits(
            &mut self,
            enrollment_name: &str,
            limit: usize,
        ) -> Result<Vec<StationTrustAudit>, Self::Error>;
    }
}

#[cfg(test)]
mod tests {
    use super::StationTrustSource;

    #[test]
    fn station_trust_source_is_closed() {
        assert_eq!(
            StationTrustSource::from_stored("automatic_verified"),
            Some(StationTrustSource::AutomaticVerified)
        );
        assert_eq!(
            StationTrustSource::from_stored("operator_replacement"),
            Some(StationTrustSource::OperatorReplacement)
        );
        assert_eq!(StationTrustSource::from_stored("unknown"), None);
    }
}
