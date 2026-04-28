use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

pub use crate::{pg::policy_data::PgPolicyDataRepository, storage::policy_data::*};

/// A versioned snapshot of policy configuration stored as free-form JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyData {
    /// Unique identifier for this policy data revision.
    pub id: Ulid,
    /// When this revision was persisted.
    pub created_at: DateTime<Utc>,
    /// Arbitrary policy payload consumed by the policy engine.
    pub data: serde_json::Value,
}
