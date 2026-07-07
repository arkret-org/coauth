use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub use crate::pg::policy_data::PgPolicyDataRepository;
pub use crate::storage::policy_data::*;

/// Dynamic policy payload consumed by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(transparent)]
pub struct PolicyDataDocument(serde_json::Value);

impl PolicyDataDocument {
    /// Create a document from parsed JSON.
    #[must_use]
    pub fn from_json(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Borrow the parsed JSON for evaluators that need dynamic lookup.
    #[must_use]
    pub fn as_json(&self) -> &serde_json::Value {
        &self.0
    }

    /// Consume the document back into parsed JSON.
    #[must_use]
    pub fn into_json(self) -> serde_json::Value {
        self.0
    }
}

impl From<serde_json::Value> for PolicyDataDocument {
    fn from(value: serde_json::Value) -> Self {
        Self::from_json(value)
    }
}

impl AsRef<serde_json::Value> for PolicyDataDocument {
    fn as_ref(&self) -> &serde_json::Value {
        self.as_json()
    }
}

/// A versioned snapshot of policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyData {
    /// Unique identifier for this policy data revision.
    pub id: Ulid,
    /// When this revision was persisted.
    pub created_at: DateTime<Utc>,
    /// Policy payload consumed by the policy engine.
    pub data: PolicyDataDocument,
}
