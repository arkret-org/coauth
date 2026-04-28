use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthLink {
    pub id: Ulid,
    pub provider_id: Ulid,
    pub user_id: Option<Ulid>,
    pub subject: String,
    /// Pasion-original: human-readable account name from upstream
    pub human_account_name: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Pasion-original: tracks when the link was last updated
    pub updated_at: DateTime<Utc>,
}

/// Pasion-original: a patch object for updating upstream OAuth link fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamOAuthLinkPatch {
    pub user_id: Option<Option<Ulid>>,
    pub subject: Option<String>,
    pub human_account_name: Option<Option<String>>,
}

impl UpstreamOAuthLinkPatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user_id.is_none() && self.subject.is_none() && self.human_account_name.is_none()
    }
}
