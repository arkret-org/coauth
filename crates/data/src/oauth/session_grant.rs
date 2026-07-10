use arkret_core::GrantId;
use chrono::{DateTime, Utc};
use coauth_oauth_types::scope::Scope;
use serde::Serialize;
use serde_json::Value;
use ulid::Ulid;

use crate::{Clock, InvalidTransitionError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionGrant {
    pub id: Ulid,
    pub grant_id: GrantId,
    pub browser_session_id: Option<Ulid>,
    pub issuer: String,
    pub subject: String,
    pub device_id: Option<String>,
    pub applet_id: Option<String>,
    pub effective_scope: Option<Value>,
    pub registration_epoch: Option<String>,
    pub service_did: Option<String>,
    pub capability_grant_refs: Vec<String>,
    pub audience: String,
    pub scope: Scope,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl SessionGrant {
    #[must_use]
    pub fn is_active(&self, clock: &dyn Clock) -> bool {
        self.revoked_at.is_none() && self.expires_at > clock.now()
    }

    pub fn revoke(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        if self.revoked_at.is_some() {
            return Err(InvalidTransitionError);
        }

        self.revoked_at = Some(revoked_at);
        Ok(self)
    }
}
