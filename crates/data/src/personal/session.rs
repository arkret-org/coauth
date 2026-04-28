use std::net::IpAddr;

use chrono::{DateTime, Utc};
use oauth2_types::scope::Scope;
use serde::Serialize;
use ulid::Ulid;

use crate::{Client, InvalidTransitionError, User};

/// Lifecycle state of a personal session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum SessionState {
    /// The session is active and may be used.
    #[default]
    Valid,
    /// The session has been explicitly terminated.
    Revoked {
        /// Instant at which the session was revoked.
        revoked_at: DateTime<Utc>,
    },
}

impl SessionState {
    /// `true` when the session is still active.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// `true` when the session has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// Transition from [`Valid`](Self::Valid) to [`Revoked`](Self::Revoked).
    ///
    /// # Errors
    ///
    /// Fails with [`InvalidTransitionError`] when the session was already
    /// revoked.
    pub fn revoke(self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Revoked { revoked_at }),
            Self::Revoked { .. } => Err(InvalidTransitionError),
        }
    }

    /// If the session has been revoked, returns the instant it happened.
    #[must_use]
    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Valid => None,
            Self::Revoked { revoked_at } => Some(*revoked_at),
        }
    }
}

/// Persistent personal session issued outside the OAuth 2.0 flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonalSession {
    pub id: Ulid,
    pub state: SessionState,
    pub owner: PersonalSessionOwner,
    pub actor_user_id: Ulid,
    pub human_name: String,
    /// OAuth 2-compatible scope granted to this session.  May optionally
    /// contain a device scope (personal sessions are not required to have one).
    pub scope: Scope,
    pub created_at: DateTime<Utc>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

/// Who owns a personal session -- either a user directly or an OAuth 2 client.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize)]
pub enum PersonalSessionOwner {
    /// Owned by the user identified by this ULID.
    User(Ulid),
    /// Owned by the OAuth 2 client identified by this ULID.
    OAuth2Client(Ulid),
}

impl<'a> From<&'a User> for PersonalSessionOwner {
    fn from(u: &'a User) -> Self {
        Self::User(u.id)
    }
}

impl<'a> From<&'a Client> for PersonalSessionOwner {
    fn from(c: &'a Client) -> Self {
        Self::OAuth2Client(c.id)
    }
}

// Allow callers to invoke `SessionState` methods directly on `PersonalSession`.
impl std::ops::Deref for PersonalSession {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl PersonalSession {
    /// Revoke (finish) this session.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransitionError`] if the session was already revoked.
    pub fn finish(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.revoke(revoked_at)?;
        Ok(self)
    }

    /// Whether the session's scope includes a Matrix device scope, indicating
    /// that a device is attached.
    #[must_use]
    pub fn has_device(&self) -> bool {
        const DEVICE_URN: &str = "urn:matrix:client:device:";
        const DEVICE_URN_MSC: &str = "urn:matrix:org.matrix.msc2967.client:device:";

        self.scope.iter().any(|tok| {
            let s = tok.as_str();
            s.starts_with(DEVICE_URN) || s.starts_with(DEVICE_URN_MSC)
        })
    }
}
