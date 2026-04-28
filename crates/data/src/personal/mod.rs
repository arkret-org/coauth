pub mod session;

use chrono::{DateTime, Utc};
use ulid::Ulid;

/// A bearer token that grants access to a
/// [`PersonalSession`](session::PersonalSession).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalAccessToken {
    /// Unique identifier for this token.
    pub id: Ulid,
    /// The session this token authenticates.
    pub session_id: Ulid,
    /// When the token was issued.
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry; `None` means the token lives until revoked.
    pub expires_at: Option<DateTime<Utc>>,
    /// Set when the token is explicitly revoked; `None` while active.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl PersonalAccessToken {
    /// A token is valid when it has not been revoked and, if it carries an
    /// expiry, that expiry has not yet passed.
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }

        match self.expires_at {
            Some(deadline) => now < deadline,
            None => true,
        }
    }
}

pub use crate::{
    pg::personal::{PgPersonalAccessTokenRepository, PgPersonalSessionRepository},
    storage::personal::*,
};
