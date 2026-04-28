//! User-registration workflow cookie.
//!
//! Stores the set of in-flight registration IDs the browser is allowed to
//! interact with. Shares the [`TimedCookie`] contract with the upstream
//! OAuth 2.0 cookie; this module only supplies the payload-specific filter
//! and the "remove when empty" save override.

use std::collections::BTreeSet;

use crate::salvo_utils::cookies::{CookieExpiration, CookieJar, TimedCookie, ulid_is_expired};
use chrono::{DateTime, Duration, Utc};
use coauth_data::{Clock, UserRegistration};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// Sessions expire after an hour.
fn user_registration_max_age() -> Duration {
    Duration::hours(1)
}

/// The content of the cookie, which stores a list of user registration IDs
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct UserRegistrationSessions(BTreeSet<Ulid>);

#[derive(Debug, Error, PartialEq, Eq)]
#[error("user registration session not found")]
pub struct UserRegistrationSessionNotFound;

impl TimedCookie for UserRegistrationSessions {
    const COOKIE_NAME: &'static str = "user-registration-sessions";

    fn max_age() -> Duration {
        user_registration_max_age()
    }

    fn expire(mut self, now: DateTime<Utc>) -> Self {
        let max_age = Self::max_age();
        self.0.retain(|id| !ulid_is_expired(*id, now, max_age));
        self
    }

    /// Override `save` to *remove* the cookie entirely when no registration
    /// IDs remain, keeping the default non-empty branch.
    fn save<C: Clock>(self, cookie_jar: CookieJar, clock: &C) -> CookieJar {
        let this = self.expire(clock.now());
        if this.is_empty() {
            cookie_jar.remove(Self::COOKIE_NAME)
        } else {
            cookie_jar.save(Self::COOKIE_NAME, &this, CookieExpiration::Session)
        }
    }
}

impl UserRegistrationSessions {
    /// Returns true if the cookie is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add a new session, for a provider and a random state
    pub fn add(mut self, user_registration: &UserRegistration) -> Self {
        self.0.insert(user_registration.id);
        self
    }

    /// Check if the session is in the list
    pub fn contains(&self, user_registration: &UserRegistration) -> bool {
        self.0.contains(&user_registration.id)
    }

    /// Check if the session is in the list by registration ID
    pub fn contains_id(&self, user_registration_id: Ulid) -> bool {
        self.0.contains(&user_registration_id)
    }

    /// Mark a link as consumed to avoid replay
    pub fn consume_session(
        mut self,
        user_registration: &UserRegistration,
    ) -> Result<Self, UserRegistrationSessionNotFound> {
        if !self.0.remove(&user_registration.id) {
            return Err(UserRegistrationSessionNotFound);
        }

        Ok(self)
    }
}
