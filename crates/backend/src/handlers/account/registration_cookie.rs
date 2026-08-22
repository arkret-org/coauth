// Cookie management for user registration sessions

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use coauth_data::{Clock, UserRegistration};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::salvo_utils::cookies::{CookieExpiration, CookieJar};

/// Name of the cookie
static COOKIE_NAME: &str = "user-registration-sessions";

/// Sessions expire after an hour
static SESSION_MAX_TIME: Duration = Duration::hours(1);

/// The content of the cookie, which stores a list of user registration IDs
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct UserRegistrationSessions(BTreeSet<Ulid>);

impl UserRegistrationSessions {
    /// Load the user registration sessions cookie
    pub fn load(cookie_jar: &CookieJar) -> Self {
        match cookie_jar.load(COOKIE_NAME) {
            Ok(Some(sessions)) => sessions,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "Invalid upstream sessions cookie"
                );
                Self::default()
            }
        }
    }

    /// Returns true if the cookie is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Save the user registration sessions to the cookie jar
    pub fn save<C>(self, cookie_jar: CookieJar, clock: &C) -> CookieJar
    where
        C: Clock,
    {
        let this = self.expire(clock.now());

        if this.is_empty() {
            cookie_jar.remove(COOKIE_NAME)
        } else {
            cookie_jar.save(COOKIE_NAME, &this, CookieExpiration::Session)
        }
    }

    fn expire(mut self, now: DateTime<Utc>) -> Self {
        self.0.retain(|id| {
            let Ok(ts) = id.timestamp_ms().try_into() else {
                return false;
            };
            let Some(when) = DateTime::from_timestamp_millis(ts) else {
                return false;
            };
            now - when < SESSION_MAX_TIME
        });

        self
    }

    /// Add a new session, for a provider and a random state
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, user_registration: &UserRegistration) -> Self {
        self.0.insert(user_registration.id);
        self
    }
}
