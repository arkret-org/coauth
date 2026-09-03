//! Repositories to interact with all kinds of sessions

use chrono::{DateTime, Utc};
use coauth_data::{BrowserSession, Clock, Session, User};

use crate::{Page, Pagination, repository_impl};

/// The state of a session
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSessionState {
    /// The session is active
    Active,
    /// The session is finished
    Finished,
}

impl AppSessionState {
    /// Returns [`true`] if we're looking for active sessions
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns [`true`] if we're looking for finished sessions
    #[must_use]
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// An [`AppSession`] represents an OAuth [`Session`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppSession {
    /// An OAuth session
    OAuth(Box<Session>),
}

/// Filtering parameters for application sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AppSessionFilter<'a> {
    user: Option<&'a User>,
    browser_session: Option<&'a BrowserSession>,
    state: Option<AppSessionState>,
    device_id: Option<&'a str>,
    last_active_before: Option<DateTime<Utc>>,
}

impl<'a> AppSessionFilter<'a> {
    /// Create a new [`AppSessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user who owns the sessions
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    #[must_use]
    pub fn user(&self) -> Option<&'a User> {
        self.user
    }

    /// Set the browser session filter
    #[must_use]
    pub fn for_browser_session(mut self, browser_session: &'a BrowserSession) -> Self {
        self.browser_session = Some(browser_session);
        self
    }

    /// Get the browser session filter
    #[must_use]
    pub fn browser_session(&self) -> Option<&'a BrowserSession> {
        self.browser_session
    }

    /// Set the device ID filter
    #[must_use]
    pub fn for_device(mut self, device_id: &'a str) -> Self {
        self.device_id = Some(device_id);
        self
    }

    /// Get the device ID filter
    #[must_use]
    pub fn device(&self) -> Option<&'a str> {
        self.device_id
    }

    /// Only return sessions with a last active time before the given time
    #[must_use]
    pub fn with_last_active_before(mut self, last_active_before: DateTime<Utc>) -> Self {
        self.last_active_before = Some(last_active_before);
        self
    }

    /// Get the last active before filter
    ///
    /// Returns [`None`] if no client filter was set
    #[must_use]
    pub fn last_active_before(&self) -> Option<DateTime<Utc>> {
        self.last_active_before
    }

    /// Only return active application sessions
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(AppSessionState::Active);
        self
    }

    /// Only return finished application sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(AppSessionState::Finished);
        self
    }

    /// Get the state filter
    #[must_use]
    pub fn state(&self) -> Option<AppSessionState> {
        self.state
    }
}

repository_impl! {
    /// A [`AppSessionRepository`] helps interacting with
    /// OAuth [`Session`] saved in the storage backend
    pub trait AppSessionRepository {
        /// The error type returned by the repository
        type Error;

        /// List [`AppSession`] with the given filter and pagination
        ///
        /// Returns a page of [`AppSession`] matching the given filter
        ///
        /// # Parameters
        ///
        /// * `filter`: The filter to apply
        /// * `pagination`: The pagination parameters
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails
        async fn list(
            &mut self,
            filter: AppSessionFilter<'_>,
            pagination: Pagination,
        ) -> Result<Page<AppSession>, Self::Error>;

        /// Count the number of [`AppSession`] with the given filter
        ///
        /// # Parameters
        ///
        /// * `filter`: The filter to apply
        ///
        /// # Errors
        ///
        /// Returns [`Self::Error`] if the underlying repository fails
        async fn count(&mut self, filter: AppSessionFilter<'_>) -> Result<usize, Self::Error>;

        /// Finishes any application sessions that are using the specified device's
        /// ID.
        ///
        /// This is intended for logging in using an existing device ID (i.e.
        /// replacing a device).
        ///
        /// Should be called *before* creating a new session for the device.
        ///
        /// Returns true if a session was finished.
        async fn finish_sessions_to_replace_device(
            &mut self,
            clock: &dyn Clock,
            user: &User,
            device: &str,
        ) -> Result<bool, Self::Error>;
    }
}
