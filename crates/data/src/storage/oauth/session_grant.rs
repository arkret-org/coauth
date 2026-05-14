use async_trait::async_trait;
use chrono::{DateTime, Utc};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, SessionGrant, pagination::Page, repository_impl, storage::Pagination};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Filters used when listing persisted Contrix session grants.
pub struct SessionGrantFilter<'a> {
    browser_session_id: Option<Ulid>,
    subject: Option<&'a str>,
    device_id: Option<&'a str>,
    audience: Option<&'a str>,
    active_at: Option<DateTime<Utc>>,
}

impl<'a> SessionGrantFilter<'a> {
    /// Create an empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict results to grants bound to one browser session.
    #[must_use]
    pub fn for_browser_session(mut self, browser_session_id: Ulid) -> Self {
        self.browser_session_id = Some(browser_session_id);
        self
    }

    /// Return the browser session id constraint, if present.
    #[must_use]
    pub fn browser_session_id(&self) -> Option<Ulid> {
        self.browser_session_id
    }

    /// Restrict results to a subject DID.
    #[must_use]
    pub fn for_subject(mut self, subject: &'a str) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Return the subject constraint, if present.
    #[must_use]
    pub fn subject(&self) -> Option<&'a str> {
        self.subject
    }

    /// Restrict results to a Contrix client device id.
    #[must_use]
    pub fn for_device(mut self, device_id: &'a str) -> Self {
        self.device_id = Some(device_id);
        self
    }

    /// Return the device id constraint, if present.
    #[must_use]
    pub fn device_id(&self) -> Option<&'a str> {
        self.device_id
    }

    /// Restrict results to a grant audience.
    #[must_use]
    pub fn for_audience(mut self, audience: &'a str) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Return the audience constraint, if present.
    #[must_use]
    pub fn audience(&self) -> Option<&'a str> {
        self.audience
    }

    /// Restrict results to grants active at the provided timestamp.
    #[must_use]
    pub fn active_at(mut self, active_at: DateTime<Utc>) -> Self {
        self.active_at = Some(active_at);
        self
    }

    /// Return the active-at constraint, if present.
    #[must_use]
    pub fn active_at_value(&self) -> Option<DateTime<Utc>> {
        self.active_at
    }
}

#[derive(Debug)]
/// Parameters for creating a persisted Contrix session grant.
pub struct NewSessionGrant<'a> {
    /// Browser session that the grant is bound to.
    pub browser_session_id: Ulid,
    /// DID issuer of the signed grant.
    pub issuer: &'a str,
    /// DID subject authorized by the grant.
    pub subject: &'a str,
    /// Optional Contrix client device id.
    pub device_id: Option<&'a str>,
    /// Intended grant audience.
    pub audience: &'a str,
    /// Granted OAuth scope set.
    pub scope: Scope,
    /// Signed session grant JWT.
    pub grant_jwt: &'a str,
    /// Public key generated for this session grant.
    pub session_public_key: &'a str,
    /// Grant expiration timestamp.
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
/// Repository for persisted Contrix session grants.
pub trait SessionGrantRepository: Send + Sync {
    /// Repository-specific error type.
    type Error;

    /// Persist a new session grant.
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        grant: NewSessionGrant<'_>,
    ) -> Result<SessionGrant, Self::Error>;

    /// Look up a session grant by id.
    async fn lookup(&mut self, id: Ulid) -> Result<Option<SessionGrant>, Self::Error>;

    /// Look up a session grant by its signed JWT.
    async fn lookup_by_grant_jwt(
        &mut self,
        grant_jwt: &str,
    ) -> Result<Option<SessionGrant>, Self::Error>;

    /// List session grants matching the supplied filter.
    async fn list(
        &mut self,
        filter: SessionGrantFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<SessionGrant>, Self::Error>;

    /// Mark a session grant as revoked.
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        grant: SessionGrant,
    ) -> Result<SessionGrant, Self::Error>;

    /// Delete session grants whose `expires_at` is strictly before `until`.
    ///
    /// Mirrors the time-cursor cleanup contract used elsewhere
    /// (e.g. `oauth2_session.cleanup_finished`): paginates through
    /// matching rows in `expires_at` ascending order, returns the count
    /// deleted in this batch and the latest `expires_at` processed so a
    /// later call can resume from `since = next_cursor`.
    ///
    /// # Parameters
    ///
    /// * `since`: Only delete grants with `expires_at` at or after this
    ///   timestamp. `None` starts from the beginning.
    /// * `until`: Latest `expires_at` to delete (exclusive).
    /// * `limit`: Maximum number of grants to delete in this batch.
    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;
}

repository_impl!(SessionGrantRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        grant: NewSessionGrant<'_>,
    ) -> Result<SessionGrant, Self::Error>;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<SessionGrant>, Self::Error>;

    async fn lookup_by_grant_jwt(
        &mut self,
        grant_jwt: &str,
    ) -> Result<Option<SessionGrant>, Self::Error>;

    async fn list(
        &mut self,
        filter: SessionGrantFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<SessionGrant>, Self::Error>;

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        grant: SessionGrant,
    ) -> Result<SessionGrant, Self::Error>;

    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;
);
