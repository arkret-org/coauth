use arkret_core::GrantId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_oauth_types::scope::Scope;
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::pagination::Page;
use crate::storage::Pagination;
use crate::{Clock, SessionGrant, repository_impl};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Filters used when listing persisted Arkret session grants.
pub struct SessionGrantFilter<'a> {
    browser_session_id: Option<Ulid>,
    /// Owning account, resolved through the grant's browser session
    /// (`oauth_session_grants.user_session_id -> user_sessions.user_id`).
    account_id: Option<Ulid>,
    subject: Option<&'a str>,
    device_id: Option<&'a str>,
    applet_id: Option<&'a str>,
    effective_scope: Option<&'a Value>,
    registration_epoch: Option<&'a str>,
    service_did: Option<&'a str>,
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

    /// Restrict results to grants owned by one account.
    ///
    /// Ownership is the `user_id` of the browser session the grant is bound
    /// to. Grants without a browser session (`user_session_id IS NULL`) never
    /// match an account filter. Pushing this down avoids paging the whole
    /// table and resolving the owner per grant in memory.
    #[must_use]
    pub fn for_account(mut self, account_id: Ulid) -> Self {
        self.account_id = Some(account_id);
        self
    }

    /// Return the owning-account constraint, if present.
    #[must_use]
    pub fn account_id(&self) -> Option<Ulid> {
        self.account_id
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

    /// Restrict results to a Arkret client device id.
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

    /// Restrict results to applet-delegated grants for one effective install epoch.
    #[must_use]
    pub fn for_applet_delegation(
        mut self,
        applet_id: &'a str,
        effective_scope: &'a Value,
        registration_epoch: &'a str,
        service_did: Option<&'a str>,
    ) -> Self {
        self.applet_id = Some(applet_id);
        self.effective_scope = Some(effective_scope);
        self.registration_epoch = Some(registration_epoch);
        self.service_did = service_did;
        self
    }

    /// Return the applet id constraint, if present.
    #[must_use]
    pub fn applet_id(&self) -> Option<&'a str> {
        self.applet_id
    }

    /// Return the effective scope constraint, if present.
    #[must_use]
    pub fn effective_scope(&self) -> Option<&'a Value> {
        self.effective_scope
    }

    /// Return the registration epoch constraint, if present.
    #[must_use]
    pub fn registration_epoch(&self) -> Option<&'a str> {
        self.registration_epoch
    }

    /// Return the service DID constraint, if present.
    #[must_use]
    pub fn service_did(&self) -> Option<&'a str> {
        self.service_did
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
/// Parameters for creating a persisted Arkret session grant.
pub struct NewSessionGrant<'a> {
    /// Protocol-visible session grant id (`ak:grant:<uuidv7>`).
    pub grant_id: GrantId,
    /// Browser session that the grant is bound to.
    pub browser_session_id: Option<Ulid>,
    /// DID issuer of the signed grant.
    pub issuer: &'a str,
    /// DID subject authorized by the grant.
    pub subject: &'a str,
    /// Optional Arkret client device id.
    pub device_id: Option<&'a str>,
    /// Applet effective install id, for applet-specific delegated sessions.
    pub applet_id: Option<&'a str>,
    /// Canonical effective scope bound to the applet delegated session.
    pub effective_scope: Option<Value>,
    /// Applet registration epoch hash.
    pub registration_epoch: Option<&'a str>,
    /// Applet service DID bound to the delegation, when available.
    pub service_did: Option<&'a str>,
    /// Capability grant refs that backed the applet delegation.
    pub capability_grant_refs: Vec<String>,
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
/// Repository for persisted Arkret session grants.
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

    /// Look up a session grant by protocol-visible grant id.
    async fn lookup_by_grant_id(
        &mut self,
        grant_id: &GrantId,
    ) -> Result<Option<SessionGrant>, Self::Error>;

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

    /// Atomically consume a grant: set `revoked_at` **only if** it is still
    /// `NULL`, returning whether this call performed the revocation.
    ///
    /// This is the single-use rotation gate (account-lifecycle §4.1). The
    /// conditional `UPDATE ... WHERE revoked_at IS NULL` row-locks the grant,
    /// so two concurrent rotations of the same parent contend on that lock;
    /// exactly one observes the row still active and gets `true`, the other
    /// re-reads the now-committed `revoked_at` and gets `false`. Returning
    /// `false` MUST be treated as `grant_already_consumed` — never minting a
    /// second active child of one parent.
    async fn revoke_if_active(&mut self, clock: &dyn Clock, id: Ulid) -> Result<bool, Self::Error>;

    /// Delete session grants whose `expires_at` is strictly before `until`.
    ///
    /// Mirrors the time-cursor cleanup contract used elsewhere
    /// (e.g. `oauth_session.cleanup_finished`): paginates through
    /// matching rows in `expires_at` ascending order, returns the count
    /// deleted in this batch and the latest `expires_at` processed so a
    /// later call can resume from `since = next_cursor`.
    ///
    /// # Parameters
    ///
    /// * `since`: Only delete grants with `expires_at` at or after this timestamp. `None` starts
    ///   from the beginning.
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

    async fn lookup_by_grant_id(
        &mut self,
        grant_id: &GrantId,
    ) -> Result<Option<SessionGrant>, Self::Error>;

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

    async fn revoke_if_active(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
    ) -> Result<bool, Self::Error>;

    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;
);
