//! Append-only handle audit log (T3.2 — spec 0a5ab85 §3.7).
//!
//! Records the four immutable-history events called out in the task brief:
//!   * Handle reassignment (old_did -> new_did)
//!   * Handle revocation (user- or admin-initiated)
//!   * TTL expiry of an emitted `handle_claim`
//!   * Detected divergence in DID Document `alsoKnownAs[]` (watcher hook emits this; a
//!     `not_detected` placeholder is written when no watcher is configured).
//!
//! UPDATE / DELETE are blocked at the database trigger level — see
//! migration `20260520000100_handle_claims_and_audit/up.sql`. This module
//! therefore exposes only `record` and read accessors; there is no patch
//! API by design.
//!
//! Spec 7157ee8 (R3.1) stores the canonical `<localpart>:<domain>` handle
//! in the `handle` column — see migration
//! `20260527000200_handle_canonicalize_rename`.

use async_trait::async_trait;
use coauth_data::Clock;
use coauth_data::audit::HandleAuditEvent;
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::repository_impl;

/// Parameters used to insert a new [`HandleAuditEvent`].
#[derive(Debug, Clone)]
pub struct NewHandleAuditEvent {
    user_id: Option<Ulid>,
    event_type: HandleAuditEventType,
    handle: Option<String>,
    handle_aliases: Vec<String>,
    old_did: Option<String>,
    new_did: Option<String>,
    issuer_service_id: Option<String>,
    audience: Option<String>,
    details: Value,
    actor_id: Option<Ulid>,
}

impl NewHandleAuditEvent {
    /// Construct a new draft. All optional fields default to `None` /
    /// `Value::Null`.
    #[must_use]
    pub fn new(event_type: HandleAuditEventType) -> Self {
        Self {
            user_id: None,
            event_type,
            handle: None,
            handle_aliases: Vec::new(),
            old_did: None,
            new_did: None,
            issuer_service_id: None,
            audience: None,
            details: Value::Null,
            actor_id: None,
        }
    }

    /// Bind to a specific user record.
    #[must_use]
    pub fn with_user(mut self, user_id: Ulid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set the canonical `<localpart>:<domain>` handle affected.
    ///
    /// Spec 7157ee8 §3.1 — the wire form is the colon-joined canonical
    /// shape.
    #[must_use]
    pub fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Attach a free-form JSON detail payload (e.g. ticket id, reason).
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    /// Borrow the user id, if any.
    #[must_use]
    pub fn user_id(&self) -> Option<Ulid> {
        self.user_id
    }

    /// Borrow the event type.
    #[must_use]
    pub fn event_type(&self) -> &HandleAuditEventType {
        &self.event_type
    }

    /// Borrow the canonical `<localpart>:<domain>` handle, if any.
    #[must_use]
    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
    }

    /// Borrow the aliases at the time of the event.
    #[must_use]
    pub fn handle_aliases(&self) -> &[String] {
        &self.handle_aliases
    }

    /// Borrow the old DID, if any.
    #[must_use]
    pub fn old_did(&self) -> Option<&str> {
        self.old_did.as_deref()
    }

    /// Borrow the new DID, if any.
    #[must_use]
    pub fn new_did(&self) -> Option<&str> {
        self.new_did.as_deref()
    }

    /// Borrow the issuer service DID.
    #[must_use]
    pub fn issuer_service_id(&self) -> Option<&str> {
        self.issuer_service_id.as_deref()
    }

    /// Borrow the audience.
    #[must_use]
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// Borrow the free-form details.
    #[must_use]
    pub fn details(&self) -> &Value {
        &self.details
    }

    /// Borrow the actor id.
    #[must_use]
    pub fn actor_id(&self) -> Option<Ulid> {
        self.actor_id
    }
}

/// Discriminator for the handle audit log. Stored as `snake_case` text in
/// the database; new variants are additive and do not break existing rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleAuditEventType {
    /// A handle URI was issued for the first time.
    Issued,
    /// A `handle_claim` JWT was signed and dispatched.
    ClaimIssued,
    /// The handle was reassigned from `old_did` to `new_did`.
    Reassigned,
    /// The handle was revoked (user or admin).
    Revoked,
    /// A previously emitted `handle_claim` reached its TTL.
    ClaimExpired,
    /// The DID Document `alsoKnownAs[]` for the bound DID was observed to
    /// diverge from coauth's canonical handle URI.
    AlsoKnownAsDivergence,
    /// Placeholder entry recording that no watcher was configured to
    /// monitor DID Document divergence. Written at issuance time so
    /// auditors can see the gap rather than infer it from absence.
    AlsoKnownAsWatcherUnconfigured,
}

/// Repository accessor for the append-only handle audit log.
#[async_trait]
pub trait HandleAuditRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Insert a new audit event. There is no companion update / delete by
    /// design; the database enforces append-only at the trigger level.
    async fn record(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewHandleAuditEvent,
    ) -> Result<HandleAuditEvent, Self::Error>;

    /// List all audit events for a given user, newest first.
    async fn list_for_user(
        &mut self,
        user_id: Ulid,
        limit: usize,
    ) -> Result<Vec<HandleAuditEvent>, Self::Error>;

    /// List the most recent N events of a given type across all users.
    async fn list_by_event_type(
        &mut self,
        event_type: HandleAuditEventType,
        limit: usize,
    ) -> Result<Vec<HandleAuditEvent>, Self::Error>;

    /// Look up a single audit event by id.
    async fn lookup(&mut self, id: Ulid) -> Result<Option<HandleAuditEvent>, Self::Error>;

    /// Count events for a given user (audit-summary endpoints).
    async fn count_for_user(&mut self, user_id: Ulid) -> Result<usize, Self::Error>;
}

repository_impl!(HandleAuditRepository:
    async fn record(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewHandleAuditEvent,
    ) -> Result<HandleAuditEvent, Self::Error>;
    async fn list_for_user(
        &mut self,
        user_id: Ulid,
        limit: usize,
    ) -> Result<Vec<HandleAuditEvent>, Self::Error>;
    async fn list_by_event_type(
        &mut self,
        event_type: HandleAuditEventType,
        limit: usize,
    ) -> Result<Vec<HandleAuditEvent>, Self::Error>;
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<HandleAuditEvent>, Self::Error>;
    async fn count_for_user(&mut self, user_id: Ulid) -> Result<usize, Self::Error>;
);
