use arkret_identifiers::SessionGrantId;
use arkret_models_identity::SessionGrantProofKind;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_oauth_types::scope::Scope;
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::oauth::{SessionGrant, SessionGrantOperation, SessionGrantOperationDescriptor};
use crate::pagination::Page;
use crate::storage::Pagination;
use crate::{Clock, repository_impl};

/// Storage-enforced minimum lifetime for request-identity replay evidence.
pub const MIN_SESSION_GRANT_OPERATION_RETENTION_SECONDS: i64 = 86_400;

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
    service_id: Option<&'a str>,
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
        service_id: Option<&'a str>,
    ) -> Self {
        self.applet_id = Some(applet_id);
        self.effective_scope = Some(effective_scope);
        self.registration_epoch = Some(registration_epoch);
        self.service_id = service_id;
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
    pub fn service_id(&self) -> Option<&'a str> {
        self.service_id
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
    pub grant_id: SessionGrantId,
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
    pub service_id: Option<&'a str>,
    /// Capability grant refs that backed the applet delegation.
    pub capability_grant_refs: Vec<String>,
    /// Intended grant audience.
    pub audience: &'a str,
    /// Granted OAuth scope set.
    pub scope: Scope,
    /// Signed session grant JWT.
    pub grant_jwt: &'a str,
    /// Stable, independently allocated refresh-chain identifier.
    pub session_id: &'a str,
    /// Canonical Base64URL issuer nonce included in the signed claims.
    pub issuance_nonce: &'a str,
    /// Exact canonical JCS issuance preimage committed by the issuer.
    pub issuance_preimage: &'a [u8],
    /// SHA-256 digest of `issuance_preimage` and digest portion of `grant_id`.
    pub issuance_digest: [u8; 32],
    /// Issuer signing-key id used for the durable JWT outcome.
    pub signing_key_id: &'a str,
    /// Public key generated for this session grant.
    pub session_public_key: &'a str,
    /// Closed signed credential class (`standard`).
    pub credential_class: &'a str,
    /// Grant expiration timestamp.
    pub not_before: DateTime<Utc>,
    /// Grant expiration timestamp.
    pub expires_at: DateTime<Utc>,
}

/// Stable exact-replay identity and canonical intent for one issuer operation.
#[derive(Debug)]
pub struct NewSessionGrantOperation<'a> {
    /// Issuer DID that owns this replay namespace.
    pub issuer: &'a str,
    /// Closed lifecycle operation family.
    pub operation: SessionGrantOperationDescriptor,
    /// Signed proof kind for initial issuance; absent for other operations.
    pub proof_kind: Option<SessionGrantProofKind>,
    /// Stable proof- or predecessor-derived request identity.
    pub request_identity: &'a str,
    /// SHA-256 digest of the exact canonical intent.
    pub canonical_intent_digest: [u8; 32],
    /// Exact canonical request intent bytes.
    pub canonical_intent: &'a [u8],
    /// Locked predecessor for refresh; absent for issue and selector-based revoke.
    pub target_session_grant_id: Option<&'a SessionGrantId>,
    /// Existing issuance nonce for an internally pre-minted initial grant.
    /// External issue operations leave this absent so reservation allocates it.
    pub issuance_nonce: Option<&'a str>,
    /// Existing rotation-chain id for refresh; initial issuance allocates when absent.
    pub session_id: Option<&'a str>,
    /// Immutable signing window for a grant-producing operation.
    pub grant_not_before: Option<DateTime<Utc>>,
    /// Immutable grant expiry selected at reservation time.
    pub grant_expires_at: Option<DateTime<Utc>>,
    /// Signing key selected at reservation time; retries never switch keys.
    pub signing_key_id: Option<&'a str>,
    /// Caller retention request; the repository applies its stronger policy floor.
    pub retained_until: DateTime<Utc>,
}

/// Durable authorization result for a consumed one-shot proof.
#[derive(Debug, Clone, Copy)]
pub struct SessionGrantProofAuthorization<'a> {
    /// Stable reference to the consumed proof authorization.
    pub authorization_ref: &'a str,
    /// Closed durable result needed to resume after proof consumption.
    pub checkpoint: &'a Value,
    /// Expiry of the proof/checkpoint retry window.
    pub proof_expires_at: DateTime<Utc>,
}

/// Byte-exact canonical response persisted before a successful response is returned.
#[derive(Debug, Clone, Copy)]
pub struct SessionGrantExactOutcome<'a> {
    /// Exact canonical HTTP response bytes returned on replay.
    pub canonical_response: &'a [u8],
    /// SHA-256 digest of `canonical_response`.
    pub response_digest: [u8; 32],
}

/// Closed selector for one durable revoke mutation.
#[derive(Debug, Clone, Copy)]
pub enum SessionGrantRevokeSelector<'a> {
    /// Revoke one exact grant.
    Grant(&'a SessionGrantId),
    /// Revoke every active grant for one subject/device binding.
    Device {
        /// Subject DID.
        subject: &'a str,
        /// Device binding.
        device_id: &'a str,
    },
    /// Revoke every active grant for a subject.
    AllForSubject {
        /// Subject DID.
        subject: &'a str,
    },
}

/// Result of reserving a request identity in the durable operation ledger.
#[derive(Debug)]
pub enum SessionGrantReserveOutcome {
    /// This caller created the first durable reservation.
    Reserved(SessionGrantOperation),
    /// The identical operation already exists without a committed outcome.
    Pending(SessionGrantOperation),
    /// The identical operation already committed and can return its exact outcome.
    Replay(SessionGrantOperation),
    /// The request identity exists with different canonical intent.
    Conflict(SessionGrantOperation),
    /// A tombstone exists but its exact outcome is no longer available.
    Indeterminate(SessionGrantOperation),
}

/// Idempotent result of committing a newly issued grant.
#[derive(Debug)]
pub enum SessionGrantCommitOutcome {
    /// This call atomically committed the first outcome.
    Committed(SessionGrant),
    /// A prior commit won; return its byte-exact operation outcome.
    Replay(SessionGrantOperation),
    /// The operation is an evicted tombstone.
    Indeterminate(SessionGrantOperation),
}

/// Atomic refresh result.
#[derive(Debug)]
pub enum SessionGrantRefreshOutcome {
    /// This call committed the first successor.
    Committed {
        /// Atomically superseded predecessor.
        predecessor: SessionGrant,
        /// Atomically inserted successor.
        successor: SessionGrant,
    },
    /// A prior refresh committed the byte-exact outcome.
    Replay(SessionGrantOperation),
    /// The predecessor was already revoked or superseded by another operation.
    PredecessorTerminal(SessionGrant),
    /// The operation is an evicted tombstone.
    Indeterminate(SessionGrantOperation),
}

/// Idempotent revoke result.
#[derive(Debug)]
pub enum SessionGrantRevokeOutcome {
    /// This call committed the first selector mutation.
    Revoked {
        /// Complete locked set changed by this transaction.
        grants: Vec<SessionGrant>,
        /// Shared mutation timestamp.
        revoked_at: DateTime<Utc>,
        /// Committed ledger record carrying the repository-generated canonical outcome.
        operation: SessionGrantOperation,
    },
    /// A prior revoke committed the byte-exact mutation outcome.
    Replay(SessionGrantOperation),
    /// The selector matched only already-terminal grants.
    AlreadyTerminal {
        /// Complete locked terminal set selected by the request.
        grants: Vec<SessionGrant>,
        /// Committed zero-mutation outcome for exact replay.
        operation: SessionGrantOperation,
    },
    /// The operation is an evicted tombstone.
    Indeterminate(SessionGrantOperation),
}

#[async_trait]
/// Repository for persisted Arkret session grants.
pub trait SessionGrantRepository: Send + Sync {
    /// Repository-specific error type.
    type Error;

    /// Reserve a stable request identity before consuming its authorization proof.
    async fn reserve_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation: NewSessionGrantOperation<'_>,
    ) -> Result<SessionGrantReserveOutcome, Self::Error>;

    /// Persist an external one-shot authorization checkpoint before later commit.
    async fn checkpoint_authorization(
        &mut self,
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
    ) -> Result<SessionGrantOperation, Self::Error>;

    /// Atomically persist the exact JWT outcome and commit its operation.
    async fn commit_issuance(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        outcome: SessionGrantExactOutcome<'_>,
        grant: NewSessionGrant<'_>,
    ) -> Result<SessionGrantCommitOutcome, Self::Error>;

    /// Atomically insert a successor, supersede its active predecessor, and commit replay state.
    async fn commit_refresh(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        outcome: SessionGrantExactOutcome<'_>,
        predecessor_grant_id: &SessionGrantId,
        successor: NewSessionGrant<'_>,
    ) -> Result<SessionGrantRefreshOutcome, Self::Error>;

    /// Atomically revoke an active grant and commit an exact-replay outcome.
    async fn commit_revoke(
        &mut self,
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        selector: SessionGrantRevokeSelector<'_>,
    ) -> Result<SessionGrantRevokeOutcome, Self::Error>;

    /// Look up a session grant by id.
    async fn lookup(&mut self, id: Ulid) -> Result<Option<SessionGrant>, Self::Error>;

    /// Look up a session grant by protocol-visible grant id.
    async fn lookup_by_grant_id(
        &mut self,
        grant_id: &SessionGrantId,
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
    async fn reserve_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation: NewSessionGrantOperation<'_>,
    ) -> Result<SessionGrantReserveOutcome, Self::Error>;

    async fn checkpoint_authorization(
        &mut self,
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
    ) -> Result<SessionGrantOperation, Self::Error>;

    async fn commit_issuance(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        outcome: SessionGrantExactOutcome<'_>,
        grant: NewSessionGrant<'_>,
    ) -> Result<SessionGrantCommitOutcome, Self::Error>;

    async fn commit_refresh(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        outcome: SessionGrantExactOutcome<'_>,
        predecessor_grant_id: &SessionGrantId,
        successor: NewSessionGrant<'_>,
    ) -> Result<SessionGrantRefreshOutcome, Self::Error>;

    async fn commit_revoke(
        &mut self,
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        selector: SessionGrantRevokeSelector<'_>,
    ) -> Result<SessionGrantRevokeOutcome, Self::Error>;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<SessionGrant>, Self::Error>;

    async fn lookup_by_grant_id(
        &mut self,
        grant_id: &SessionGrantId,
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
