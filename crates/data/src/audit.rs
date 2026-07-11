use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Ulid;
pub use crate::pg::audit::PgAuditRepository;
pub use crate::pg::handle_audit::PgHandleAuditRepository;
pub use crate::storage::audit::*;
pub use crate::storage::handle_audit::{
    HandleAuditEventType, HandleAuditRepository, NewHandleAuditEvent,
};

/// An admin operation log entry, recording actions taken by administrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminOperationLog {
    /// Stable unique identifier for the log entry.
    pub id: Ulid,
    /// The admin user who performed the operation.
    pub admin_user_id: Ulid,
    /// The type of operation performed.
    pub operation: AdminOperation,
    /// The target resource type.
    pub resource_type: String,
    /// The target resource ID.
    pub resource_id: Option<Ulid>,
    /// Structured details about the operation.
    pub details: Value,
    /// Client IP address of the admin.
    pub ip_address: Option<std::net::IpAddr>,
    /// User-agent string of the admin's client.
    pub user_agent: Option<String>,
    /// When the operation occurred.
    pub created_at: DateTime<Utc>,
    /// Optional detached signature over the canonical-JSON row transcript,
    /// produced with the coauth service signing key. `None` is valid for
    /// rollout/fail-open deployments; readers surface that as `unsigned`
    /// rather than rejecting the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_signature: Option<String>,
}

/// Types of admin operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOperation {
    /// A new user account was created.
    UserCreated,
    /// A user account was locked.
    UserLocked,
    /// A user account was unlocked.
    UserUnlocked,
    /// A user account was deactivated.
    UserDeactivated,
    /// A user account was reactivated.
    UserReactivated,
    /// A user's password was set by an admin.
    UserPasswordSet,
    /// A user's admin flag was modified.
    UserAdminSet,
    /// A user's profile or state was updated through the unified patch strand.
    UserUpdated,
    /// An email address was added to a user account.
    UserEmailAdded,
    /// An email address was modified.
    UserEmailUpdated,
    /// An email address was removed from a user account.
    UserEmailRemoved,
    /// A browser or OAuth session was terminated.
    SessionTerminated,
    /// A registration token was created.
    RegistrationTokenCreated,
    /// A registration token was revoked.
    RegistrationTokenRevoked,
    /// Policy data was updated.
    PolicyDataUpdated,
    /// An upstream OAuth provider was modified.
    UpstreamProviderModified,
    /// An upstream OAuth link was created.
    UpstreamLinkCreated,
    /// An upstream OAuth link was updated.
    UpstreamLinkUpdated,
    /// An upstream OAuth link was deleted.
    UpstreamLinkDeleted,
    /// Localised metadata for an OAuth client was replaced.
    OAuthClientLocalizedMetadataUpdated,
    /// An operation not covered by the enumerated variants.
    Other(String),
}

/// A security event associated with a user account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSecurityEvent {
    /// Stable unique identifier for the event.
    pub id: Ulid,
    /// The user account this event relates to.
    pub user_id: Ulid,
    /// The type of security event.
    pub event_type: SecurityEventType,
    /// Structured event metadata.
    pub metadata: Value,
    /// Client IP address associated with the event.
    pub ip_address: Option<std::net::IpAddr>,
    /// User-agent string associated with the event.
    pub user_agent: Option<String>,
    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// A single immutable handle-history event. Companion type to
/// [`HandleAuditEventType`] (re-exported via [`HandleAuditRepository`]).
///
/// Rows persisted in `handle_audit_log` and surfaced unchanged through
/// [`HandleAuditRepository::list_for_user`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAuditEvent {
    /// Stable unique identifier for the audit entry.
    pub id: Ulid,
    /// Optional binding to a user record (NULL when the event covers a
    /// freshly revoked handle whose user row has been hard-deleted).
    pub user_id: Option<Ulid>,
    /// The kind of event recorded.
    pub event_type: HandleAuditEventType,
    /// Canonical `<localpart>:<domain>` handle affected by the event
    /// (spec 7157ee8 §3.1).
    pub handle: Option<String>,
    /// Interop aliases (e.g. `acct:<local>@<host>`) recorded with the event.
    pub handle_aliases: Vec<String>,
    /// Previous DID this handle resolved to (reassignment / divergence).
    pub old_did: Option<String>,
    /// New DID the handle resolves to as of this event.
    pub new_did: Option<String>,
    /// Issuer service DID that signed the affected claim, if any.
    pub issuer_service_id: Option<String>,
    /// Audience the affected claim was bound to.
    pub audience: Option<String>,
    /// `sha256:<hex>` digest of the canonical-JSON form of the emitted
    /// claim (audit chain anchor / cache key per §3.7.1).
    pub claim_digest: Option<String>,
    /// Free-form structured payload (reason text, ticket id, etc.).
    pub details: Value,
    /// Actor (admin / system component) that triggered the event, if any.
    pub actor_id: Option<Ulid>,
    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Types of security events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    /// A successful login.
    LoginSuccess,
    /// A failed login attempt.
    LoginFailed,
    /// A user changed their password.
    PasswordChanged,
    /// A password reset was requested.
    PasswordResetRequested,
    /// A password reset was completed.
    PasswordResetCompleted,
    /// An email address was verified.
    EmailVerified,
    /// A phone number was verified.
    PhoneVerified,
    /// A new session was created.
    SessionCreated,
    /// A session was terminated.
    SessionTerminated,
    /// The user account was locked.
    AccountLocked,
    /// The user account was deactivated.
    AccountDeactivated,
    /// An upstream provider was linked to the account.
    UpstreamLinked,
    /// An upstream provider was unlinked from the account.
    UpstreamUnlinked,
    /// The user was rate limited.
    RateLimited,
}
