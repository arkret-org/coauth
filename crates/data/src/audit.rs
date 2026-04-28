use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Ulid;
pub use crate::{pg::audit::PgAuditRepository, storage::audit::*};

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
    /// A user's profile or state was updated through the unified patch flow.
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
    /// Localised metadata for an OAuth 2.0 client was replaced.
    OAuth2ClientLocalizedMetadataUpdated,
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
