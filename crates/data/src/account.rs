use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Ulid;
pub use crate::{pg::account::PgAccountRepository, storage::account::*};

/// A unified contact point associated with a user account.
///
/// This abstraction unifies email addresses and phone numbers under a single
/// domain concept, making it easier to reason about "how to reach a user"
/// regardless of channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountContactPoint {
    pub id: Ulid,
    /// The user this contact point belongs to.
    pub user_id: Ulid,
    /// The channel type for this contact point.
    pub channel: ContactChannel,
    /// The contact value (email address or phone number).
    pub value: String,
    /// Whether this contact point has been verified.
    pub verified: bool,
    /// When verification was completed, if applicable.
    pub verified_at: Option<DateTime<Utc>>,
    /// Whether this is the user's primary contact for this channel.
    pub is_primary: bool,
    /// When this contact point was created.
    pub created_at: DateTime<Utc>,
}

/// Channel type for a contact point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactChannel {
    Email,
    Phone,
}

/// A binding between a user account and an external identity.
///
/// This represents the link between a Pasion user and an identity in an
/// external system (e.g., an upstream OAuth provider, a Matrix homeserver,
/// or a directory service).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountIdentityBinding {
    pub id: Ulid,
    /// The local user account.
    pub user_id: Ulid,
    /// The type of external identity provider.
    pub provider_type: IdentityProviderType,
    /// The provider-specific identifier (e.g., provider ULID, connector name).
    pub provider_id: String,
    /// The subject identifier at the external provider.
    pub external_subject: String,
    /// Optional human-readable account name at the provider.
    pub external_display_name: Option<String>,
    /// Optional structured metadata about the binding.
    pub metadata: Value,
    /// When this binding was established.
    pub created_at: DateTime<Utc>,
    /// When the binding was last used for authentication.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Type of external identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProviderType {
    /// An upstream OAuth2/OIDC provider.
    UpstreamOAuth2,
    /// The connected Matrix homeserver (Palpo).
    MatrixHomeserver,
    /// An LDAP or directory service.
    Directory,
    /// A SAML identity provider.
    Saml,
}
