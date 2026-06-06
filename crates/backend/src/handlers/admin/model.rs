// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use chrono::{DateTime, Utc};
pub use coauth_admin_types::Resource;
use coauth_data::personal::{
    PersonalAccessToken as DataModelPersonalAccessToken,
    session::{PersonalSession as DataModelPersonalSession, PersonalSessionOwner},
};
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;

/// A user
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct User {
    #[serde(skip)]
    id: Ulid,

    /// The handle of the user.
    handle: String,

    /// When the user was created
    created_at: DateTime<Utc>,

    /// When the user was last updated through the local account model.
    updated_at: DateTime<Utc>,

    /// When the user was locked. If null, the user is not locked.
    locked_at: Option<DateTime<Utc>>,

    /// When the user was deactivated. If null, the user is not deactivated.
    deactivated_at: Option<DateTime<Utc>>,

    /// Whether the user can request admin privileges.
    admin: bool,

    /// Human-facing display name.
    display_name: Option<String>,

    /// Optional avatar URL.
    avatar_url: Option<String>,

    /// Preferred locale stored for this user.
    preferred_locale: Option<String>,
}

impl From<coauth_data::User> for User {
    fn from(user: coauth_data::User) -> Self {
        Self {
            id: user.id,
            handle: user.handle,
            created_at: user.created_at,
            updated_at: user.updated_at,
            locked_at: user.locked_at,
            deactivated_at: user.deactivated_at,
            admin: user.can_request_admin,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            preferred_locale: user.preferred_locale,
        }
    }
}

impl Resource for User {
    const KIND: &'static str = "user";
    const PATH: &'static str = "/_coauth/admin/users";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

/// An email address for a user
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct UserEmail {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the object was last updated
    updated_at: DateTime<Utc>,

    /// The ID of the user who owns this email address
    #[schemars(with = "super::schema::Ulid")]
    user_id: Ulid,

    /// The email address
    email: String,

    /// When the email was confirmed, if ever.
    confirmed_at: Option<DateTime<Utc>>,

    /// Whether this email is the primary email for the account.
    is_primary: bool,
}

impl Resource for UserEmail {
    const KIND: &'static str = "user-email";
    const PATH: &'static str = "/_coauth/admin/user-emails";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

impl From<coauth_data::UserEmail> for UserEmail {
    fn from(value: coauth_data::UserEmail) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            updated_at: value.updated_at,
            user_id: value.user_id,
            email: value.email,
            confirmed_at: value.confirmed_at,
            is_primary: value.is_primary,
        }
    }
}

/// A OAuth session
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct OAuthSession {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the session was finished
    finished_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns the session
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_id: Option<Ulid>,

    /// The ID of the browser session which started this session
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_session_id: Option<Ulid>,

    /// The ID of the client which requested this session
    #[schemars(with = "super::schema::Ulid")]
    client_id: Ulid,

    /// The scope granted for this session
    scope: String,

    /// The user agent string of the client which started this session
    user_agent: Option<String>,

    /// The last time the session was active
    last_active_at: Option<DateTime<Utc>>,

    /// The last IP address used by the session
    last_active_ip: Option<IpAddr>,

    /// The user-provided name, if any
    human_name: Option<String>,
}

impl From<coauth_data::Session> for OAuthSession {
    fn from(session: coauth_data::Session) -> Self {
        Self {
            id: session.id,
            created_at: session.created_at,
            finished_at: session.finished_at(),
            user_id: session.user_id,
            user_session_id: session.user_session_id,
            client_id: session.client_id,
            scope: session.scope.to_string(),
            user_agent: session.user_agent,
            last_active_at: session.last_active_at,
            last_active_ip: session.last_active_ip,
            human_name: session.human_name,
        }
    }
}

impl Resource for OAuthSession {
    const KIND: &'static str = "oauth-session";
    const PATH: &'static str = "/_coauth/admin/oauth-sessions";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

/// The browser (cookie) session for a user
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct UserSession {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the session was finished
    finished_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns the session
    #[schemars(with = "super::schema::Ulid")]
    user_id: Ulid,

    /// The user agent string of the client which started this session
    user_agent: Option<String>,

    /// The last time the session was active
    last_active_at: Option<DateTime<Utc>>,

    /// The last IP address used by the session
    last_active_ip: Option<IpAddr>,
}

impl From<coauth_data::BrowserSession> for UserSession {
    fn from(value: coauth_data::BrowserSession) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            finished_at: value.finished_at,
            user_id: value.user.id,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        }
    }
}

impl Resource for UserSession {
    const KIND: &'static str = "user-session";
    const PATH: &'static str = "/_coauth/admin/user-sessions";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

/// An upstream OAuth link
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct UpstreamOAuthLink {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the object was last updated
    updated_at: DateTime<Utc>,

    /// The ID of the provider
    #[schemars(with = "super::schema::Ulid")]
    provider_id: Ulid,

    /// The subject of the upstream account, unique per provider
    subject: String,

    /// The ID of the user who owns this link, if any
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_id: Option<Ulid>,

    /// A human-readable name of the upstream account
    human_account_name: Option<String>,
}

impl Resource for UpstreamOAuthLink {
    const KIND: &'static str = "upstream-oauth-link";
    const PATH: &'static str = "/_coauth/admin/upstream-oauth-links";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

impl From<coauth_data::UpstreamOAuthLink> for UpstreamOAuthLink {
    fn from(value: coauth_data::UpstreamOAuthLink) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            updated_at: value.updated_at,
            provider_id: value.provider_id,
            subject: value.subject,
            user_id: value.user_id,
            human_account_name: value.human_account_name,
        }
    }
}

/// The policy data
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PolicyData {
    #[serde(skip)]
    id: Ulid,

    /// The creation date of the policy data
    created_at: DateTime<Utc>,

    /// The policy data content
    data: serde_json::Value,
}

impl From<coauth_data::PolicyData> for PolicyData {
    fn from(policy_data: coauth_data::PolicyData) -> Self {
        Self {
            id: policy_data.id,
            created_at: policy_data.created_at,
            data: policy_data.data,
        }
    }
}

impl Resource for PolicyData {
    const KIND: &'static str = "policy-data";
    const PATH: &'static str = "/_coauth/admin/policy-data";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

/// A registration token
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct UserRegistrationToken {
    #[serde(skip)]
    id: Ulid,

    /// The token string
    token: String,

    /// Whether the token is valid
    valid: bool,

    /// Maximum number of times this token can be used
    usage_limit: Option<u32>,

    /// Number of times this token has been used
    times_used: u32,

    /// When the token was created
    created_at: DateTime<Utc>,

    /// When the token was last used. If null, the token has never been used.
    last_used_at: Option<DateTime<Utc>>,

    /// When the token expires. If null, the token never expires.
    expires_at: Option<DateTime<Utc>>,

    /// When the token was revoked. If null, the token is not revoked.
    revoked_at: Option<DateTime<Utc>>,
}

impl UserRegistrationToken {
    pub fn new(token: coauth_data::UserRegistrationToken, now: DateTime<Utc>) -> Self {
        Self {
            id: token.id,
            valid: token.is_valid(now),
            token: token.token,
            usage_limit: token.usage_limit,
            times_used: token.times_used,
            created_at: token.created_at,
            last_used_at: token.last_used_at,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
        }
    }
}

impl Resource for UserRegistrationToken {
    const KIND: &'static str = "user-registration_token";
    const PATH: &'static str = "/_coauth/admin/user-registration-tokens";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

impl UserRegistrationToken {
    /// Samples of registration tokens
    pub fn samples() -> [Self; 2] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                token: "abc123def456".to_owned(),
                valid: true,
                usage_limit: Some(10),
                times_used: 5,
                created_at: DateTime::default(),
                last_used_at: Some(DateTime::default()),
                expires_at: Some(DateTime::default() + chrono::Duration::days(30)),
                revoked_at: None,
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                token: "xyz789abc012".to_owned(),
                valid: false,
                usage_limit: None,
                times_used: 0,
                created_at: DateTime::default(),
                last_used_at: None,
                expires_at: None,
                revoked_at: Some(DateTime::default()),
            },
        ]
    }
}

/// An upstream OAuth provider
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct UpstreamOAuthProvider {
    #[serde(skip)]
    id: Ulid,

    /// The OIDC issuer of the provider
    issuer: Option<String>,

    /// A human-readable name for the provider
    human_name: Option<String>,

    /// A brand identifier, e.g. "apple" or "google"
    brand_name: Option<String>,

    /// When the provider was created
    created_at: DateTime<Utc>,

    /// When the provider was disabled. If null, the provider is enabled.
    disabled_at: Option<DateTime<Utc>>,

    /// Origin of this provider row.
    ///
    /// `"config"` rows are managed by `coauth config sync` (the configuration
    /// file is the source of truth) and the admin API will refuse to edit
    /// or hard-delete them. `"manual"` rows were created via the admin API
    /// and are fully mutable from there.
    source: String,
}

impl From<coauth_data::UpstreamOAuthProvider> for UpstreamOAuthProvider {
    fn from(provider: coauth_data::UpstreamOAuthProvider) -> Self {
        Self {
            id: provider.id,
            issuer: provider.issuer,
            human_name: provider.human_name,
            brand_name: provider.brand_name,
            created_at: provider.created_at,
            disabled_at: provider.disabled_at,
            source: provider.source.as_str().to_owned(),
        }
    }
}

impl Resource for UpstreamOAuthProvider {
    const KIND: &'static str = "upstream-oauth-provider";
    const PATH: &'static str = "/_coauth/admin/upstream-oauth-providers";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

/// An error that shouldn't happen in practice, but suggests database
/// inconsistency.
#[derive(Debug, Error)]
#[error(
    "personal session {session_id} in inconsistent state: not revoked but no valid access token"
)]
pub struct InconsistentPersonalSession {
    pub session_id: Ulid,
}

// Note: we don't expose a separate concept of personal access tokens to the
// admin API; we merge the relevant attributes into the personal session.
/// A personal session (session using personal access tokens)
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PersonalSession {
    #[serde(skip)]
    id: Ulid,

    /// When the session was created
    created_at: DateTime<Utc>,

    /// When the session was revoked, if applicable
    revoked_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns this session (if user-owned)
    #[schemars(with = "Option<super::schema::Ulid>")]
    owner_user_id: Option<Ulid>,

    /// The ID of the `OAuth` client that owns this session (if client-owned)
    #[schemars(with = "Option<super::schema::Ulid>")]
    owner_client_id: Option<Ulid>,

    /// The ID of the user that the session acts on behalf of
    #[schemars(with = "super::schema::Ulid")]
    actor_user_id: Ulid,

    /// Human-readable name for the session
    human_name: String,

    /// `OAuth` scopes for this session
    scope: String,

    /// When the session was last active
    last_active_at: Option<DateTime<Utc>>,

    /// IP address of last activity
    last_active_ip: Option<IpAddr>,

    /// When the current token for this session expires.
    /// The session will need to be regenerated, producing a new access token,
    /// after this time.
    /// None if the current token won't expire or if the session is revoked.
    expires_at: Option<DateTime<Utc>>,

    /// The actual access token (only returned on creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
}

impl
    TryFrom<(
        DataModelPersonalSession,
        Option<DataModelPersonalAccessToken>,
    )> for PersonalSession
{
    type Error = InconsistentPersonalSession;

    fn try_from(
        (session, token): (
            DataModelPersonalSession,
            Option<DataModelPersonalAccessToken>,
        ),
    ) -> Result<Self, InconsistentPersonalSession> {
        let expires_at = if let Some(token) = token {
            token.expires_at
        } else {
            if !session.is_revoked() {
                // No active token, but the session is not revoked.
                return Err(InconsistentPersonalSession {
                    session_id: session.id,
                });
            }
            None
        };

        let (owner_user_id, owner_client_id) = match session.owner {
            PersonalSessionOwner::User(id) => (Some(id), None),
            PersonalSessionOwner::OAuthClient(id) => (None, Some(id)),
        };

        Ok(Self {
            id: session.id,
            created_at: session.created_at,
            revoked_at: session.revoked_at(),
            owner_user_id,
            owner_client_id,
            actor_user_id: session.actor_user_id,
            human_name: session.human_name,
            scope: session.scope.to_string(),
            last_active_at: session.last_active_at,
            last_active_ip: session.last_active_ip,
            expires_at,
            // If relevant, the caller will populate using `with_token` afterwards.
            access_token: None,
        })
    }
}

impl Resource for PersonalSession {
    const KIND: &'static str = "personal-session";
    const PATH: &'static str = "/_coauth/admin/personal-sessions";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

impl PersonalSession {
    /// Add the actual token value (for use in creation responses)
    pub fn with_token(mut self, access_token: String) -> Self {
        self.access_token = Some(access_token);
        self
    }
}
