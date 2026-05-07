// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use coauth_data::personal::{
    PersonalAccessToken as DataModelPersonalAccessToken,
    session::{PersonalSession as DataModelPersonalSession, PersonalSessionOwner},
};
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

// `Resource` lives in `coauth_admin_types::envelope` so admin DTOs and
// their wrappers stay in lock-step on both server and client. Re-exported
// here for the historical `crate::handlers::admin::model::Resource` path
// that existing handlers depend on.
pub use coauth_admin_types::Resource;

/// A user
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct User {
    #[serde(skip)]
    id: Ulid,

    /// The username (localpart) of the user
    username: String,

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

    /// Whether the user was a legacy guest during Matrix-era migration.
    legacy_guest: bool,

    /// Human-facing display name for the legacy compatibility data model.
    display_name: Option<String>,

    /// Optional avatar URL for the legacy compatibility data model.
    avatar_url: Option<String>,

    /// Preferred locale stored for this user.
    preferred_locale: Option<String>,
}

impl User {
    /// Samples of users with different properties for examples in the schema
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                updated_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                admin: false,
                legacy_guest: false,
                display_name: Some("Alice".to_owned()),
                avatar_url: None,
                preferred_locale: Some("zh-CN".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                username: "bob".to_owned(),
                created_at: DateTime::default(),
                updated_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                admin: true,
                legacy_guest: false,
                display_name: Some("Bob".to_owned()),
                avatar_url: Some("mxc://example.org/avatar".to_owned()),
                preferred_locale: Some("en".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                username: "charlie".to_owned(),
                created_at: DateTime::default(),
                updated_at: DateTime::default(),
                locked_at: Some(DateTime::default()),
                deactivated_at: None,
                admin: false,
                legacy_guest: true,
                display_name: None,
                avatar_url: None,
                preferred_locale: None,
            },
        ]
    }
}

impl From<coauth_data::User> for User {
    fn from(user: coauth_data::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            created_at: user.created_at,
            updated_at: user.updated_at,
            locked_at: user.locked_at,
            deactivated_at: user.deactivated_at,
            admin: user.can_request_admin,
            legacy_guest: user.is_guest,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            preferred_locale: user.preferred_locale,
        }
    }
}

impl Resource for User {
    const KIND: &'static str = "user";
    const PATH: &'static str = "/api/admin/v1/users";

    fn id(&self) -> Ulid {
        self.id
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
    const PATH: &'static str = "/api/admin/v1/user-emails";

    fn id(&self) -> Ulid {
        self.id
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

impl UserEmail {
    pub fn samples() -> [Self; 1] {
        [Self {
            id: Ulid::from_bytes([0x01; 16]),
            created_at: DateTime::default(),
            updated_at: DateTime::default(),
            user_id: Ulid::from_bytes([0x02; 16]),
            email: "alice@example.com".to_owned(),
            confirmed_at: Some(DateTime::default()),
            is_primary: true,
        }]
    }
}

/// A OAuth 2.0 session
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct OAuth2Session {
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

impl From<coauth_data::Session> for OAuth2Session {
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

impl OAuth2Session {
    /// Samples of OAuth 2.0 sessions
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Some(Ulid::from_bytes([0x02; 16])),
                user_session_id: Some(Ulid::from_bytes([0x03; 16])),
                client_id: Ulid::from_bytes([0x04; 16]),
                scope: "openid".to_owned(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
                human_name: Some("Laptop".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: None,
                user_session_id: None,
                client_id: Ulid::from_bytes([0x05; 16]),
                scope: "urn:coauth:admin".to_owned(),
                user_agent: None,
                last_active_at: None,
                last_active_ip: None,
                human_name: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                finished_at: Some(DateTime::default()),
                user_id: Some(Ulid::from_bytes([0x04; 16])),
                user_session_id: Some(Ulid::from_bytes([0x05; 16])),
                client_id: Ulid::from_bytes([0x06; 16]),
                scope: "urn:contrix:admin:session".to_owned(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
                human_name: None,
            },
        ]
    }
}

impl Resource for OAuth2Session {
    const KIND: &'static str = "oauth2-session";
    const PATH: &'static str = "/api/admin/v1/oauth2-sessions";

    fn id(&self) -> Ulid {
        self.id
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

impl UserSession {
    /// Samples of user sessions
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Ulid::from_bytes([0x02; 16]),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Ulid::from_bytes([0x03; 16]),
                user_agent: None,
                last_active_at: None,
                last_active_ip: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                finished_at: Some(DateTime::default()),
                user_id: Ulid::from_bytes([0x04; 16]),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
            },
        ]
    }
}

impl Resource for UserSession {
    const KIND: &'static str = "user-session";
    const PATH: &'static str = "/api/admin/v1/user-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}

/// An upstream OAuth 2.0 link
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
    const PATH: &'static str = "/api/admin/v1/upstream-oauth-links";

    fn id(&self) -> Ulid {
        self.id
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

impl UpstreamOAuthLink {
    /// Samples of upstream OAuth 2.0 links
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                updated_at: DateTime::default(),
                provider_id: Ulid::from_bytes([0x02; 16]),
                subject: "john-42".to_owned(),
                user_id: Some(Ulid::from_bytes([0x03; 16])),
                human_account_name: Some("john.doe@example.com".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                updated_at: DateTime::default(),
                provider_id: Ulid::from_bytes([0x03; 16]),
                subject: "jane-123".to_owned(),
                user_id: None,
                human_account_name: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                updated_at: DateTime::default(),
                provider_id: Ulid::from_bytes([0x04; 16]),
                subject: "bob@social.example.com".to_owned(),
                user_id: Some(Ulid::from_bytes([0x05; 16])),
                human_account_name: Some("bob".to_owned()),
            },
        ]
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
    const PATH: &'static str = "/api/admin/v1/policy-data";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl PolicyData {
    /// Samples of policy data
    pub fn samples() -> [Self; 1] {
        [Self {
            id: Ulid::from_bytes([0x01; 16]),
            created_at: DateTime::default(),
            data: serde_json::json!({
                "hello": "world",
                "foo": 42,
                "bar": true
            }),
        }]
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
    const PATH: &'static str = "/api/admin/v1/user-registration-tokens";

    fn id(&self) -> Ulid {
        self.id
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

/// An upstream OAuth 2.0 provider
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
    const PATH: &'static str = "/api/admin/v1/upstream-oauth-providers";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl UpstreamOAuthProvider {
    /// Samples of upstream OAuth 2.0 providers
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                issuer: Some("https://accounts.google.com".to_owned()),
                human_name: Some("Google".to_owned()),
                brand_name: Some("google".to_owned()),
                created_at: DateTime::default(),
                disabled_at: None,
                source: "config".to_owned(),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                issuer: Some("https://appleid.apple.com".to_owned()),
                human_name: Some("Apple ID".to_owned()),
                brand_name: Some("apple".to_owned()),
                created_at: DateTime::default(),
                disabled_at: Some(DateTime::default()),
                source: "config".to_owned(),
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                issuer: None,
                human_name: Some("Custom OAuth Provider".to_owned()),
                brand_name: None,
                created_at: DateTime::default(),
                disabled_at: None,
                source: "manual".to_owned(),
            },
        ]
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

    /// The ID of the `OAuth2` client that owns this session (if client-owned)
    #[schemars(with = "Option<super::schema::Ulid>")]
    owner_client_id: Option<Ulid>,

    /// The ID of the user that the session acts on behalf of
    #[schemars(with = "super::schema::Ulid")]
    actor_user_id: Ulid,

    /// Human-readable name for the session
    human_name: String,

    /// `OAuth2` scopes for this session
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
            PersonalSessionOwner::OAuth2Client(id) => (None, Some(id)),
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
    const PATH: &'static str = "/api/admin/v1/personal-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl PersonalSession {
    /// Sample personal sessions for documentation/testing
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_string("01FSHN9AG0AJ6AC5HQ9X6H4RP4").unwrap(),
                created_at: DateTime::from_timestamp(1_642_338_000, 0).unwrap(), /* 2022-01-16T14:
                                                                                  * 40:00Z */
                revoked_at: None,
                owner_user_id: Some(Ulid::from_string("01FSHN9AG0MZAA6S4AF7CTV32E").unwrap()),
                owner_client_id: None,
                actor_user_id: Ulid::from_string("01FSHN9AG0MZAA6S4AF7CTV32E").unwrap(),
                human_name: "Alice's Development Token".to_owned(),
                scope: "openid urn:coauth:admin".to_owned(),
                last_active_at: Some(DateTime::from_timestamp(1_642_347_000, 0).unwrap()), /* 2022-01-16T17:10:00Z */
                last_active_ip: Some("192.168.1.100".parse().unwrap()),
                expires_at: None,
                access_token: None,
            },
            Self {
                id: Ulid::from_string("01FSHN9AG0BJ6AC5HQ9X6H4RP5").unwrap(),
                created_at: DateTime::from_timestamp(1_642_338_060, 0).unwrap(), /* 2022-01-16T14:
                                                                                  * 41:00Z */
                revoked_at: Some(DateTime::from_timestamp(1_642_350_000, 0).unwrap()), /* 2022-01-16T18:00:00Z */
                owner_user_id: Some(Ulid::from_string("01FSHN9AG0NZAA6S4AF7CTV32F").unwrap()),
                owner_client_id: None,
                actor_user_id: Ulid::from_string("01FSHN9AG0NZAA6S4AF7CTV32F").unwrap(),
                human_name: "Bob's Mobile App".to_owned(),
                scope: "openid".to_owned(),
                last_active_at: Some(DateTime::from_timestamp(1_642_349_000, 0).unwrap()), /* 2022-01-16T17:43:20Z */
                last_active_ip: Some("10.0.0.50".parse().unwrap()),
                expires_at: None,
                access_token: None,
            },
            Self {
                id: Ulid::from_string("01FSHN9AG0CJ6AC5HQ9X6H4RP6").unwrap(),
                created_at: DateTime::from_timestamp(1_642_338_120, 0).unwrap(), /* 2022-01-16T14:
                                                                                  * 42:00Z */
                revoked_at: None,
                owner_user_id: None,
                owner_client_id: Some(Ulid::from_string("01FSHN9AG0DJ6AC5HQ9X6H4RP7").unwrap()),
                actor_user_id: Ulid::from_string("01FSHN9AG0MZAA6S4AF7CTV32E").unwrap(),
                human_name: "CI/CD Pipeline Token".to_owned(),
                scope: "openid urn:coauth:admin".to_owned(),
                last_active_at: Some(DateTime::from_timestamp(1_642_348_000, 0).unwrap()), /* 2022-01-16T17:26:40Z */
                last_active_ip: Some("203.0.113.10".parse().unwrap()),
                expires_at: Some(DateTime::from_timestamp(1_642_999_000, 0).unwrap()),
                access_token: None,
            },
        ]
    }

    /// Add the actual token value (for use in creation responses)
    pub fn with_token(mut self, access_token: String) -> Self {
        self.access_token = Some(access_token);
        self
    }
}
