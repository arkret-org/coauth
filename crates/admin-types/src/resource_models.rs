use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Resource;

macro_rules! impl_resource {
    ($type:ty, $kind:literal, $path:literal) => {
        impl Resource for $type {
            const KIND: &'static str = $kind;
            const PATH: &'static str = $path;

            fn id(&self) -> String {
                self.id.clone()
            }
        }
    };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct UserEmail {
    #[serde(skip)]
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: String,
    pub email: String,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub is_primary: bool,
}

impl_resource!(UserEmail, "user-email", "/_coauth/admin/user-emails");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct OAuthSession {
    #[serde(skip)]
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub user_id: Option<String>,
    pub user_session_id: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
    pub human_name: Option<String>,
}

impl_resource!(
    OAuthSession,
    "oauth-session",
    "/_coauth/admin/oauth-sessions"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct UserSession {
    #[serde(skip)]
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub user_id: String,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl_resource!(UserSession, "user-session", "/_coauth/admin/user-sessions");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct UpstreamOAuthLink {
    #[serde(skip)]
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub provider_id: String,
    pub subject: String,
    pub user_id: Option<String>,
    pub human_account_name: Option<String>,
}

impl_resource!(
    UpstreamOAuthLink,
    "upstream-oauth-link",
    "/_coauth/admin/upstream-oauth-links"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct UserRegistrationToken {
    #[serde(skip)]
    pub id: String,
    pub token: String,
    pub valid: bool,
    pub usage_limit: Option<u32>,
    pub times_used: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl_resource!(
    UserRegistrationToken,
    "user-registration_token",
    "/_coauth/admin/user-registration-tokens"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct UpstreamOAuthProvider {
    #[serde(skip)]
    pub id: String,
    pub oidc_issuer_uri: Option<String>,
    pub human_name: Option<String>,
    pub brand_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub source: String,
}

impl_resource!(
    UpstreamOAuthProvider,
    "upstream-oauth-provider",
    "/_coauth/admin/upstream-oauth-providers"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct PersonalSession {
    #[serde(skip)]
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub owner_user_id: Option<String>,
    pub owner_client_id: Option<String>,
    pub actor_user_id: String,
    pub human_name: String,
    pub scope: String,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

impl PersonalSession {
    pub fn with_token(mut self, access_token: String) -> Self {
        self.access_token = Some(access_token);
        self
    }
}

impl_resource!(
    PersonalSession,
    "personal-session",
    "/_coauth/admin/personal-sessions"
);
