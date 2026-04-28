use std::num::NonZeroU64;

use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::ConfigurationSection;

/// Five minutes expressed in microseconds -- the default token lifetime
const ACCESS_TOKEN_TTL_MICROS: i64 = 5 * 60 * 1_000_000;

fn default_access_token_ttl() -> Duration {
    Duration::microseconds(ACCESS_TOKEN_TTL_MICROS)
}

fn access_token_ttl_is_default(ttl: &Duration) -> bool {
    *ttl == default_access_token_ttl()
}

fn default_bool_true() -> bool {
    true
}

/// Tuning options for automatic expiration of idle sessions
#[serde_as]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct InactiveSessionExpirationConfig {
    /// Duration (in seconds) after which an idle session is terminated
    #[schemars(with = "u64", range(min = 600, max = 7_776_000))]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub ttl: Duration,

    /// Apply the inactivity timeout to OAuth 2.0 sessions
    #[serde(default = "default_bool_true")]
    pub expire_oauth_sessions: bool,

    /// Apply the inactivity timeout to browser (user) sessions
    #[serde(default = "default_bool_true")]
    pub expire_user_sessions: bool,
}

/// Hard and soft caps on the number of active sessions per user
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SessionLimitConfig {
    pub soft_limit: NonZeroU64,
    pub hard_limit: NonZeroU64,
}

/// Experimental feature flags -- change at your own risk
#[serde_as]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct ExperimentalConfig {
    /// Lifetime of access tokens (seconds). Default: 300 (5 min).
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_access_token_ttl",
        skip_serializing_if = "access_token_ttl_is_default"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub access_token_ttl: Duration,

    /// Opt-in automatic expiration of sessions that have been idle
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive_session_expiration: Option<InactiveSessionExpirationConfig>,

    /// URI for an embeddable plan-management interface (forwarded to the
    /// client verbatim without validation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_management_iframe_uri: Option<String>,

    /// Limit the total number of concurrent application sessions per user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_limit: Option<SessionLimitConfig>,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: default_access_token_ttl(),
            inactive_session_expiration: None,
            plan_management_iframe_uri: None,
            session_limit: None,
        }
    }
}

impl ExperimentalConfig {
    pub(crate) fn is_default(&self) -> bool {
        access_token_ttl_is_default(&self.access_token_ttl)
            && self.inactive_session_expiration.is_none()
            && self.plan_management_iframe_uri.is_none()
            && self.session_limit.is_none()
    }
}

impl ConfigurationSection for ExperimentalConfig {
    const PATH: &'static str = "experimental";
}
