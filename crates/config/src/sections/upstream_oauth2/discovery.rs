// ── Discovery, PKCE, and Backchannel Logout Configuration ──
//
// Enumerations that control how the application discovers provider
// metadata, handles PKCE, and responds to backchannel logout signals.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Discovery Mode ──

/// Determines how the provider's endpoints and metadata are discovered
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// Use OIDC discovery with strict metadata verification
    #[default]
    Oidc,

    /// Use OIDC discovery with relaxed metadata verification
    Insecure,

    /// Use a static configuration (no discovery)
    Disabled,
}

impl DiscoveryMode {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) const fn is_default(&self) -> bool {
        matches!(self, Self::Oidc)
    }
}

// ── PKCE Method ──

/// Controls whether Proof Key for Code Exchange is used during the
/// authorization code flow
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PkceMethod {
    /// Use PKCE if the provider supports it.
    ///
    /// Falls back to no PKCE when provider discovery is disabled.
    #[default]
    Auto,

    /// Always use PKCE with the S256 challenge method
    Always,

    /// Never use PKCE
    Never,
}

impl PkceMethod {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) const fn is_default(&self) -> bool {
        matches!(self, Self::Auto)
    }
}

// ── Backchannel Logout ──

/// Determines the server's response to an OIDC Backchannel logout
/// notification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnBackchannelLogout {
    /// Take no action
    #[default]
    DoNothing,

    /// Only log out the Pasion 'browser session' started by this OIDC session
    LogoutBrowserOnly,

    /// Log out all sessions started by this OIDC session, including Pasion
    /// 'browser sessions' and client sessions
    LogoutAll,
}

impl OnBackchannelLogout {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) const fn is_default(&self) -> bool {
        matches!(self, Self::DoNothing)
    }
}
