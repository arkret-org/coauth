use chrono::{DateTime, Utc};
use coauth_iana::jose::JsonWebSignatureAlg;
use oauth2_types::scope::Scope;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    /// Use OIDC discovery to fetch and verify the provider metadata
    #[default]
    Oidc,

    /// Use OIDC discovery to fetch the provider metadata, but don't verify it
    Insecure,

    /// Don't fetch the provider metadata
    Disabled,
}

impl DiscoveryMode {
    /// Returns `true` if discovery is disabled
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        matches!(self, DiscoveryMode::Disabled)
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid discovery mode {0:?}")]
pub struct InvalidDiscoveryModeError(String);

impl std::str::FromStr for DiscoveryMode {
    type Err = InvalidDiscoveryModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(Self::Oidc),
            "insecure" => Ok(Self::Insecure),
            "disabled" => Ok(Self::Disabled),
            s => Err(InvalidDiscoveryModeError(s.to_owned())),
        }
    }
}

impl DiscoveryMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Insecure => "insecure",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for DiscoveryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PkceMode {
    /// Use PKCE if the provider supports it
    #[default]
    Auto,

    /// Always use PKCE with the S256 method
    S256,

    /// Don't use PKCE
    Disabled,
}

#[derive(Debug, Clone, Error)]
#[error("Invalid PKCE mode {0:?}")]
pub struct InvalidPkceModeError(String);

impl std::str::FromStr for PkceMode {
    type Err = InvalidPkceModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "s256" => Ok(Self::S256),
            "disabled" => Ok(Self::Disabled),
            s => Err(InvalidPkceModeError(s.to_owned())),
        }
    }
}

impl PkceMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::S256 => "s256",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for PkceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Pasion-original: response mode for the upstream OAuth 2.0 authorization
/// request.
#[derive(Debug, Clone, Error)]
#[error("Invalid response mode {0:?}")]
pub struct InvalidResponseModeError(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    #[default]
    Query,
    FormPost,
}

impl From<ResponseMode> for oauth2_types::requests::ResponseMode {
    fn from(value: ResponseMode) -> Self {
        match value {
            ResponseMode::Query => oauth2_types::requests::ResponseMode::Query,
            ResponseMode::FormPost => oauth2_types::requests::ResponseMode::FormPost,
        }
    }
}

impl ResponseMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ResponseMode {
    type Err = InvalidResponseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(ResponseMode::Query),
            "form_post" => Ok(ResponseMode::FormPost),
            s => Err(InvalidResponseModeError(s.to_owned())),
        }
    }
}

/// Pasion-original: token endpoint authentication method for upstream
/// providers.
///
/// Extends the standard OAuth methods with platform-specific variants for
/// Chinese social login providers and Apple Sign-In.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    SignInWithApple,
    QQConnect,
    Feishu,
    Lark,
    DingTalk,
    WeChat,
    WeCom,
}

impl TokenAuthMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::SignInWithApple => "sign_in_with_apple",
            Self::QQConnect => "qq_connect",
            Self::Feishu => "feishu",
            Self::Lark => "lark",
            Self::DingTalk => "dingtalk",
            Self::WeChat => "wechat",
            Self::WeCom => "wecom",
        }
    }
}

impl std::fmt::Display for TokenAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TokenAuthMethod {
    type Err = InvalidUpstreamOAuth2TokenAuthMethod;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_jwt" => Ok(Self::ClientSecretJwt),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "sign_in_with_apple" => Ok(Self::SignInWithApple),
            "qq_connect" => Ok(Self::QQConnect),
            "feishu" => Ok(Self::Feishu),
            "lark" => Ok(Self::Lark),
            "dingtalk" => Ok(Self::DingTalk),
            "wechat" => Ok(Self::WeChat),
            "wecom" => Ok(Self::WeCom),
            s => Err(InvalidUpstreamOAuth2TokenAuthMethod(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid upstream OAuth 2.0 token auth method: {0}")]
pub struct InvalidUpstreamOAuth2TokenAuthMethod(String);

/// Pasion-original: behaviour on receiving a backchannel logout from an
/// upstream provider.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnBackchannelLogout {
    DoNothing,
    LogoutBrowserOnly,
    LogoutAll,
}

impl OnBackchannelLogout {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoNothing => "do_nothing",
            Self::LogoutBrowserOnly => "logout_browser_only",
            Self::LogoutAll => "logout_all",
        }
    }
}

impl std::fmt::Display for OnBackchannelLogout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for OnBackchannelLogout {
    type Err = InvalidUpstreamOAuth2OnBackchannelLogout;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "do_nothing" => Ok(Self::DoNothing),
            "logout_browser_only" => Ok(Self::LogoutBrowserOnly),
            "logout_all" => Ok(Self::LogoutAll),
            s => Err(InvalidUpstreamOAuth2OnBackchannelLogout(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid upstream OAuth 2.0 'on backchannel logout': {0}")]
pub struct InvalidUpstreamOAuth2OnBackchannelLogout(String);

/// The origin of an upstream OAuth provider row.
///
/// Distinguishes rows seeded by `coauth config sync` from rows created via
/// the admin REST API. The two are managed by mutually exclusive code paths so
/// that one cannot silently undo the other across restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProviderSource {
    /// Created/maintained by the configuration file via `config_sync`.
    #[default]
    Config,
    /// Created/maintained by the admin REST API.
    Manual,
}

impl ProviderSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Manual => "manual",
        }
    }
}

impl std::fmt::Display for ProviderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid upstream OAuth provider source {0:?}")]
pub struct InvalidProviderSourceError(String);

impl std::str::FromStr for ProviderSource {
    type Err = InvalidProviderSourceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "config" => Ok(Self::Config),
            "manual" => Ok(Self::Manual),
            s => Err(InvalidProviderSourceError(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthProvider {
    pub id: Ulid,
    /// Pasion-original: `issuer` is Optional (for non-OIDC providers)
    pub issuer: Option<String>,
    pub human_name: Option<String>,
    pub brand_name: Option<String>,
    pub discovery_mode: DiscoveryMode,
    pub pkce_mode: PkceMode,
    pub jwks_uri_override: Option<Url>,
    pub authorization_endpoint_override: Option<Url>,
    pub scope: Scope,
    pub token_endpoint_override: Option<Url>,
    /// Pasion-original: allow overriding the userinfo endpoint
    pub userinfo_endpoint_override: Option<Url>,
    /// Pasion-original: whether to fetch userinfo from the upstream
    pub fetch_userinfo: bool,
    /// Pasion-original: signing alg for userinfo responses
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
    pub client_id: String,
    pub encrypted_client_secret: Option<String>,
    pub token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,
    /// Pasion-original: uses custom `TokenAuthMethod` enum instead of
    /// `OAuthClientAuthenticationMethod`
    pub token_endpoint_auth_method: TokenAuthMethod,
    /// Pasion-original: expected signing algorithm for ID tokens
    pub id_token_signed_response_alg: JsonWebSignatureAlg,
    /// Pasion-original: response mode for the authorization request
    pub response_mode: Option<ResponseMode>,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub claims_imports: ClaimsImports,
    pub additional_authorization_parameters: Vec<(String, String)>,
    /// Pasion-original: whether to forward the login_hint parameter
    pub forward_login_hint: bool,
    /// Pasion-original: backchannel logout behaviour
    pub on_backchannel_logout: OnBackchannelLogout,
    /// Where the row originated (config file vs admin API).
    pub source: ProviderSource,
}

impl PartialOrd for UpstreamOAuthProvider {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UpstreamOAuthProvider {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl UpstreamOAuthProvider {
    /// Returns `true` if the provider is enabled
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.disabled_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClaimsImports {
    #[serde(default)]
    pub subject: SubjectPreference,

    /// Pasion-original: whether to skip the confirmation step
    #[serde(default)]
    pub skip_confirmation: bool,

    #[serde(default)]
    pub username: UsernamePreference,

    #[serde(default)]
    pub displayname: ImportPreference,

    #[serde(default)]
    pub email: ImportPreference,

    #[serde(default)]
    pub avatar: ImportPreference,

    /// Pasion-original: template for computing a human-readable account name
    #[serde(default)]
    pub account_name: SubjectPreference,
}

/// Template-based preference used by simple subject/display-name claim
/// imports. The type is deliberately minimal — just an optional template
/// string — so it can be shared by every field that doesn't need conflict
/// resolution (see [`UsernamePreference`] below for the richer variant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubjectPreference {
    #[serde(default)]
    pub template: Option<String>,
}

/// Pasion-original: username preference with conflict-resolution strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UsernamePreference {
    #[serde(default)]
    pub action: ImportAction,

    #[serde(default)]
    pub template: Option<String>,

    #[serde(default)]
    pub on_conflict: OnConflict,
}

impl std::ops::Deref for UsernamePreference {
    type Target = ImportAction;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportPreference {
    #[serde(default)]
    pub action: ImportAction,

    #[serde(default)]
    pub template: Option<String>,
}

impl std::ops::Deref for ImportPreference {
    type Target = ImportAction;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ImportAction {
    /// Ignore the claim
    #[default]
    Ignore,

    /// Suggest the claim value, but allow the user to change it
    Suggest,

    /// Force the claim value, but don't fail if it is missing
    Force,

    /// Force the claim value, and fail if it is missing
    Require,
}

impl ImportAction {
    #[must_use]
    pub fn is_forced_or_required(&self) -> bool {
        matches!(self, Self::Force | Self::Require)
    }

    #[must_use]
    pub fn ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }

    #[must_use]
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Require)
    }

    #[must_use]
    pub fn should_import(&self, user_preference: bool) -> bool {
        match self {
            Self::Ignore => false,
            Self::Suggest => user_preference,
            Self::Force | Self::Require => true,
        }
    }
}

/// Pasion-original: conflict-resolution strategy for upstream username
/// imports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnConflict {
    /// Fails the upstream OAuth 2.0 login on conflict
    #[default]
    Fail,

    /// Adds the upstream OAuth 2.0 identity link, regardless of whether there
    /// is an existing link or not
    Add,

    /// Replace any existing upstream OAuth 2.0 identity link
    Replace,

    /// Adds the upstream OAuth 2.0 identity link *only* if there is no existing
    /// link for this provider on the matching user
    Set,
}
