// ── Provider Configuration ──
//
// Defines the full configuration for a single upstream OAuth 2.0 / OIDC
// provider, including authentication methods and endpoint overrides.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use coauth_iana::jose::JsonWebSignatureAlg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use ulid::Ulid;
use url::Url;

use super::{
    claims::ClaimsImports,
    discovery::{DiscoveryMode, OnBackchannelLogout, PkceMethod},
};
use crate::{ClientSecret, ClientSecretRaw};

// ── Response Mode ──

/// Specifies how the authorization server delivers the response back to
/// the relying party
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// The provider sends the response as URL query parameters
    Query,

    /// The provider sends the response via an HTML form POST
    ///
    /// See <https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html>
    FormPost,
}

// ── Token Auth Method ──

/// Supported authentication methods for the upstream token endpoint
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    /// `none`: No client authentication
    None,

    /// `client_secret_basic`: HTTP Basic auth with client_id and client_secret
    ClientSecretBasic,

    /// `client_secret_post`: client_id and client_secret in the POST body
    ClientSecretPost,

    /// `client_secret_jwt`: signed client_assertion using the client_secret
    ClientSecretJwt,

    /// `private_key_jwt`: signed client_assertion using an asymmetric key
    PrivateKeyJwt,

    /// `sign_in_with_apple`: Apple-specific authentication flow
    SignInWithApple,

    /// `qq_connect`: QQ Connect OAuth2 flow
    QQConnect,

    /// `feishu`: Feishu (Lark China) OAuth2 flow
    Feishu,

    /// `lark`: Lark (international Feishu) OAuth2 flow
    Lark,

    /// `dingtalk`: DingTalk OAuth2 flow
    DingTalk,

    /// `wechat`: WeChat Open Platform OAuth2 flow
    WeChat,

    /// `wecom`: WeCom (Enterprise WeChat) OAuth2 flow
    WeCom,
}

// ── Sign In With Apple ──

/// Additional parameters required for Apple's authentication flow
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignInWithApple {
    /// The private key file used to sign the `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub private_key_file: Option<Utf8PathBuf>,

    /// The private key used to sign the `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// The Team ID of the Apple Developer Portal
    pub team_id: String,

    /// The key ID of the Apple Developer Portal
    pub key_id: String,
}

// ── Default Value Helpers ──

fn default_enabled() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_enabled_default(value: &bool) -> bool {
    *value
}

fn default_scope() -> String {
    "openid".to_owned()
}

fn is_default_scope(scope: &str) -> bool {
    scope == "openid"
}

#[allow(clippy::ref_option)]
fn is_signed_response_alg_default(alg: &JsonWebSignatureAlg) -> bool {
    *alg == signed_response_alg_default()
}

#[allow(clippy::unnecessary_wraps)]
fn signed_response_alg_default() -> JsonWebSignatureAlg {
    JsonWebSignatureAlg::Rs256
}

// ── Provider Struct ──

/// Full configuration for a single upstream OAuth 2.0 / OIDC provider
#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Provider {
    /// Whether this provider is enabled.
    ///
    /// Defaults to `true`
    #[serde(
        default = "default_enabled",
        skip_serializing_if = "is_enabled_default"
    )]
    pub enabled: bool,

    /// An internal unique identifier for this provider
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A ULID as per https://github.com/ulid/spec"
    )]
    pub id: Ulid,

    /// The ID of the provider that was used by Palpo.
    /// In order to perform a Palpo migration migration, this must be specified.
    ///
    /// ## For providers that used OAuth 2.0 or OpenID Connect in Palpo
    ///
    /// ### For `oidc_providers`:
    /// This should be specified as `oidc-` followed by the ID that was
    /// configured as `idp_id` in one of the `oidc_providers` in the Palpo
    /// configuration.
    /// For example, if Palpo's configuration contained `idp_id: wombat` for
    /// this provider, then specify `oidc-wombat` here.
    ///
    /// ### For `oidc_config` (legacy):
    /// Specify `oidc` here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub palpo_idp_id: Option<String>,

    /// The OIDC issuer URL
    ///
    /// This is required if OIDC discovery is enabled (which is the default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// A human-readable name for the provider, that will be shown to users
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_name: Option<String>,

    /// A brand identifier used to customise the UI, e.g. `apple`, `google`,
    /// `github`, etc.
    ///
    /// Values supported by the default template are:
    ///
    ///  - `apple`
    ///  - `google`
    ///  - `facebook`
    ///  - `github`
    ///  - `gitlab`
    ///  - `twitter`
    ///  - `discord`
    ///  - `qq`
    ///  - `feishu`
    ///  - `lark`
    ///  - `dingtalk`
    ///  - `wechat`
    ///  - `wecom`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand_name: Option<String>,

    /// The client ID to use when authenticating with the provider
    pub client_id: String,

    /// The client secret to use when authenticating with the provider
    ///
    /// Used by the `client_secret_basic`, `client_secret_post`, and
    /// `client_secret_jwt` methods
    #[schemars(with = "ClientSecretRaw")]
    #[serde_as(as = "serde_with::TryFromInto<ClientSecretRaw>")]
    #[serde(flatten)]
    pub client_secret: Option<ClientSecret>,

    /// The method to authenticate the client with the provider
    pub token_endpoint_auth_method: TokenAuthMethod,

    /// Additional parameters for the `sign_in_with_apple` method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_with_apple: Option<SignInWithApple>,

    /// The JWS algorithm to use when authenticating the client with the
    /// provider
    ///
    /// Used by the `client_secret_jwt` and `private_key_jwt` methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// Expected signature for the JWT payload returned by the token
    /// authentication endpoint.
    ///
    /// Defaults to `RS256`.
    #[serde(
        default = "signed_response_alg_default",
        skip_serializing_if = "is_signed_response_alg_default"
    )]
    pub id_token_signed_response_alg: JsonWebSignatureAlg,

    /// The scopes to request from the provider
    ///
    /// Defaults to `openid`.
    #[serde(default = "default_scope", skip_serializing_if = "is_default_scope")]
    pub scope: String,

    /// How to discover the provider's configuration
    ///
    /// Defaults to `oidc`, which uses OIDC discovery with strict metadata
    /// verification
    #[serde(default, skip_serializing_if = "DiscoveryMode::is_default")]
    pub discovery_mode: DiscoveryMode,

    /// Whether to use proof key for code exchange (PKCE) when requesting and
    /// exchanging the token.
    ///
    /// Defaults to `auto`, which uses PKCE if the provider supports it.
    #[serde(default, skip_serializing_if = "PkceMethod::is_default")]
    pub pkce_method: PkceMethod,

    /// Whether to fetch the user profile from the userinfo endpoint,
    /// or to rely on the data returned in the `id_token` from the
    /// `token_endpoint`.
    ///
    /// Defaults to `false`.
    #[serde(default)]
    pub fetch_userinfo: bool,

    /// Expected signature for the JWT payload returned by the userinfo
    /// endpoint.
    ///
    /// If not specified, the response is expected to be an unsigned JSON
    /// payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// The URL to use for the provider's authorization endpoint
    ///
    /// Defaults to the `authorization_endpoint` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<Url>,

    /// The URL to use for the provider's userinfo endpoint
    ///
    /// Defaults to the `userinfo_endpoint` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,

    /// The URL to use for the provider's token endpoint
    ///
    /// Defaults to the `token_endpoint` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,

    /// The URL to use for getting the provider's public keys
    ///
    /// Defaults to the `jwks_uri` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,

    /// The response mode we ask the provider to use for the callback
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<ResponseMode>,

    /// How claims should be imported from the `id_token` provided by the
    /// provider
    #[serde(default, skip_serializing_if = "ClaimsImports::is_default")]
    pub claims_imports: ClaimsImports,

    /// Additional parameters to include in the authorization request
    ///
    /// Orders of the keys are not preserved.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_authorization_parameters: BTreeMap<String, String>,

    /// Whether the `login_hint` should be forwarded to the provider in the
    /// authorization request.
    ///
    /// Defaults to `false`.
    #[serde(default)]
    pub forward_login_hint: bool,

    /// What to do when receiving an OIDC Backchannel logout request.
    ///
    /// Defaults to `do_nothing`.
    #[serde(default, skip_serializing_if = "OnBackchannelLogout::is_default")]
    pub on_backchannel_logout: OnBackchannelLogout,
}

impl Provider {
    /// Resolves and returns the client secret for this provider.
    ///
    /// When `client_secret_file` was specified, the file is read at call time.
    ///
    /// # Errors
    ///
    /// Returns an error if the referenced file cannot be read.
    pub async fn client_secret(&self) -> anyhow::Result<Option<String>> {
        match &self.client_secret {
            Some(secret) => Ok(Some(secret.value().await?)),
            None => Ok(None),
        }
    }
}
