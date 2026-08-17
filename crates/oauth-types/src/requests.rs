// Copyright 2025 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! OAuth and OpenID Connect request/response message types.
//!
//! Implements the wire format for endpoints defined across:
//! - [RFC 6749 - The OAuth Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
//! - [RFC 7009 - Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
//! - [RFC 7662 - Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
//! - [RFC 8628 - Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
//! - [RFC 9126 - Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
//! - [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

use chrono::{DateTime, Duration, Utc};
use coauth_iana::oauth::{OAuthAccessTokenType, OAuthTokenTypeHint};
use language_tags::LanguageTag;
use serde::{Deserialize, Serialize};
use serde_with::formats::SpaceSeparator;
use serde_with::{
    DeserializeFromStr, DisplayFromStr, DurationSeconds, SerializeDisplay, StringWithSeparator,
    TimestampSeconds, serde_as, skip_serializing_none,
};
use url::Url;

use crate::response_type::ResponseType;
use crate::scope::Scope;

// ref: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml

// ---------------------------------------------------------------------------
// Macro: declaratively define an enum whose variants map to fixed strings,
// plus a fallback `Unknown(String)` arm. Generates `Display` and `FromStr`.
// ---------------------------------------------------------------------------

/// Internal helper macro that generates `Display`, `FromStr`,
/// `SerializeDisplay` and `DeserializeFromStr` for "string enums" used
/// throughout the OAuth / OIDC wire protocol.
macro_rules! string_enum {
    (
        $(#[$outer:meta])*
        $vis:vis enum $Enum:ident {
            $(
                $(#[$vmeta:meta])*
                $Variant:ident => $wire:literal,
            )*
            @unknown
            $(#[$umeta:meta])*
            Unknown(String),
        }
    ) => {
        $(#[$outer])*
        #[derive(
            Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone,
            SerializeDisplay, DeserializeFromStr,
        )]
        #[non_exhaustive]
        $vis enum $Enum {
            $(
                $(#[$vmeta])*
                $Variant,
            )*
            $(#[$umeta])*
            Unknown(String),
        }

        impl core::fmt::Display for $Enum {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let text = match self {
                    $( Self::$Variant => $wire, )*
                    Self::Unknown(s) => s.as_str(),
                };
                f.write_str(text)
            }
        }

        impl core::str::FromStr for $Enum {
            type Err = core::convert::Infallible;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let variant = match input {
                    $( $wire => Self::$Variant, )*
                    other => Self::Unknown(other.to_owned()),
                };
                Ok(variant)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// ResponseMode
// ---------------------------------------------------------------------------

string_enum! {
    /// The mechanism to be used for returning Authorization Response parameters
    /// from the Authorization Endpoint.
    ///
    /// Defined in [OAuth Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes).
    pub enum ResponseMode {
        /// Authorization Response parameters are encoded in the query string added
        /// to the `redirect_uri`.
        Query => "query",

        /// Authorization Response parameters are encoded in the fragment added to
        /// the `redirect_uri`.
        Fragment => "fragment",

        /// Authorization Response parameters are encoded as HTML form values that
        /// are auto-submitted in the User Agent, and thus are transmitted via the
        /// HTTP `POST` method to the Client, with the result parameters being
        /// encoded in the body using the `application/x-www-form-urlencoded`
        /// format.
        ///
        /// Defined in [OAuth Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).
        FormPost => "form_post",

        @unknown
        /// An unknown value.
        Unknown(String),
    }
}

// ---------------------------------------------------------------------------
// Display (OIDC display mode)
// ---------------------------------------------------------------------------

string_enum! {
    /// Value that specifies how the Authorization Server displays the
    /// authentication and consent user interface pages to the End-User.
    ///
    /// Defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
    pub enum Display {
        /// The Authorization Server should display the authentication and consent
        /// UI consistent with a full User Agent page view.
        ///
        /// This is the default display mode.
        Page => "page",

        /// The Authorization Server should display the authentication and consent
        /// UI consistent with a popup User Agent window.
        Popup => "popup",

        /// The Authorization Server should display the authentication and consent
        /// UI consistent with a device that leverages a touch interface.
        Touch => "touch",

        /// The Authorization Server should display the authentication and consent
        /// UI consistent with a "feature phone" type display.
        Wap => "wap",

        @unknown
        /// An unknown value.
        Unknown(String),
    }
}

// The variant is declared inside the `string_enum!` macro, so we can't
// easily attach `#[default]` to it; keep the manual impl.
#[allow(clippy::derivable_impls)]
impl Default for Display {
    fn default() -> Self {
        Self::Page
    }
}

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

string_enum! {
    /// Value that specifies whether the Authorization Server prompts the End-User
    /// for reauthentication and consent.
    ///
    /// Defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
    pub enum Prompt {
        /// The Authorization Server must not display any authentication or consent
        /// user interface pages.
        None => "none",

        /// The Authorization Server should prompt the End-User for
        /// reauthentication.
        Login => "login",

        /// The Authorization Server should prompt the End-User for consent before
        /// returning information to the Client.
        Consent => "consent",

        /// The Authorization Server should prompt the End-User to select a user
        /// account.
        ///
        /// This enables an End-User who has multiple accounts at the Authorization
        /// Server to select amongst the multiple accounts that they might have
        /// current sessions for.
        SelectAccount => "select_account",

        /// The Authorization Server should prompt the End-User to create a user
        /// account.
        ///
        /// Defined in [Initiating User Registration via OpenID Connect](https://openid.net/specs/openid-connect-prompt-create-1_0.html).
        Create => "create",

        @unknown
        /// An unknown value.
        Unknown(String),
    }
}

// ---------------------------------------------------------------------------
// GrantType
// ---------------------------------------------------------------------------

string_enum! {
    /// All possible values for the `grant_type` parameter.
    pub enum GrantType {
        /// [`authorization_code`](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)
        AuthorizationCode => "authorization_code",

        /// [`refresh_token`](https://www.rfc-editor.org/rfc/rfc6749#section-6)
        RefreshToken => "refresh_token",

        /// [`implicit`](https://www.rfc-editor.org/rfc/rfc6749#section-4.2)
        Implicit => "implicit",

        /// [`client_credentials`](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
        ClientCredentials => "client_credentials",

        /// [`password`](https://www.rfc-editor.org/rfc/rfc6749#section-4.3)
        Password => "password",

        /// [`urn:ietf:params:oauth:grant-type:device_code`](https://www.rfc-editor.org/rfc/rfc8628)
        DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",

        /// [`https://datatracker.ietf.org/doc/html/rfc7523#section-2.1`](https://www.rfc-editor.org/rfc/rfc7523#section-2.1)
        JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",

        /// [`urn:openid:params:grant-type:ciba`](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
        ClientInitiatedBackchannelAuthentication => "urn:openid:params:grant-type:ciba",

        @unknown
        /// An unknown value.
        Unknown(String),
    }
}

// ---------------------------------------------------------------------------
// AuthorizationRequest
// ---------------------------------------------------------------------------

/// The body of a request to the [Authorization Endpoint].
///
/// [Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[skip_serializing_none]
#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct AuthorizationRequest {
    /// OAuth Response Type value that determines the authorization
    /// processing strand to be used.
    pub response_type: ResponseType,

    /// OAuth Client Identifier valid at the Authorization Server.
    pub client_id: String,

    /// Redirection URI to which the response will be sent.
    ///
    /// This field is required when using a response type returning an
    /// authorization code.
    ///
    /// This URI must have been pre-registered with the OpenID Provider.
    pub redirect_uri: Option<Url>,

    /// The scope of the access request.
    ///
    /// OpenID Connect requests must contain the `openid` scope value.
    pub scope: Scope,

    /// Opaque value used to maintain state between the request and the
    /// callback.
    pub state: Option<String>,

    /// The mechanism to be used for returning parameters from the Authorization
    /// Endpoint.
    ///
    /// This use of this parameter is not recommended when the Response Mode
    /// that would be requested is the default mode specified for the Response
    /// Type.
    pub response_mode: Option<ResponseMode>,

    /// String value used to associate a Client session with an ID Token, and to
    /// mitigate replay attacks.
    pub nonce: Option<String>,

    /// How the Authorization Server should display the authentication and
    /// consent user interface pages to the End-User.
    pub display: Option<Display>,

    /// Whether the Authorization Server should prompt the End-User for
    /// reauthentication and consent.
    ///
    /// If [`Prompt::None`] is used, it must be the only value.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, Prompt>>")]
    #[serde(default)]
    pub prompt: Option<Vec<Prompt>>,

    /// The allowable elapsed time in seconds since the last time the End-User
    /// was actively authenticated by the OpenID Provider.
    #[serde(default)]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub max_age: Option<u32>,

    /// End-User's preferred languages and scripts for the user interface.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    pub ui_locales: Option<Vec<LanguageTag>>,

    /// ID Token previously issued by the Authorization Server being passed as a
    /// hint about the End-User's current or past authenticated session with the
    /// Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in.
    pub login_hint: Option<String>,

    /// Requested Authentication Context Class Reference values.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    #[serde(default)]
    pub acr_values: Option<HashSet<String>>,

    /// A JWT that contains the request's parameter values, called a [Request
    /// Object].
    ///
    /// [Request Object]: https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
    pub request: Option<String>,

    /// A URI referencing a [Request Object] or a [Pushed Authorization
    /// Request].
    ///
    /// [Request Object]: https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter
    /// [Pushed Authorization Request]: https://datatracker.ietf.org/doc/html/rfc9126
    pub request_uri: Option<Url>,

    /// A JSON object containing the Client Metadata when interacting with a
    /// [Self-Issued OpenID Provider].
    ///
    /// [Self-Issued OpenID Provider]: https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
    pub registration: Option<String>,
}

impl AuthorizationRequest {
    /// Creates a basic `AuthorizationRequest`.
    #[must_use]
    pub fn new(response_type: ResponseType, client_id: String, scope: Scope) -> Self {
        Self {
            response_type,
            client_id,
            scope,
            redirect_uri: None,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            request: None,
            request_uri: None,
            registration: None,
        }
    }
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sensitive fields (client_id, state, nonce, id_token_hint) are omitted
        // from the Debug representation to prevent accidental logging.
        f.debug_struct("AuthorizationRequest")
            .field("response_type", &self.response_type)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("response_mode", &self.response_mode)
            .field("display", &self.display)
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field("ui_locales", &self.ui_locales)
            .field("login_hint", &self.login_hint)
            .field("acr_values", &self.acr_values)
            .field("request", &self.request)
            .field("request_uri", &self.request_uri)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// AuthorizationResponse
// ---------------------------------------------------------------------------

/// A successful response from the [Authorization Endpoint].
///
/// [Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[skip_serializing_none]
#[serde_as]
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AuthorizationResponse {
    /// The authorization code generated by the authorization server.
    pub code: Option<String>,

    /// The access token to access the requested scope.
    pub access_token: Option<String>,

    /// The type of the access token.
    pub token_type: Option<OAuthAccessTokenType>,

    /// ID Token value associated with the authenticated session.
    pub id_token: Option<String>,

    /// The duration for which the access token is valid.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,
}

impl fmt::Debug for AuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Tokens and codes are sensitive -- expose only the metadata fields.
        f.debug_struct("AuthorizationResponse")
            .field("token_type", &self.token_type)
            .field("id_token", &self.id_token)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Device Authorization (RFC 8628)
// ---------------------------------------------------------------------------

/// A request to the [Device Authorization Endpoint].
///
/// [Device Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc8628
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationRequest {
    /// The scope of the access request.
    pub scope: Option<Scope>,
}

/// The default value of the `interval` between polling requests, if it is not
/// set.
pub const DEFAULT_DEVICE_AUTHORIZATION_INTERVAL: Duration =
    Duration::microseconds(5 * 1_000 * 1_000);

/// A successful response from the [Device Authorization Endpoint].
///
/// [Device Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc8628
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,

    /// The end-user verification code.
    pub user_code: String,

    /// The end-user verification URI on the authorization server.
    ///
    /// The URI should be short and easy to remember as end users will be asked
    /// to manually type it into their user agent.
    pub verification_uri: Url,

    /// A verification URI that includes the `user_code` (or other information
    /// with the same function as the `user_code`), which is designed for
    /// non-textual transmission.
    pub verification_uri_complete: Option<Url>,

    /// The lifetime of the `device_code` and `user_code`.
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: Duration,

    /// The minimum amount of time in seconds that the client should wait
    /// between polling requests to the token endpoint.
    ///
    /// Defaults to [`DEFAULT_DEVICE_AUTHORIZATION_INTERVAL`].
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub interval: Option<Duration>,
}

impl DeviceAuthorizationResponse {
    /// The minimum amount of time in seconds that the client should wait
    /// between polling requests to the token endpoint.
    ///
    /// Defaults to [`DEFAULT_DEVICE_AUTHORIZATION_INTERVAL`].
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
            .unwrap_or(DEFAULT_DEVICE_AUTHORIZATION_INTERVAL)
    }
}

impl fmt::Debug for DeviceAuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hide device_code and user_code -- only show timing/URI info.
        f.debug_struct("DeviceAuthorizationResponse")
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Token endpoint grant payloads
// ---------------------------------------------------------------------------

/// A request to the [Token Endpoint] for the [Authorization Code] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Authorization Code]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    /// The authorization code that was returned from the authorization
    /// endpoint.
    pub code: String,

    /// The `redirect_uri` that was included in the authorization request.
    ///
    /// This field must match exactly the value passed to the authorization
    /// endpoint.
    pub redirect_uri: Option<Url>,

    /// The code verifier that matches the code challenge that was sent to the
    /// authorization endpoint.
    // TODO: move this somehow in the pkce module
    pub code_verifier: Option<String>,
}

impl fmt::Debug for AuthorizationCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCodeGrant")
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// A request to the [Token Endpoint] for [refreshing an access token].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [refreshing an access token]: https://www.rfc-editor.org/rfc/rfc6749#section-6
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RefreshTokenGrant {
    /// The refresh token issued to the client.
    pub refresh_token: String,

    /// The scope of the access request.
    ///
    /// The requested scope must not include any scope not originally granted by
    /// the resource owner, and if omitted is treated as equal to the scope
    /// originally granted by the resource owner.
    pub scope: Option<Scope>,
}

impl fmt::Debug for RefreshTokenGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshTokenGrant")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// A request to the [Token Endpoint] for the [Client Credentials] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Client Credentials]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialsGrant {
    /// The scope of the access request.
    pub scope: Option<Scope>,
}

/// A request to the [Token Endpoint] for the [Device Authorization] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Device Authorization]: https://www.rfc-editor.org/rfc/rfc8628
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceCodeGrant {
    /// The device verification code, from the device authorization response.
    pub device_code: String,
}

impl fmt::Debug for DeviceCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCodeGrant").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// AccessTokenRequest (tagged union over grant_type)
// ---------------------------------------------------------------------------

/// An enum representing the possible requests to the [Token Endpoint].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AccessTokenRequest {
    /// A request in the Authorization Code strand.
    AuthorizationCode(AuthorizationCodeGrant),

    /// A request to refresh an access token.
    RefreshToken(RefreshTokenGrant),

    /// A request in the Client Credentials strand.
    ClientCredentials(ClientCredentialsGrant),

    /// A request in the Device Code strand.
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),

    /// An unsupported request.
    #[serde(skip_serializing, other)]
    Unsupported,
}

impl AccessTokenRequest {
    /// Returns the string representation of the grant type of the request.
    #[must_use]
    pub fn grant_type(&self) -> &'static str {
        match self {
            Self::AuthorizationCode(_) => "authorization_code",
            Self::RefreshToken(_) => "refresh_token",
            Self::ClientCredentials(_) => "client_credentials",
            Self::DeviceCode(_) => "urn:ietf:params:oauth:grant-type:device_code",
            Self::Unsupported => "unsupported",
        }
    }
}

// ---------------------------------------------------------------------------
// AccessTokenResponse (with builder)
// ---------------------------------------------------------------------------

/// A successful response from the [Token Endpoint].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AccessTokenResponse {
    /// The access token to access the requested scope.
    pub access_token: String,

    /// The token to refresh the access token when it expires.
    pub refresh_token: Option<String>,

    /// ID Token value associated with the authenticated session.
    // TODO: this should be somewhere else
    pub id_token: Option<String>,

    /// The type of the access token.
    pub token_type: OAuthAccessTokenType,

    /// The duration for which the access token is valid.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,

    /// The scope of the access token.
    pub scope: Option<Scope>,
}

impl AccessTokenResponse {
    /// Creates a new `AccessTokenResponse` with the given access token.
    #[must_use]
    pub fn new(access_token: String) -> AccessTokenResponse {
        AccessTokenResponse {
            access_token,
            refresh_token: None,
            id_token: None,
            token_type: OAuthAccessTokenType::Bearer,
            expires_in: None,
            scope: None,
        }
    }

    /// Adds a refresh token to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    /// Adds an ID token to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_id_token(mut self, id_token: String) -> Self {
        self.id_token = Some(id_token);
        self
    }

    /// Adds a scope to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Adds an expiration duration to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }
}

impl fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Introspection (RFC 7662)
// ---------------------------------------------------------------------------

/// A request to the [Introspection Endpoint].
///
/// [Introspection Endpoint]: https://www.rfc-editor.org/rfc/rfc7662#section-2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IntrospectionRequest {
    /// The value of the token.
    pub token: String,

    /// A hint about the type of the token submitted for introspection.
    pub token_type_hint: Option<OAuthTokenTypeHint>,
}

impl fmt::Debug for IntrospectionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionRequest")
            .field("token_type_hint", &self.token_type_hint)
            .finish_non_exhaustive()
    }
}

/// A successful response from the [Introspection Endpoint].
///
/// [Introspection Endpoint]: https://www.rfc-editor.org/rfc/rfc7662#section-2
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrospectionResponse {
    /// Whether or not the presented token is currently active.
    pub active: bool,

    /// The scope associated with the token.
    pub scope: Option<Scope>,

    /// Client identifier for the OAuth client that requested this token.
    pub client_id: Option<String>,

    /// Human-readable identifier for the resource owner who authorized this
    /// token.
    pub username: Option<String>,

    /// Type of the token.
    pub token_type: Option<OAuthTokenTypeHint>,

    /// Timestamp indicating when the token will expire.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub exp: Option<DateTime<Utc>>,

    /// Relative timestamp indicating when the token will expire,
    /// in seconds from the current instant.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,

    /// Timestamp indicating when the token was issued.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub iat: Option<DateTime<Utc>>,

    /// Timestamp indicating when the token is not to be used before.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub nbf: Option<DateTime<Utc>>,

    /// Subject of the token.
    pub sub: Option<String>,

    /// Intended audience of the token.
    pub aud: Option<String>,

    /// Issuer of the token.
    pub iss: Option<String>,

    /// String identifier for the token.
    pub jti: Option<String>,

    /// Arkret extension: principal DID associated with the token subject.
    #[serde(rename = "org.arkret.principal_did")]
    pub arkret_principal_did: Option<String>,

    /// Arkret extension: normalized device identifier associated with the
    /// session, when present.
    #[serde(rename = "org.arkret.device_id")]
    pub arkret_device_id: Option<String>,

    /// Arkret extension: session identifier associated with the token.
    #[serde(rename = "org.arkret.session_id")]
    pub arkret_session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Revocation (RFC 7009)
// ---------------------------------------------------------------------------

/// A request to the [Revocation Endpoint].
///
/// [Revocation Endpoint]: https://www.rfc-editor.org/rfc/rfc7009#section-2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// The value of the token.
    pub token: String,

    /// A hint about the type of the token submitted for introspection.
    pub token_type_hint: Option<OAuthTokenTypeHint>,
}

impl fmt::Debug for RevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token_type_hint", &self.token_type_hint)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Pushed Authorization Request (RFC 9126)
// ---------------------------------------------------------------------------

/// A successful response from the [Pushed Authorization Request Endpoint].
///
/// Note that there is no request type because it is by definition the same as
/// [`AuthorizationRequest`].
///
/// [Pushed Authorization Request Endpoint]: https://datatracker.ietf.org/doc/html/rfc9126
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PushedAuthorizationResponse {
    /// The `request_uri` to use for the request to the authorization endpoint.
    pub request_uri: String,

    /// The duration for which the request URI is valid.
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: Duration,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use coauth_iana::oauth::OAuthAuthorizationEndpointResponseType;
    use serde_json::json;

    use super::*;
    use crate::scope::OPENID;
    use crate::test_utils::assert_serde_json;

    // -- Fixtures -----------------------------------------------------------

    const FIXTURE_CODE: &str = "abcd";
    const FIXTURE_REDIRECT: &str = "https://example.com/redirect";

    // -- Grant round-trip tests ---------------------------------------------

    #[test]
    fn refresh_token_grant_roundtrip() {
        let scope: Option<Scope> = Some(vec![OPENID].into_iter().collect());

        let req = AccessTokenRequest::RefreshToken(RefreshTokenGrant {
            refresh_token: FIXTURE_CODE.into(),
            scope,
        });

        let expected = json!({
            "grant_type": "refresh_token",
            "refresh_token": FIXTURE_CODE,
            "scope": "openid",
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn authorization_code_grant_roundtrip() {
        let redirect: Url = FIXTURE_REDIRECT.parse().expect("valid URL");

        let req = AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: FIXTURE_CODE.into(),
            redirect_uri: Some(redirect),
            code_verifier: None,
        });

        let expected = json!({
            "grant_type": "authorization_code",
            "code": FIXTURE_CODE,
            "redirect_uri": FIXTURE_REDIRECT,
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn authorization_request_accepts_zero_max_age() {
        let request: AuthorizationRequest = serde_urlencoded::from_str(
            "response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fexample.com%2Fredirect&scope=openid&prompt=login&max_age=0",
        )
        .expect("max_age=0 is a valid OIDC authorization request parameter");

        assert_eq!(
            request.response_type,
            OAuthAuthorizationEndpointResponseType::Code.into()
        );
        assert_eq!(request.max_age, Some(0));
        assert_eq!(request.prompt, Some(vec![Prompt::Login]));
    }

    // -- GrantType serialization --------------------------------------------

    #[test]
    fn grant_type_serializes_correctly() {
        let cases: &[(GrantType, &str)] = &[
            (GrantType::AuthorizationCode, "\"authorization_code\""),
            (GrantType::RefreshToken, "\"refresh_token\""),
            (GrantType::Implicit, "\"implicit\""),
            (GrantType::ClientCredentials, "\"client_credentials\""),
            (GrantType::Password, "\"password\""),
            (
                GrantType::DeviceCode,
                "\"urn:ietf:params:oauth:grant-type:device_code\"",
            ),
            (
                GrantType::ClientInitiatedBackchannelAuthentication,
                "\"urn:openid:params:grant-type:ciba\"",
            ),
        ];

        for (variant, expected_json) in cases {
            let serialized = serde_json::to_string(variant).unwrap();
            assert_eq!(&serialized, expected_json, "serialize {variant:?}");
        }
    }

    #[test]
    fn grant_type_deserializes_correctly() {
        let cases: &[(&str, GrantType)] = &[
            ("\"authorization_code\"", GrantType::AuthorizationCode),
            ("\"refresh_token\"", GrantType::RefreshToken),
            ("\"implicit\"", GrantType::Implicit),
            ("\"client_credentials\"", GrantType::ClientCredentials),
            ("\"password\"", GrantType::Password),
            (
                "\"urn:ietf:params:oauth:grant-type:device_code\"",
                GrantType::DeviceCode,
            ),
            (
                "\"urn:openid:params:grant-type:ciba\"",
                GrantType::ClientInitiatedBackchannelAuthentication,
            ),
        ];

        for (json_str, expected_variant) in cases {
            let deserialized: GrantType = serde_json::from_str(json_str).unwrap();
            assert_eq!(&deserialized, expected_variant, "deserialize {json_str}");
        }
    }

    // -- ResponseMode serialization -----------------------------------------

    #[test]
    fn response_mode_serde() {
        let cases: &[(ResponseMode, &str)] = &[
            (ResponseMode::Query, "\"query\""),
            (ResponseMode::Fragment, "\"fragment\""),
            (ResponseMode::FormPost, "\"form_post\""),
        ];

        for (variant, json_str) in cases {
            assert_eq!(serde_json::to_string(variant).unwrap(), *json_str);
            assert_eq!(
                serde_json::from_str::<ResponseMode>(json_str).unwrap(),
                *variant,
            );
        }
    }

    // -- Display serialization ----------------------------------------------

    #[test]
    fn display_enum_serde() {
        let cases: &[(Display, &str)] = &[
            (Display::Page, "\"page\""),
            (Display::Popup, "\"popup\""),
            (Display::Touch, "\"touch\""),
            (Display::Wap, "\"wap\""),
        ];

        for (variant, json_str) in cases {
            assert_eq!(serde_json::to_string(variant).unwrap(), *json_str);
            assert_eq!(serde_json::from_str::<Display>(json_str).unwrap(), *variant,);
        }
    }

    // -- Prompt serialization -----------------------------------------------

    #[test]
    fn prompt_enum_serde() {
        let cases: &[(Prompt, &str)] = &[
            (Prompt::None, "\"none\""),
            (Prompt::Login, "\"login\""),
            (Prompt::Consent, "\"consent\""),
            (Prompt::SelectAccount, "\"select_account\""),
            (Prompt::Create, "\"create\""),
        ];

        for (variant, json_str) in cases {
            assert_eq!(serde_json::to_string(variant).unwrap(), *json_str);
            assert_eq!(serde_json::from_str::<Prompt>(json_str).unwrap(), *variant,);
        }
    }
}
