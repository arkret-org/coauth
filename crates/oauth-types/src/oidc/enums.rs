// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! String-backed enums and default static arrays used by the OpenID Connect
//! provider metadata types.

use std::fmt;

use coauth_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::requests::{GrantType, ResponseMode};

macro_rules! string_enum {
    (
        $(#[$outer_meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $wire:literal,
            )*
        }
    ) => {
        $(#[$outer_meta])*
        #[derive(SerializeDisplay, DeserializeFromStr, Clone, PartialEq, Eq, Hash, Debug)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// An unknown value.
            Unknown(String),
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let repr = match self {
                    $( Self::$variant => $wire, )*
                    Self::Unknown(raw) => raw.as_str(),
                };
                f.write_str(repr)
            }
        }

        impl core::str::FromStr for $name {
            type Err = core::convert::Infallible;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let parsed = match input {
                    $( $wire => Self::$variant, )*
                    other => Self::Unknown(other.to_owned()),
                };
                Ok(parsed)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// AuthenticationMethodOrAccessTokenType
// ---------------------------------------------------------------------------

/// An enum for types that accept either an [`OAuthClientAuthenticationMethod`]
/// or an [`OAuthAccessTokenType`].
#[derive(SerializeDisplay, DeserializeFromStr, Clone, PartialEq, Eq, Hash, Debug)]
pub enum AuthenticationMethodOrAccessTokenType {
    /// An authentication method.
    AuthenticationMethod(OAuthClientAuthenticationMethod),

    /// An access token type.
    AccessTokenType(OAuthAccessTokenType),

    /// An unknown value.
    ///
    /// Note that this variant should only be used as the result parsing a
    /// string of unknown type. To build a custom variant, first parse a
    /// string with the wanted type then use `.into()`.
    Unknown(String),
}

impl core::fmt::Display for AuthenticationMethodOrAccessTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationMethod(method) => write!(f, "{method}"),
            Self::AccessTokenType(tok) => write!(f, "{tok}"),
            Self::Unknown(raw) => f.write_str(raw),
        }
    }
}

impl core::str::FromStr for AuthenticationMethodOrAccessTokenType {
    type Err = core::convert::Infallible;

    /// Parse the string, trying access token types first, then authentication
    /// methods, falling back to Unknown.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt access token type resolution first.
        let tok = OAuthAccessTokenType::from_str(s)?;
        if !matches!(tok, OAuthAccessTokenType::Unknown(_)) {
            return Ok(Self::AccessTokenType(tok));
        }

        // Then try authentication method.
        let method = OAuthClientAuthenticationMethod::from_str(s)?;
        if !matches!(method, OAuthClientAuthenticationMethod::Unknown(_)) {
            return Ok(Self::AuthenticationMethod(method));
        }

        Ok(Self::Unknown(s.to_owned()))
    }
}

impl AuthenticationMethodOrAccessTokenType {
    /// Get the authentication method of this
    /// `AuthenticationMethodOrAccessTokenType`.
    #[must_use]
    pub fn authentication_method(&self) -> Option<&OAuthClientAuthenticationMethod> {
        match self {
            Self::AuthenticationMethod(m) => Some(m),
            _ => None,
        }
    }
}

impl From<OAuthClientAuthenticationMethod> for AuthenticationMethodOrAccessTokenType {
    fn from(method: OAuthClientAuthenticationMethod) -> Self {
        Self::AuthenticationMethod(method)
    }
}

impl From<OAuthAccessTokenType> for AuthenticationMethodOrAccessTokenType {
    fn from(tok: OAuthAccessTokenType) -> Self {
        Self::AccessTokenType(tok)
    }
}

// ---------------------------------------------------------------------------
// Simple string enums generated via the macro
// ---------------------------------------------------------------------------

string_enum! {
    /// The kind of an application.
    pub enum ApplicationType {
        /// A web application.
        Web => "web",
        /// A native application.
        Native => "native",
    }
}

string_enum! {
    /// Subject Identifier types.
    ///
    /// A Subject Identifier is a locally unique and never reassigned identifier
    /// within the Issuer for the End-User, which is intended to be consumed by the
    /// Client.
    pub enum SubjectType {
        /// This provides the same `sub` (subject) value to all Clients.
        Public => "public",
        /// This provides a different `sub` value to each Client, so as not to
        /// enable Clients to correlate the End-User's activities without
        /// permission.
        Pairwise => "pairwise",
    }
}

string_enum! {
    /// Claim types.
    pub enum ClaimType {
        /// Claims that are directly asserted by the OpenID Provider.
        Normal => "normal",
        /// Claims that are asserted by a Claims Provider other than the OpenID
        /// Provider but are returned by OpenID Provider.
        Aggregated => "aggregated",
        /// Claims that are asserted by a Claims Provider other than the OpenID
        /// Provider but are returned as references by the OpenID Provider.
        Distributed => "distributed",
    }
}

// AccountManagementAction has extra derives, so we use the macro but add them
// via the outer_meta.
string_enum! {
    /// An account management action that a user can take.
    #[non_exhaustive]
    #[derive(PartialOrd, Ord)]
    pub enum AccountManagementAction {
        /// `profile`
        ///
        /// The user wishes to view their profile (name, avatar, contact details).
        Profile => "profile",

        /// `sessions_list`
        ///
        /// The user wishes to view a list of their sessions.
        SessionsList => "sessions_list",

        /// `session_view`
        ///
        /// The user wishes to view the details of a specific session.
        SessionView => "session_view",

        /// `session_end`
        ///
        /// The user wishes to end/log out of a specific session.
        SessionEnd => "session_end",

        /// `account_deactivate`
        ///
        /// The user wishes to deactivate their account.
        AccountDeactivate => "account_deactivate",
    }
}

// ---------------------------------------------------------------------------
// Default static arrays (per OIDC Discovery 1.0 Section 3)
// ---------------------------------------------------------------------------

/// The default value of `response_modes_supported` if it is not set.
pub static DEFAULT_RESPONSE_MODES_SUPPORTED: &[ResponseMode] =
    &[ResponseMode::Query, ResponseMode::Fragment];

/// The default value of `grant_types_supported` if it is not set.
pub static DEFAULT_GRANT_TYPES_SUPPORTED: &[GrantType] =
    &[GrantType::AuthorizationCode, GrantType::Implicit];

/// The default value of `token_endpoint_auth_methods_supported` if it is not
/// set.
pub static DEFAULT_AUTH_METHODS_SUPPORTED: &[OAuthClientAuthenticationMethod] =
    &[OAuthClientAuthenticationMethod::ClientSecretBasic];

/// The default value of `claim_types_supported` if it is not set.
pub static DEFAULT_CLAIM_TYPES_SUPPORTED: &[ClaimType] = &[ClaimType::Normal];
